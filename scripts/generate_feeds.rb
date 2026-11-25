#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "json"
require "net/http"
require "time"
require "uri"
require "yaml"

ROOT = File.expand_path("..", __dir__)
PACKAGES_FILE = File.join(ROOT, "_data", "packages.yml")
CVES_DIR = File.join(ROOT, "_data", "cves")
ADVISORIES_DIR = File.join(ROOT, "_advisories")
GHSA_DATA_DIR = File.join(ROOT, "_data", "ghsa")
OUT_DIR = File.join(ROOT, "feeds")
BASE_URL = "https://cve.ribose.com"
OSV_SCHEMA_VERSION = "1.6.7"

def normalize_timestamp(raw)
  return nil if raw.nil? || raw.to_s.strip.empty?

  str = raw.to_s.strip
  if /\A\d{4}-\d{2}-\d{2}\z/.match?(str)
    return "#{str}T00:00:00Z"
  end

  Time.parse(str).utc.strftime("%Y-%m-%dT%H:%M:%SZ")
rescue ArgumentError
  nil
end

def load_packages
  data = YAML.safe_load_file(PACKAGES_FILE, permitted_classes: [Date, Time])
  packages = data.fetch("packages", [])
  raise "No packages defined in #{PACKAGES_FILE}" if packages.empty?

  packages
end

def parse_advisories
  by_cve = Hash.new { |h, k| h[k] = [] }
  return by_cve unless Dir.exist?(ADVISORIES_DIR)

  Dir.glob(File.join(ADVISORIES_DIR, "*.adoc")).sort.each do |path|
    content = File.read(path, encoding: "UTF-8")
    frontmatter = {}
    body = content

    if content.start_with?("---\n") || content.start_with?("---\r\n")
      parts = content.split(/^---\s*$/, 3)
      if parts.length >= 3
        frontmatter = YAML.safe_load(parts[1], permitted_classes: [Date, Time]) || {}
        body = parts[2]
      end
    end

    slug = File.basename(path, ".adoc")
    adv_id = (frontmatter["id"] || slug.upcase).to_s.strip
    date_str = frontmatter["date"]&.to_s
    title = frontmatter["title"]&.to_s&.strip
    url = "#{BASE_URL}/advisories/#{slug}/"

    # Extract CVE IDs from body anchors and links (authoritative) and frontmatter
    cves = body.scan(/\bCVE-\d{4}-\d+\b/).uniq
    if cves.empty? && frontmatter["cve_id"]
      cves = [frontmatter["cve_id"].to_s.strip]
    end

    cves.each do |cve_id|
      by_cve[cve_id] << {
        id: adv_id,
        slug: slug,
        date: date_str,
        title: title,
        url: url
      }
    end
  end

  by_cve
end

def normalize_repo_url(url)
  url.to_s.strip.downcase.sub(%r{\.git\z}, "").sub(%r{/+\z}, "")
end

def match_package(affected_entry, packages)
  repo_url = normalize_repo_url(affected_entry["repo"])
  product = affected_entry["product"].to_s.strip.downcase

  packages.find do |pkg|
    repo_match = !repo_url.empty? && Array(pkg["repo_urls"]).any? { |u| normalize_repo_url(u) == repo_url }
    product_match = !product.empty? && Array(pkg["product_names"]).any? { |n| n.to_s.strip.downcase == product }
    repo_match || product_match
  end
end

def map_reference_type(ref)
  tags = Array(ref["tags"]).map(&:to_s)
  url = ref["url"].to_s

  return "ADVISORY" if tags.include?("vendor-advisory") || tags.include?("third-party-advisory")
  return "REPORT" if tags.include?("issue-tracking")
  return "ADVISORY" if tags.include?("release-notes")
  return "FIX" if url.include?("/commit/") && tags.include?("fix")
  return "WEB" if tags.include?("related")

  "WEB"
end

def extract_severity(cna)
  osv_severities = []
  base_severities = []

  Array(cna["metrics"]).each do |metric|
    if (v4 = metric["cvssV4_0"]) && v4["vectorString"]
      osv_severities << { "type" => "CVSS_V4", "score" => v4["vectorString"].to_s }
      base_severities << v4["baseSeverity"].to_s.upcase if v4["baseSeverity"]
    end
    if (v3 = metric["cvssV3_1"] || metric["cvssV3_0"]) && v3["vectorString"]
      osv_severities << { "type" => "CVSS_V3", "score" => v3["vectorString"].to_s }
      base_severities << v3["baseSeverity"].to_s.upcase if v3["baseSeverity"]
    end
  end

  rank = { "CRITICAL" => 4, "HIGH" => 3, "MEDIUM" => 2, "LOW" => 1 }
  top_severity = base_severities.max_by { |s| rank.fetch(s, 0) } || "UNKNOWN"

  [osv_severities, top_severity]
end

def extract_cwe_ids(cna)
  cwes = []
  Array(cna["problemTypes"]).each do |pt|
    Array(pt["descriptions"]).each do |desc|
      cwe = desc["cweId"]&.to_s&.strip
      cwes << cwe if cwe && !cwe.empty?
    end
  end
  cwes.uniq
end

def build_osv_record(cve_path, packages, advisories_by_cve)
  raw = JSON.parse(File.read(cve_path, encoding: "UTF-8"))
  cve_meta = raw["cveMetadata"] || {}
  cve_id = cve_meta["cveId"] || File.basename(cve_path, ".json")
  cna = raw.dig("containers", "cna") || {}
  linked_advisories = advisories_by_cve[cve_id] || []

  timestamps = []
  timestamps << normalize_timestamp(cna["datePublic"])
  timestamps << normalize_timestamp(cve_meta["datePublished"])
  linked_advisories.each { |a| timestamps << normalize_timestamp(a[:date]) }
  Array(cna["timeline"]).each { |t| timestamps << normalize_timestamp(t["time"]) }
  timestamps.compact!

  published = normalize_timestamp(cna["datePublic"]) ||
              normalize_timestamp(cve_meta["datePublished"]) ||
              timestamps.min ||
              "1970-01-01T00:00:00Z"

  modified = normalize_timestamp(cve_meta["dateUpdated"]) ||
             timestamps.max ||
             published

  description = cna.dig("descriptions", 0, "value").to_s.strip
  summary = cna["title"]&.to_s&.strip
  summary = description.lines.first.to_s.strip if summary.nil? || summary.empty?

  osv_severities, top_severity = extract_severity(cna)
  cwe_ids = extract_cwe_ids(cna)

  matched_packages = []
  osv_affected = []

  Array(cna["affected"]).each do |aff|
    pkg = match_package(aff, packages)
    next unless pkg

    matched_packages << pkg
    ranges = []
    versions = []

    Array(aff["versions"]).each do |ver|
      next unless ver["status"].to_s == "affected"

      v_str = ver["version"].to_s.strip
      next if v_str.empty?

      if ver["lessThan"]
        ranges << {
          "type" => "SEMVER",
          "events" => [
            { "introduced" => v_str },
            { "fixed" => ver["lessThan"].to_s.strip }
          ]
        }
      elsif ver["lessThanOrEqual"]
        ranges << {
          "type" => "SEMVER",
          "events" => [
            { "introduced" => v_str },
            { "last_affected" => ver["lessThanOrEqual"].to_s.strip }
          ]
        }
      else
        versions << v_str
        ranges << {
          "type" => "SEMVER",
          "events" => [
            { "introduced" => v_str },
            { "last_affected" => v_str }
          ]
        }
      end
    end

    entry = {
      "package" => {
        "ecosystem" => pkg["ecosystem"],
        "name" => pkg["package_name"],
        "purl" => pkg["purl"]
      }
    }
    entry["ranges"] = ranges unless ranges.empty?
    entry["versions"] = versions.uniq unless versions.empty?
    osv_affected << entry
  end

  references = []
  seen_urls = {}

  Array(cna["references"]).each do |ref|
    url = ref["url"].to_s.strip
    next if url.empty? || seen_urls[url]

    seen_urls[url] = true
    references << {
      "type" => map_reference_type(ref),
      "url" => url
    }
  end

  linked_advisories.each do |adv|
    next if seen_urls[adv[:url]]

    seen_urls[adv[:url]] = true
    references << {
      "type" => "ADVISORY",
      "url" => adv[:url]
    }
  end

  record = {
    "schema_version" => OSV_SCHEMA_VERSION,
    "id" => cve_id,
    "modified" => modified,
    "published" => published,
    "summary" => summary,
    "details" => description,
    "affected" => osv_affected,
    "references" => references
  }

  related_ids = linked_advisories.map { |a| a[:id] }.uniq
  record["related"] = related_ids unless related_ids.empty?
  record["severity"] = osv_severities unless osv_severities.empty?

  db_specific = {
    "severity" => top_severity,
    "cna_assigner" => "Ribose"
  }
  db_specific["cwe_ids"] = cwe_ids unless cwe_ids.empty?
  db_specific["advisory_ids"] = related_ids unless related_ids.empty?
  record["database_specific"] = db_specific

  [record, matched_packages.uniq { |p| p["name"] }]
end

def extract_cvss_v3_for_csaf(cna)
  Array(cna["metrics"]).each do |metric|
    v3 = metric["cvssV3_1"] || metric["cvssV3_0"]
    next unless v3 && v3["vectorString"] && v3["baseScore"] && v3["baseSeverity"] && v3["version"]

    return {
      "version" => v3["version"].to_s,
      "vectorString" => v3["vectorString"].to_s,
      "baseScore" => v3["baseScore"].to_f,
      "baseSeverity" => v3["baseSeverity"].to_s.upcase
    }
  end
  nil
end

def extract_first_cwe_for_csaf(cna)
  Array(cna["problemTypes"]).each do |pt|
    Array(pt["descriptions"]).each do |desc|
      cwe_id = desc["cweId"]&.to_s&.strip
      next unless cwe_id && /\ACWE-[1-9]\d{0,5}\z/.match?(cwe_id)

      cwe_name = desc["description"]&.to_s&.strip
      cwe_name = cwe_id if cwe_name.nil? || cwe_name.empty?
      return { "id" => cwe_id, "name" => cwe_name }
    end
  end
  nil
end

def build_csaf_product_tree(matched_pkgs)
  vendor_branches = matched_pkgs.group_by { |p| p["org"].to_s }.map do |org, pkgs|
    product_branches = pkgs.map do |pkg|
      {
        "category" => "product_name",
        "name" => pkg["package_name"],
        "product" => {
          "name" => pkg["package_name"],
          "product_id" => pkg["name"],
          "product_identification_helper" => {
            "purl" => pkg["purl"]
          }
        }
      }
    end
    {
      "category" => "vendor",
      "name" => org,
      "branches" => product_branches
    }
  end

  { "branches" => vendor_branches }
end

def build_csaf_vulnerability(cve_path, packages, advisories_by_cve)
  raw = JSON.parse(File.read(cve_path, encoding: "UTF-8"))
  cve_meta = raw["cveMetadata"] || {}
  cve_id = cve_meta["cveId"] || File.basename(cve_path, ".json")
  cna = raw.dig("containers", "cna") || {}
  linked_advisories = advisories_by_cve[cve_id] || []

  published = normalize_timestamp(cna["datePublic"]) ||
              normalize_timestamp(cve_meta["datePublished"]) ||
              "1970-01-01T00:00:00Z"
  modified = normalize_timestamp(cve_meta["dateUpdated"]) || published

  description = cna.dig("descriptions", 0, "value").to_s.strip
  summary = cna["title"]&.to_s&.strip
  summary = description.lines.first.to_s.strip if summary.nil? || summary.empty?

  matched_packages = []
  affected_product_ids = []
  fixed_versions = []

  Array(cna["affected"]).each do |aff|
    pkg = match_package(aff, packages)
    next unless pkg

    matched_packages << pkg
    affected_product_ids << pkg["name"]

    Array(aff["versions"]).each do |ver|
      next unless ver["status"].to_s == "affected"

      if ver["lessThan"] && !ver["lessThan"].to_s.strip.empty?
        fixed_versions << ver["lessThan"].to_s.strip
      end
    end
  end

  matched_packages.uniq! { |p| p["name"] }
  affected_product_ids.uniq!

  references = []
  seen_urls = {}
  Array(cna["references"]).each do |ref|
    url = ref["url"].to_s.strip
    next if url.empty? || seen_urls[url]

    seen_urls[url] = true
    ref_name = ref["name"].to_s.strip
    references << {
      "category" => map_reference_type(ref) == "ADVISORY" ? "external" : "self",
      "summary" => ref_name.empty? ? url : ref_name,
      "url" => url
    }
  end
  linked_advisories.each do |adv|
    next if seen_urls[adv[:url]]

    seen_urls[adv[:url]] = true
    references << {
      "category" => "self",
      "summary" => adv[:title] && !adv[:title].empty? ? adv[:title] : adv[:id],
      "url" => adv[:url]
    }
  end

  vuln = {
    "cve" => cve_id,
    "title" => summary,
    "release_date" => published,
    "notes" => [
      {
        "category" => "description",
        "text" => description.empty? ? summary : description
      }
    ]
  }

  cwe = extract_first_cwe_for_csaf(cna)
  vuln["cwe"] = cwe if cwe

  unless affected_product_ids.empty?
    vuln["product_status"] = {
      "known_affected" => affected_product_ids
    }
  end

  cvss_v3 = extract_cvss_v3_for_csaf(cna)
  if cvss_v3 && !affected_product_ids.empty?
    vuln["scores"] = [
      {
        "cvss_v3" => cvss_v3,
        "products" => affected_product_ids
      }
    ]
  end

  unless fixed_versions.empty? || affected_product_ids.empty?
    vuln["remediations"] = [
      {
        "category" => "vendor_fix",
        "details" => "Upgrade to #{fixed_versions.uniq.join(', ')} or later.",
        "product_ids" => affected_product_ids
      }
    ]
  end

  vuln["references"] = references unless references.empty?

  {
    cve_id: cve_id,
    published: published,
    modified: modified,
    summary: summary,
    description: description,
    matched_packages: matched_packages,
    vulnerability: vuln,
    fixed_versions: fixed_versions.uniq
  }
end

def build_csaf_document(id:, title:, initial_date:, current_date:, matched_packages:, vulnerabilities:)
  doc = {
    "document" => {
      "category" => "csaf_vex",
      "csaf_version" => "2.0",
      "publisher" => {
        "category" => "vendor",
        "name" => "Ribose",
        "namespace" => BASE_URL
      },
      "title" => title,
      "tracking" => {
        "current_release_date" => current_date,
        "id" => id,
        "initial_release_date" => initial_date,
        "revision_history" => [
          {
            "date" => current_date,
            "number" => "1.0.0",
            "summary" => "Initial publication"
          }
        ],
        "status" => "final",
        "version" => "1.0.0"
      }
    }
  }

  doc["product_tree"] = build_csaf_product_tree(matched_packages) unless matched_packages.empty?
  doc["vulnerabilities"] = vulnerabilities unless vulnerabilities.empty?
  doc
end

def build_vex_document(cve_info)
  cve_id = cve_info[:cve_id]
  products = cve_info[:matched_packages].map do |pkg|
    {
      "@id" => pkg["purl"],
      "identifiers" => {
        "purl" => pkg["purl"]
      }
    }
  end

  action_statement = if cve_info[:fixed_versions].empty?
                       "Upgrade to a patched release."
                     else
                       "Upgrade to #{cve_info[:fixed_versions].join(', ')} or later."
                     end

  statement = {
    "vulnerability" => {
      "@id" => "https://nvd.nist.gov/vuln/detail/#{cve_id}",
      "name" => cve_id,
      "description" => cve_info[:summary]
    },
    "timestamp" => cve_info[:modified],
    "products" => products,
    "status" => "affected",
    "action_statement" => action_statement
  }

  unless cve_info[:fixed_versions].empty?
    statement["status_notes"] = "Fixed in #{cve_info[:fixed_versions].join(', ')}."
  end

  {
    "@context" => "https://openvex.dev/ns/v0.2.0",
    "@id" => "#{BASE_URL}/feeds/vex/#{cve_id}.json",
    "author" => "Ribose",
    "role" => "CNA",
    "timestamp" => cve_info[:modified],
    "version" => 1,
    "statements" => [statement]
  }
end

def fetch_upstream_ghsa(repo)
  return [] unless ENV["FETCH_UPSTREAM"] == "1"

  uri = URI("https://api.github.com/repos/#{repo}/security-advisories")
  req = Net::HTTP::Get.new(uri)
  req["Accept"] = "application/vnd.github+json"
  req["User-Agent"] = "cve-ribose-feed-generator/1.0"
  req["Authorization"] = "Bearer #{ENV['GITHUB_TOKEN']}" if ENV["GITHUB_TOKEN"] && !ENV["GITHUB_TOKEN"].empty?

  res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true, open_timeout: 5, read_timeout: 10) do |http|
    http.request(req)
  end
  return [] unless res.is_a?(Net::HTTPSuccess)

  parsed = JSON.parse(res.body)
  parsed.is_a?(Array) ? parsed : []
rescue StandardError
  []
end

def load_ghsa_advisories(pkg)
  local_file = File.join(GHSA_DATA_DIR, "#{pkg['name']}.json")
  if File.exist?(local_file)
    parsed = JSON.parse(File.read(local_file, encoding: "UTF-8"))
    return parsed.is_a?(Array) ? parsed : Array(parsed["advisories"])
  end

  fetch_upstream_ghsa(pkg["repo"])
end

def write_json(path, data)
  FileUtils.mkdir_p(File.dirname(path))
  File.write(path, "#{JSON.pretty_generate(data)}\n", encoding: "UTF-8")
end

def main
  packages = load_packages
  advisories_by_cve = parse_advisories

  osv_by_package = Hash.new { |h, k| h[k] = [] }
  csaf_by_package = Hash.new { |h, k| h[k] = [] }
  all_records = []
  all_cve_infos = []

  Dir.glob(File.join(CVES_DIR, "*.json")).sort.each do |cve_path|
    record, matched_pkgs = build_osv_record(cve_path, packages, advisories_by_cve)
    all_records << record

    cve_info = build_csaf_vulnerability(cve_path, packages, advisories_by_cve)
    all_cve_infos << cve_info

    matched_pkgs.each do |pkg|
      osv_by_package[pkg["name"]] << record
      csaf_by_package[pkg["name"]] << cve_info
    end
  end

  # Sort records deterministically by ID descending (newest CVEs first)
  all_records.sort_by! { |r| r["id"] }.reverse!
  all_cve_infos.sort_by! { |c| c[:cve_id] }.reverse!

  osv_dir = File.join(OUT_DIR, "osv")
  ghsa_dir = File.join(OUT_DIR, "ghsa")
  csaf_dir = File.join(OUT_DIR, "csaf")
  vex_dir = File.join(OUT_DIR, "vex")
  FileUtils.rm_rf(OUT_DIR)
  FileUtils.mkdir_p(osv_dir)
  FileUtils.mkdir_p(ghsa_dir)
  FileUtils.mkdir_p(csaf_dir)
  FileUtils.mkdir_p(vex_dir)

  # 1. Individual OSV, CSAF, and OpenVEX records: /feeds/{osv,csaf,vex}/<ID>.json
  all_records.each do |record|
    write_json(File.join(osv_dir, "#{record['id']}.json"), record)
  end

  all_cve_infos.each do |cve_info|
    cve_id = cve_info[:cve_id]
    csaf_doc = build_csaf_document(
      id: "RIBOSE-CSAF-#{cve_id}",
      title: "#{cve_id}: #{cve_info[:summary]}",
      initial_date: cve_info[:published],
      current_date: cve_info[:modified],
      matched_packages: cve_info[:matched_packages],
      vulnerabilities: [cve_info[:vulnerability]]
    )
    write_json(File.join(csaf_dir, "#{cve_id}.json"), csaf_doc)

    vex_doc = build_vex_document(cve_info)
    write_json(File.join(vex_dir, "#{cve_id}.json"), vex_doc)
  end

  # 2. Per-package OSV, GHSA, CSAF, and OpenVEX feeds
  index_packages = []
  by_purl = {}
  ghsa_index_packages = []
  csaf_index_packages = []
  csaf_by_purl = {}
  vex_index_packages = []
  vex_by_purl = {}

  packages.each do |pkg|
    pkg_vulns = osv_by_package[pkg["name"]].sort_by { |r| r["id"] }.reverse
    pkg_cve_infos = csaf_by_package[pkg["name"]].sort_by { |c| c[:cve_id] }.reverse
    pkg_meta = {
      "repo" => pkg["repo"],
      "name" => pkg["name"],
      "tier" => pkg["tier"],
      "release_stream" => pkg["release_stream"],
      "ecosystem" => pkg["ecosystem"],
      "purl" => pkg["purl"]
    }

    osv_feed = {
      "schema_version" => OSV_SCHEMA_VERSION,
      "package" => pkg_meta,
      "vulns" => pkg_vulns
    }
    write_json(File.join(osv_dir, "#{pkg['name']}.json"), osv_feed)

    osv_url = "#{BASE_URL}#{pkg['osv_feed_path']}"
    ghsa_url = "#{BASE_URL}#{pkg['ghsa_feed_path']}"
    csaf_path = pkg["csaf_feed_path"] || "/feeds/csaf/#{pkg['name']}.json"
    vex_path = pkg["vex_feed_path"] || "/feeds/vex/#{pkg['name']}.json"
    csaf_url = "#{BASE_URL}#{csaf_path}"
    vex_url = "#{BASE_URL}#{vex_path}"
    vuln_ids = pkg_vulns.map { |v| v["id"] }

    index_packages << {
      "repo" => pkg["repo"],
      "name" => pkg["name"],
      "tier" => pkg["tier"],
      "release_stream" => pkg["release_stream"],
      "ecosystem" => pkg["ecosystem"],
      "purl" => pkg["purl"],
      "osv_feed_url" => osv_url,
      "ghsa_feed_url" => ghsa_url,
      "csaf_feed_url" => csaf_url,
      "vex_feed_url" => vex_url,
      "vulnerability_count" => pkg_vulns.length,
      "vulnerability_ids" => vuln_ids
    }

    by_purl[pkg["purl"]] = {
      "repo" => pkg["repo"],
      "name" => pkg["name"],
      "osv_feed_url" => osv_url,
      "ghsa_feed_url" => ghsa_url,
      "csaf_feed_url" => csaf_url,
      "vex_feed_url" => vex_url,
      "vulnerability_ids" => vuln_ids
    }

    ghsa_advisories = load_ghsa_advisories(pkg)
    ghsa_feed = {
      "package" => pkg_meta,
      "advisories" => ghsa_advisories
    }
    write_json(File.join(ghsa_dir, "#{pkg['name']}.json"), ghsa_feed)

    ghsa_index_packages << {
      "repo" => pkg["repo"],
      "name" => pkg["name"],
      "tier" => pkg["tier"],
      "purl" => pkg["purl"],
      "ghsa_feed_url" => ghsa_url,
      "advisory_count" => ghsa_advisories.length
    }

    # Per-package CSAF 2.0 document
    initial_date = pkg_cve_infos.map { |c| c[:published] }.min || "1970-01-01T00:00:00Z"
    current_date = pkg_cve_infos.map { |c| c[:modified] }.max || initial_date
    csaf_pkg_doc = build_csaf_document(
      id: "RIBOSE-CSAF-#{pkg['name'].upcase}",
      title: "Ribose CSAF VEX Feed for #{pkg['repo']}",
      initial_date: initial_date,
      current_date: current_date,
      matched_packages: [pkg],
      vulnerabilities: pkg_cve_infos.map { |c| c[:vulnerability] }
    )
    write_json(File.join(csaf_dir, "#{pkg['name']}.json"), csaf_pkg_doc)

    csaf_index_packages << {
      "repo" => pkg["repo"],
      "name" => pkg["name"],
      "tier" => pkg["tier"],
      "release_stream" => pkg["release_stream"],
      "purl" => pkg["purl"],
      "csaf_feed_url" => csaf_url,
      "vulnerability_count" => pkg_cve_infos.length,
      "vulnerability_ids" => vuln_ids
    }
    csaf_by_purl[pkg["purl"]] = {
      "repo" => pkg["repo"],
      "name" => pkg["name"],
      "csaf_feed_url" => csaf_url,
      "vulnerability_ids" => vuln_ids
    }

    # Per-package OpenVEX feed
    vex_docs = pkg_cve_infos.map { |c| build_vex_document(c) }
    vex_pkg_feed = {
      "schema_version" => "0.2.0",
      "package" => pkg_meta,
      "documents" => vex_docs
    }
    write_json(File.join(vex_dir, "#{pkg['name']}.json"), vex_pkg_feed)

    vex_index_packages << {
      "repo" => pkg["repo"],
      "name" => pkg["name"],
      "tier" => pkg["tier"],
      "release_stream" => pkg["release_stream"],
      "purl" => pkg["purl"],
      "vex_feed_url" => vex_url,
      "document_count" => vex_docs.length,
      "vulnerability_ids" => vuln_ids
    }
    vex_by_purl[pkg["purl"]] = {
      "repo" => pkg["repo"],
      "name" => pkg["name"],
      "vex_feed_url" => vex_url,
      "vulnerability_ids" => vuln_ids
    }
  end

  # 3. OSV index: /feeds/osv/index.json
  osv_index = {
    "schema_version" => OSV_SCHEMA_VERSION,
    "base_url" => BASE_URL,
    "packages" => index_packages,
    "by_purl" => by_purl,
    "vulns" => all_records.map do |r|
      {
        "id" => r["id"],
        "modified" => r["modified"],
        "published" => r["published"],
        "summary" => r["summary"],
        "severity" => r.dig("database_specific", "severity") || "UNKNOWN",
        "purls" => r["affected"].map { |a| a.dig("package", "purl") }.compact.uniq,
        "url" => "#{BASE_URL}/feeds/osv/#{r['id']}.json"
      }
    end
  }
  write_json(File.join(osv_dir, "index.json"), osv_index)

  # 4. GHSA index: /feeds/ghsa/index.json
  ghsa_index = {
    "base_url" => BASE_URL,
    "packages" => ghsa_index_packages
  }
  write_json(File.join(ghsa_dir, "index.json"), ghsa_index)

  # 5. CSAF index: /feeds/csaf/index.json
  csaf_index = {
    "csaf_version" => "2.0",
    "base_url" => BASE_URL,
    "packages" => csaf_index_packages,
    "by_purl" => csaf_by_purl,
    "documents" => all_cve_infos.map do |c|
      {
        "id" => c[:cve_id],
        "published" => c[:published],
        "modified" => c[:modified],
        "summary" => c[:summary],
        "purls" => c[:matched_packages].map { |p| p["purl"] }.uniq,
        "url" => "#{BASE_URL}/feeds/csaf/#{c[:cve_id]}.json"
      }
    end
  }
  write_json(File.join(csaf_dir, "index.json"), csaf_index)

  # 6. OpenVEX index: /feeds/vex/index.json
  vex_index = {
    "openvex_version" => "0.2.0",
    "base_url" => BASE_URL,
    "packages" => vex_index_packages,
    "by_purl" => vex_by_purl,
    "documents" => all_cve_infos.map do |c|
      {
        "id" => c[:cve_id],
        "published" => c[:published],
        "modified" => c[:modified],
        "summary" => c[:summary],
        "purls" => c[:matched_packages].map { |p| p["purl"] }.uniq,
        "url" => "#{BASE_URL}/feeds/vex/#{c[:cve_id]}.json"
      }
    end
  }
  write_json(File.join(vex_dir, "index.json"), vex_index)

  puts "Generated OSV, GHSA, CSAF, and OpenVEX feeds for #{packages.length} packages (#{all_records.length} CVE records) in #{OUT_DIR}"
end

main if __FILE__ == $PROGRAM_NAME
