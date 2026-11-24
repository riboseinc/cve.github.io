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
  all_records = []

  Dir.glob(File.join(CVES_DIR, "*.json")).sort.each do |cve_path|
    record, matched_pkgs = build_osv_record(cve_path, packages, advisories_by_cve)
    all_records << record

    matched_pkgs.each do |pkg|
      osv_by_package[pkg["name"]] << record
    end
  end

  # Sort records deterministically by ID descending (newest CVEs first)
  all_records.sort_by! { |r| r["id"] }.reverse!

  osv_dir = File.join(OUT_DIR, "osv")
  ghsa_dir = File.join(OUT_DIR, "ghsa")
  FileUtils.rm_rf(OUT_DIR)
  FileUtils.mkdir_p(osv_dir)
  FileUtils.mkdir_p(ghsa_dir)

  # 1. Individual OSV records: /feeds/osv/<ID>.json
  all_records.each do |record|
    write_json(File.join(osv_dir, "#{record['id']}.json"), record)
  end

  # 2. Per-package OSV and GHSA feeds
  index_packages = []
  by_purl = {}
  ghsa_index_packages = []

  packages.each do |pkg|
    pkg_vulns = osv_by_package[pkg["name"]].sort_by { |r| r["id"] }.reverse
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
      "vulnerability_count" => pkg_vulns.length,
      "vulnerability_ids" => vuln_ids
    }

    by_purl[pkg["purl"]] = {
      "repo" => pkg["repo"],
      "name" => pkg["name"],
      "osv_feed_url" => osv_url,
      "ghsa_feed_url" => ghsa_url,
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

  puts "Generated OSV and GHSA feeds for #{packages.length} packages (#{all_records.length} OSV records) in #{OUT_DIR}"
end

main if __FILE__ == $PROGRAM_NAME
