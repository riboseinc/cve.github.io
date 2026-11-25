#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "json_schemer"
require "yaml"

ROOT = File.expand_path("..", __dir__)
SCHEMA_PATH = File.join(ROOT, "schemas", "osv-schema.json")
CSAF_SCHEMA_PATH = File.join(ROOT, "schemas", "csaf-2.0-schema.json")
VEX_SCHEMA_PATH = File.join(ROOT, "schemas", "openvex-0.2.0-schema.json")
CVSS_REF_MAP = {
  "https://www.first.org/cvss/cvss-v2.0.json" => File.join(ROOT, "schemas", "cvss-v2.0.json"),
  "https://www.first.org/cvss/cvss-v3.0.json" => File.join(ROOT, "schemas", "cvss-v3.0.json"),
  "https://www.first.org/cvss/cvss-v3.1.json" => File.join(ROOT, "schemas", "cvss-v3.1.json")
}.freeze
PACKAGES_FILE = File.join(ROOT, "_data", "packages.yml")

def validate_against_schema(schemer, record, context_label, errors)
  issues = schemer.validate(record).to_a
  return if issues.empty?

  issues.each do |issue|
    errors << "#{context_label}: #{issue['error'] || issue['details'] || issue.inspect} (at #{issue['data_pointer']})"
  end
end

def main
  feeds_dir = ARGV[0] ? File.expand_path(ARGV[0]) : File.join(ROOT, "feeds")
  schema = JSON.parse(File.read(SCHEMA_PATH, encoding: "UTF-8"))
  schemer = JSONSchemer.schema(schema)

  csaf_ref_resolver = lambda do |uri|
    path = CVSS_REF_MAP[uri.to_s]
    path ? JSON.parse(File.read(path, encoding: "UTF-8")) : nil
  end
  csaf_schemer = JSONSchemer.schema(
    JSON.parse(File.read(CSAF_SCHEMA_PATH, encoding: "UTF-8")),
    ref_resolver: csaf_ref_resolver
  )
  vex_schemer = JSONSchemer.schema(
    JSON.parse(File.read(VEX_SCHEMA_PATH, encoding: "UTF-8"))
  )

  packages = YAML.safe_load_file(PACKAGES_FILE, permitted_classes: [Date, Time]).fetch("packages", [])

  errors = []
  validated_records = 0
  validated_csaf = 0
  validated_vex = 0

  osv_dir = File.join(feeds_dir, "osv")
  ghsa_dir = File.join(feeds_dir, "ghsa")
  csaf_dir = File.join(feeds_dir, "csaf")
  vex_dir = File.join(feeds_dir, "vex")

  osv_index_path = File.join(osv_dir, "index.json")
  unless File.exist?(osv_index_path)
    errors << "Missing OSV index file: #{osv_index_path}"
  else
    osv_index = JSON.parse(File.read(osv_index_path, encoding: "UTF-8"))
    errors << "OSV index missing 'packages' array" unless osv_index["packages"].is_a?(Array)
    errors << "OSV index missing 'by_purl' object" unless osv_index["by_purl"].is_a?(Hash)
    errors << "OSV index missing 'vulns' array" unless osv_index["vulns"].is_a?(Array)
  end

  ghsa_index_path = File.join(ghsa_dir, "index.json")
  unless File.exist?(ghsa_index_path)
    errors << "Missing GHSA index file: #{ghsa_index_path}"
  else
    ghsa_index = JSON.parse(File.read(ghsa_index_path, encoding: "UTF-8"))
    errors << "GHSA index missing 'packages' array" unless ghsa_index["packages"].is_a?(Array)
  end

  csaf_index_path = File.join(csaf_dir, "index.json")
  unless File.exist?(csaf_index_path)
    errors << "Missing CSAF index file: #{csaf_index_path}"
  else
    csaf_index = JSON.parse(File.read(csaf_index_path, encoding: "UTF-8"))
    errors << "CSAF index missing 'packages' array" unless csaf_index["packages"].is_a?(Array)
    errors << "CSAF index missing 'by_purl' object" unless csaf_index["by_purl"].is_a?(Hash)
    errors << "CSAF index missing 'documents' array" unless csaf_index["documents"].is_a?(Array)
  end

  vex_index_path = File.join(vex_dir, "index.json")
  unless File.exist?(vex_index_path)
    errors << "Missing OpenVEX index file: #{vex_index_path}"
  else
    vex_index = JSON.parse(File.read(vex_index_path, encoding: "UTF-8"))
    errors << "OpenVEX index missing 'packages' array" unless vex_index["packages"].is_a?(Array)
    errors << "OpenVEX index missing 'by_purl' object" unless vex_index["by_purl"].is_a?(Hash)
    errors << "OpenVEX index missing 'documents' array" unless vex_index["documents"].is_a?(Array)
  end

  package_names = packages.map { |p| p["name"].to_s }

  packages.each do |pkg|
    name = pkg["name"].to_s
    osv_pkg_path = File.join(osv_dir, "#{name}.json")
    if File.exist?(osv_pkg_path)
      data = JSON.parse(File.read(osv_pkg_path, encoding: "UTF-8"))
      unless data["package"].is_a?(Hash) && data["package"]["purl"] == pkg["purl"]
        errors << "#{osv_pkg_path}: missing or mismatched package.purl (expected #{pkg['purl']})"
      end
      if data["vulns"].is_a?(Array)
        data["vulns"].each_with_index do |vuln, idx|
          validate_against_schema(schemer, vuln, "#{osv_pkg_path}#vulns[#{idx}]", errors)
          validated_records += 1
        end
      else
        errors << "#{osv_pkg_path}: 'vulns' must be an Array"
      end
    else
      errors << "Missing per-package OSV feed: #{osv_pkg_path}"
    end

    ghsa_pkg_path = File.join(ghsa_dir, "#{name}.json")
    if File.exist?(ghsa_pkg_path)
      data = JSON.parse(File.read(ghsa_pkg_path, encoding: "UTF-8"))
      unless data["package"].is_a?(Hash) && data["package"]["purl"] == pkg["purl"]
        errors << "#{ghsa_pkg_path}: missing or mismatched package.purl (expected #{pkg['purl']})"
      end
      errors << "#{ghsa_pkg_path}: 'advisories' must be an Array" unless data["advisories"].is_a?(Array)
    else
      errors << "Missing per-package GHSA feed: #{ghsa_pkg_path}"
    end

    csaf_pkg_path = File.join(csaf_dir, "#{name}.json")
    if File.exist?(csaf_pkg_path)
      data = JSON.parse(File.read(csaf_pkg_path, encoding: "UTF-8"))
      validate_against_schema(csaf_schemer, data, csaf_pkg_path, errors)
      validated_csaf += 1
    else
      errors << "Missing per-package CSAF feed: #{csaf_pkg_path}"
    end

    vex_pkg_path = File.join(vex_dir, "#{name}.json")
    if File.exist?(vex_pkg_path)
      data = JSON.parse(File.read(vex_pkg_path, encoding: "UTF-8"))
      unless data["package"].is_a?(Hash) && data["package"]["purl"] == pkg["purl"]
        errors << "#{vex_pkg_path}: missing or mismatched package.purl (expected #{pkg['purl']})"
      end
      if data["documents"].is_a?(Array)
        data["documents"].each_with_index do |doc, idx|
          validate_against_schema(vex_schemer, doc, "#{vex_pkg_path}#documents[#{idx}]", errors)
          validated_vex += 1
        end
      else
        errors << "#{vex_pkg_path}: 'documents' must be an Array"
      end
    else
      errors << "Missing per-package OpenVEX feed: #{vex_pkg_path}"
    end
  end

  # Validate all standalone OSV record files in feeds/osv/*.json
  Dir.glob(File.join(osv_dir, "*.json")).sort.each do |path|
    base = File.basename(path, ".json")
    next if base == "index" || package_names.include?(base)

    record = JSON.parse(File.read(path, encoding: "UTF-8"))
    validate_against_schema(schemer, record, path, errors)
    validated_records += 1
  end

  # Validate all standalone CSAF document files in feeds/csaf/*.json
  Dir.glob(File.join(csaf_dir, "*.json")).sort.each do |path|
    base = File.basename(path, ".json")
    next if base == "index" || package_names.include?(base)

    doc = JSON.parse(File.read(path, encoding: "UTF-8"))
    validate_against_schema(csaf_schemer, doc, path, errors)
    validated_csaf += 1
  end

  # Validate all standalone OpenVEX document files in feeds/vex/*.json
  Dir.glob(File.join(vex_dir, "*.json")).sort.each do |path|
    base = File.basename(path, ".json")
    next if base == "index" || package_names.include?(base)

    doc = JSON.parse(File.read(path, encoding: "UTF-8"))
    validate_against_schema(vex_schemer, doc, path, errors)
    validated_vex += 1
  end

  if errors.any?
    warn "OSV/GHSA/CSAF/VEX feed validation failed with #{errors.length} error(s):"
    errors.each { |e| warn "  - #{e}" }
    exit 1
  end

  puts "Validated #{validated_records} OSV, #{validated_csaf} CSAF, and #{validated_vex} OpenVEX record(s) across #{packages.length} package feeds."
end

main if __FILE__ == $PROGRAM_NAME
