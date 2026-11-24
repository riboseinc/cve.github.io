#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "json"
require "minitest/autorun"
require "open3"
require "tmpdir"

ROOT = File.expand_path("..", __dir__)
FEEDS_DIR = File.join(ROOT, "feeds")
GENERATE_SCRIPT = File.join(ROOT, "scripts", "generate_feeds.rb")
VALIDATE_SCRIPT = File.join(ROOT, "scripts", "validate_feeds.rb")

class TestFeeds < Minitest::Test
  def setup
    _, status = Open3.capture2e(RbConfig.ruby, GENERATE_SCRIPT)
    assert status.success?, "generate_feeds.rb must succeed"
  end

  def test_tier_a_endpoints_exist
    %w[rnp metanorma cla identity].each do |pkg|
      osv_path = File.join(FEEDS_DIR, "osv", "#{pkg}.json")
      ghsa_path = File.join(FEEDS_DIR, "ghsa", "#{pkg}.json")
      assert File.exist?(osv_path), "Expected #{osv_path} to exist"
      assert File.exist?(ghsa_path), "Expected #{ghsa_path} to exist"

      osv = JSON.parse(File.read(osv_path, encoding: "UTF-8"))
      assert_kind_of Array, osv["vulns"]
      assert_equal pkg, osv.dig("package", "name")

      ghsa = JSON.parse(File.read(ghsa_path, encoding: "UTF-8"))
      assert_kind_of Array, ghsa["advisories"]
      assert_equal pkg, ghsa.dig("package", "name")
    end
  end

  def test_osv_index_keyed_by_package_and_purl
    index = JSON.parse(File.read(File.join(FEEDS_DIR, "osv", "index.json"), encoding: "UTF-8"))
    assert_equal "https://cve.ribose.com", index["base_url"]

    expected_purls = {
      "rnp" => "pkg:github/rnpgp/rnp",
      "metanorma" => "pkg:gem/metanorma",
      "cla" => "pkg:github/riboseinc/cla",
      "identity" => "pkg:github/ribosei/identity"
    }

    expected_purls.each do |pkg, purl|
      assert index["by_purl"].key?(purl), "Expected index by_purl to include #{purl}"
      assert_equal "https://cve.ribose.com/feeds/osv/#{pkg}.json", index.dig("by_purl", purl, "osv_feed_url")
      assert_equal "https://cve.ribose.com/feeds/ghsa/#{pkg}.json", index.dig("by_purl", purl, "ghsa_feed_url")
    end
  end

  def test_rnp_osv_records_contain_expected_cves
    rnp = JSON.parse(File.read(File.join(FEEDS_DIR, "osv", "rnp.json"), encoding: "UTF-8"))
    ids = rnp["vulns"].map { |v| v["id"] }
    %w[CVE-2025-13470 CVE-2023-29480 CVE-2023-29479 CVE-2021-33589].each do |cve|
      assert_includes ids, cve
      assert File.exist?(File.join(FEEDS_DIR, "osv", "#{cve}.json"))
    end

    cve_2025 = rnp["vulns"].find { |v| v["id"] == "CVE-2025-13470" }
    assert_equal "HIGH", cve_2025.dig("database_specific", "severity")
    assert_equal "pkg:github/rnpgp/rnp", cve_2025.dig("affected", 0, "package", "purl")
    assert_includes cve_2025.dig("affected", 0, "versions"), "0.18.0"
    assert_includes cve_2025["related"], "RA-2025-11-20"
  end

  def test_validator_passes_on_generated_feeds
    out, status = Open3.capture2e(RbConfig.ruby, VALIDATE_SCRIPT, FEEDS_DIR)
    assert status.success?, "validate_feeds.rb should pass: #{out}"
  end

  def test_validator_rejects_malformed_osv_record
    Dir.mktmpdir do |tmpdir|
      FileUtils.cp_r(File.join(FEEDS_DIR, "osv"), tmpdir)
      FileUtils.cp_r(File.join(FEEDS_DIR, "ghsa"), tmpdir)

      bad_record_path = File.join(tmpdir, "osv", "CVE-2025-99999.json")
      File.write(bad_record_path, JSON.pretty_generate({ "id" => "INVALID-PREFIX-123" }))

      out, status = Open3.capture2e(RbConfig.ruby, VALIDATE_SCRIPT, tmpdir)
      refute status.success?, "validate_feeds.rb must fail on malformed OSV record"
      assert_includes out, "validation failed"
    end
  end
end
