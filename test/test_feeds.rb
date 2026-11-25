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
      csaf_path = File.join(FEEDS_DIR, "csaf", "#{pkg}.json")
      vex_path = File.join(FEEDS_DIR, "vex", "#{pkg}.json")
      assert File.exist?(osv_path), "Expected #{osv_path} to exist"
      assert File.exist?(ghsa_path), "Expected #{ghsa_path} to exist"
      assert File.exist?(csaf_path), "Expected #{csaf_path} to exist"
      assert File.exist?(vex_path), "Expected #{vex_path} to exist"

      osv = JSON.parse(File.read(osv_path, encoding: "UTF-8"))
      assert_kind_of Array, osv["vulns"]
      assert_equal pkg, osv.dig("package", "name")

      ghsa = JSON.parse(File.read(ghsa_path, encoding: "UTF-8"))
      assert_kind_of Array, ghsa["advisories"]
      assert_equal pkg, ghsa.dig("package", "name")

      csaf = JSON.parse(File.read(csaf_path, encoding: "UTF-8"))
      assert_equal "csaf_vex", csaf.dig("document", "category")
      assert_equal "2.0", csaf.dig("document", "csaf_version")

      vex = JSON.parse(File.read(vex_path, encoding: "UTF-8"))
      assert_kind_of Array, vex["documents"]
      assert_equal pkg, vex.dig("package", "name")
    end
  end

  def test_osv_index_keyed_by_package_and_purl
    index = JSON.parse(File.read(File.join(FEEDS_DIR, "osv", "index.json"), encoding: "UTF-8"))
    csaf_index = JSON.parse(File.read(File.join(FEEDS_DIR, "csaf", "index.json"), encoding: "UTF-8"))
    vex_index = JSON.parse(File.read(File.join(FEEDS_DIR, "vex", "index.json"), encoding: "UTF-8"))
    assert_equal "https://cve.ribose.com", index["base_url"]
    assert_equal "https://cve.ribose.com", csaf_index["base_url"]
    assert_equal "https://cve.ribose.com", vex_index["base_url"]

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
      assert_equal "https://cve.ribose.com/feeds/csaf/#{pkg}.json", index.dig("by_purl", purl, "csaf_feed_url")
      assert_equal "https://cve.ribose.com/feeds/vex/#{pkg}.json", index.dig("by_purl", purl, "vex_feed_url")

      assert_equal "https://cve.ribose.com/feeds/csaf/#{pkg}.json", csaf_index.dig("by_purl", purl, "csaf_feed_url")
      assert_equal "https://cve.ribose.com/feeds/vex/#{pkg}.json", vex_index.dig("by_purl", purl, "vex_feed_url")
    end
  end

  def test_rnp_osv_records_contain_expected_cves
    rnp = JSON.parse(File.read(File.join(FEEDS_DIR, "osv", "rnp.json"), encoding: "UTF-8"))
    rnp_csaf = JSON.parse(File.read(File.join(FEEDS_DIR, "csaf", "rnp.json"), encoding: "UTF-8"))
    rnp_vex = JSON.parse(File.read(File.join(FEEDS_DIR, "vex", "rnp.json"), encoding: "UTF-8"))
    ids = rnp["vulns"].map { |v| v["id"] }
    csaf_ids = rnp_csaf["vulnerabilities"].map { |v| v["cve"] }
    vex_ids = rnp_vex["documents"].map { |d| d.dig("statements", 0, "vulnerability", "name") }

    %w[CVE-2025-13470 CVE-2023-29480 CVE-2023-29479 CVE-2021-33589].each do |cve|
      assert_includes ids, cve
      assert_includes csaf_ids, cve
      assert_includes vex_ids, cve
      assert File.exist?(File.join(FEEDS_DIR, "osv", "#{cve}.json"))
      assert File.exist?(File.join(FEEDS_DIR, "csaf", "#{cve}.json"))
      assert File.exist?(File.join(FEEDS_DIR, "vex", "#{cve}.json"))
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
      FileUtils.cp_r(File.join(FEEDS_DIR, "csaf"), tmpdir)
      FileUtils.cp_r(File.join(FEEDS_DIR, "vex"), tmpdir)

      bad_record_path = File.join(tmpdir, "osv", "CVE-2025-99999.json")
      File.write(bad_record_path, JSON.pretty_generate({ "id" => "INVALID-PREFIX-123" }))

      out, status = Open3.capture2e(RbConfig.ruby, VALIDATE_SCRIPT, tmpdir)
      refute status.success?, "validate_feeds.rb must fail on malformed OSV record"
      assert_includes out, "validation failed"
    end
  end

  def test_validator_rejects_malformed_csaf_and_vex_records
    Dir.mktmpdir do |tmpdir|
      FileUtils.cp_r(File.join(FEEDS_DIR, "osv"), tmpdir)
      FileUtils.cp_r(File.join(FEEDS_DIR, "ghsa"), tmpdir)
      FileUtils.cp_r(File.join(FEEDS_DIR, "csaf"), tmpdir)
      FileUtils.cp_r(File.join(FEEDS_DIR, "vex"), tmpdir)

      File.write(File.join(tmpdir, "csaf", "CVE-2025-99999.json"), JSON.pretty_generate({ "document" => {} }))
      File.write(File.join(tmpdir, "vex", "CVE-2025-99999.json"), JSON.pretty_generate({ "statements" => [] }))

      out, status = Open3.capture2e(RbConfig.ruby, VALIDATE_SCRIPT, tmpdir)
      refute status.success?, "validate_feeds.rb must fail on malformed CSAF and OpenVEX records"
      assert_includes out, "CVE-2025-99999.json"
    end
  end
end
