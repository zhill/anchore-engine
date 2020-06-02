import datetime
import pytest
from anchore_engine.services.policy_engine.engine import vulnerabilities
from anchore_engine.subsys import logger

# DB entities used for mapping tests
from anchore_engine.db.entities.policy_engine import Image, ImageCpe, ImagePackageVulnerability, ImagePackage, Vulnerability, VulnDBCpe, VulnDBMetadata, CpeV2Vulnerability, NvdV2Metadata, FixedArtifact, VulnerableArtifact

logger.enable_test_logging(level='info')


def test_namespace_has_no_feed():
    """
    Test the caching mechanisms used during feed syncs to optimize lookups w/o db access

    :return:
    """
    # Nothing initially
    assert vulnerabilities.namespace_has_no_feed('debian', '8')

    vulnerabilities.ThreadLocalFeedGroupNameCache.add([('debian:8', True), ('debian:9', True), ('centos:4', False)])
    assert vulnerabilities.ThreadLocalFeedGroupNameCache.lookup('debian:8') == ('debian:8', True)
    assert vulnerabilities.ThreadLocalFeedGroupNameCache.lookup('debian:9') == ('debian:9', True)
    assert vulnerabilities.ThreadLocalFeedGroupNameCache.lookup('centos:4') == ('centos:4', False)
    assert not vulnerabilities.namespace_has_no_feed('debian', '8')
    assert not vulnerabilities.namespace_has_no_feed('debian', '9')
    assert vulnerabilities.namespace_has_no_feed('debian', 'foobar')
    assert vulnerabilities.namespace_has_no_feed('centos', '4')

    # Empty
    vulnerabilities.ThreadLocalFeedGroupNameCache.flush()
    assert vulnerabilities.namespace_has_no_feed('debian', '8')


def test_get_namespace_related_names():
    """
    Tests the older enable-filtering behavior of the namespace selector for which image/distros to update during a given
    feed sync

    :return:
    """
    assert vulnerabilities.namespace_has_no_feed('debian', '8')

    # State pre 0.7.0 upgrade
    # Assume centos -> centos, and all enabled
    mapped_to_centos = ['centos', 'rhel', 'fedora']
    mapped_to_rhel = []

    vulnerabilities.ThreadLocalFeedGroupNameCache.add([('centos:8', True), ('rhel:8', True)])
    # When centos feed updates
    assert set(vulnerabilities.get_namespace_related_names('centos', '8', mapped_to_centos)) == {'centos', 'fedora'}

    # When rhel feed updates
    assert set(vulnerabilities.get_namespace_related_names('rhel', '8', mapped_to_rhel)) == {'rhel'}

    vulnerabilities.ThreadLocalFeedGroupNameCache.flush()

    # State post 0.7.0 upgrade

    # Toggle enabled and see
    mapped_to_centos = []
    mapped_to_rhel = ['rhel', 'centos', 'fedora']
    vulnerabilities.ThreadLocalFeedGroupNameCache.add([('centos:7', False), ('rhel:7', True)])

    assert set(vulnerabilities.get_namespace_related_names('centos', '7', mapped_to_centos)) == set()
    assert set(vulnerabilities.get_namespace_related_names('rhel', '7', mapped_to_rhel)) == {'rhel', 'centos', 'fedora'}

    vulnerabilities.ThreadLocalFeedGroupNameCache.flush()

    # Revert from 0.7.0 upgrade if user wants RHSA again...
    mapped_to_centos = []
    mapped_to_rhel = ['rhel', 'centos', 'fedora']
    vulnerabilities.ThreadLocalFeedGroupNameCache.add([('centos:7', True), ('rhel:7', True)])

    assert set(vulnerabilities.get_namespace_related_names('centos', '7', mapped_to_centos)) == {'centos'}
    assert set(vulnerabilities.get_namespace_related_names('rhel', '7', mapped_to_rhel)) == {'rhel', 'fedora'}

    vulnerabilities.ThreadLocalFeedGroupNameCache.flush()


@pytest.fixture
def simple_nvd_vulnerability():
    # Picked a random CVE that actually exists for testing, but alters some data for better fit
    v = NvdV2Metadata()
    v.name = "CVE-2020-9785"
    v.severity = 'High'
    v.description = "Multiple memory corruption issues were addressed with improved state management. This issue is fixed in iOS 13.4 and iPadOS 13.4, macOS Catalina 10.15.4, tvOS 13.4, watchOS 6.2. A malicious application may be able to execute arbitrary code with kernel privileges"
    v.created_at = datetime.datetime.utcnow()
    v.updated_at = v.created_at
    v.namespace_name = 'nvdv2:cves'
    v.link = 'https://nvd.nist.gov/vuln/detail/CVE-2020-9785'
    v.references = [
        {"source": "MISC", "tags": ["Vendor Advisory"], "url": "https://support.apple.com/HT211100"},
        {"source": "MISC", "tags": ["Vendor Advisory"], "url": "https://support.apple.com/HT211101"},
    ]
    v.cvss_v3 = {
        "base_metrics": {
            "attack_complexity": "LOW",
            "attack_vector": "LOCAL",
            "availability_impact": "HIGH",
            "base_score": 7.8,
            "base_severity": "High",
            "confidentiality_impact": "HIGH",
            "exploitability_score": 1.8,
            "impact_score": 5.9,
            "integrity_impact": "HIGH",
            "privileges_required": "NONE",
            "scope": "UNCHANGED",
            "user_interaction": "REQUIRED"},
        "vector_string": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "version": "3.1"
    }
    v.cvss_v2 = {
        "additional_information": {
            "ac_insuf_info": False,
            "obtain_all_privilege": False,
            "obtain_other_privilege": False,
            "obtain_user_privilege": False,
            "user_interaction_required": True
            },
            "base_metrics": {
                "access_complexity": "MEDIUM",
                "access_vector": "NETWORK",
                "authentication": "NONE",
                "availability_impact": "COMPLETE",
                "base_score": 9.3,
                "confidentiality_impact": "COMPLETE",
                "exploitability_score": 8.6,
                "impact_score": 10.0,
                "integrity_impact": "COMPLETE"
            },
            "severity": "High",
            "vector_string": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
            "version": "2.0"
        }

    cpe = CpeV2Vulnerability()
    cpe.feed_name = 'nvdv2'
    cpe.namespace_name = v.namespace_name
    cpe.parent = v
    cpe.vulnerability_id = v.name
    cpe.part = 'a' #This is changed from the actual NVD record
    cpe.vendor = 'apple'
    cpe.product = 'watchos'
    cpe.version = '6.1'
    cpe.update = cpe.edition = cpe.language = cpe.sw_edition = cpe.target_hw = cpe.target_sw = cpe.other = '*'
    cpe.created_at = v.created_at
    cpe.updated_at = v.updated_at

    v.vulnerable_cpes = [cpe]
    return v

@pytest.fixture
def simple_vulndb_vulnerability():
    # Picked a random CVE that actually exists for testing, but alters some data for better fit
    v = VulnDBMetadata()
    v.name = "CVE-2020-9785"
    v.severity = 'High'
    v.description = "Multiple memory corruption issues were addressed with improved state management. This issue is fixed in iOS 13.4 and iPadOS 13.4, macOS Catalina 10.15.4, tvOS 13.4, watchOS 6.2. A malicious application may be able to execute arbitrary code with kernel privileges"
    v.created_at = datetime.datetime.utcnow()
    v.updated_at = v.created_at
    v.namespace_name = 'vulndb:cves'
    v.references = [
        {"source": "MISC", "tags": ["Vendor Advisory"], "url": "https://support.apple.com/HT211100"},
        {"source": "MISC", "tags": ["Vendor Advisory"], "url": "https://support.apple.com/HT211101"},
    ]
    v.cvss_v3 = {
        "base_metrics": {
            "attack_complexity": "LOW",
            "attack_vector": "LOCAL",
            "availability_impact": "HIGH",
            "base_score": 7.8,
            "base_severity": "High",
            "confidentiality_impact": "HIGH",
            "exploitability_score": 1.8,
            "impact_score": 5.9,
            "integrity_impact": "HIGH",
            "privileges_required": "NONE",
            "scope": "UNCHANGED",
            "user_interaction": "REQUIRED"},
        "vector_string": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "version": "3.1"
    }
    v.cvss_v2 = {
        "additional_information": {
            "ac_insuf_info": False,
            "obtain_all_privilege": False,
            "obtain_other_privilege": False,
            "obtain_user_privilege": False,
            "user_interaction_required": True
            },
            "base_metrics": {
                "access_complexity": "MEDIUM",
                "access_vector": "NETWORK",
                "authentication": "NONE",
                "availability_impact": "COMPLETE",
                "base_score": 9.3,
                "confidentiality_impact": "COMPLETE",
                "exploitability_score": 8.6,
                "impact_score": 10.0,
                "integrity_impact": "COMPLETE"
            },
            "severity": "High",
            "vector_string": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
            "version": "2.0"
        }

    # Setup the vendor stuff with a slight variation on the vulndb data
    v.vendor_cvss_v2 = v.cvss_v2
    v.vendor_cvss_v2['base_metrics']['base_score'] = 9.0
    v.vendor_cvss_v3 = v.cvss_v3
    v.vendor_cvss_v3['base_metrics']['base_score'] = 8.0
    v.vendor_product_info = None

    cpe = VulnDBCpe()
    cpe.feed_name = 'vulndb'
    cpe.namespace_name = v.namespace_name
    cpe.parent = v
    cpe.vulnerability_id = v.name
    cpe.part = 'a' #This is changed from the actual NVD record
    cpe.vendor = 'apple'
    cpe.product = 'watchos'
    cpe.version = '6.1'
    cpe.update = cpe.edition = cpe.language = cpe.sw_edition = cpe.target_hw = cpe.target_sw = cpe.other = '*'
    cpe.created_at = v.created_at
    cpe.updated_at = v.updated_at
    cpe.is_affected = True
    v.cpes = [cpe]

    return v


@pytest.fixture
def simple_fixed_distro_vulnerability():
    """
    Standard distro vuln with fixed artifacts indicating fix available
    :return:
    """

    v = Vulnerability()
    v.id = 'CVE-2020-9355'
    v.severity = 'High'
    v.description = 'Some nasty bug'
    v.namespace_name = 'debian:9'
    v.link = 'https://security-tracker.debian.org/tracker/CVE-2020-9355'
    v.created_at = v.updated_at = datetime.datetime.utcnow()
    v.metadata_json = {"NVD": {"CVSSv2": {"Score": 7.5, "Vectors": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}}}
    v.cvss2_vectors = 'AV:N/AC:L/Au:N/C:P/I:P/A:P'
    v.cvss2_score = 7.5

    f = FixedArtifact()
    f.namespace_name = v.namespace_name
    f.name = 'network-manager-ssh'
    f.vulnerability_id = v.id
    f.created_at = f.updated_at = v.created_at
    f.parent = v
    f.version = '1.2.1-1+deb9u1'
    f.version_format = 'dpkg'
    f.epochless_version = '1.2.1-1+deb9u1'
    f.include_later_versions = True
    f.vendor_no_advisory = False
    f.fix_metadata = {"VendorAdvisorySummary": [{"ID": "DSA-4637-1", "Link": "https://security-tracker.debian.org/tracker/DSA-4637-1"}]}
    f.fix_observed_at = f.updated_at
    v.fixed_in = [f]
    v.vulnerable_in = None
    return v

@pytest.fixture
def simple_will_not_fix_distro_vulnerability():
    """
    Standard distro vuln with fixed artifacts indicating fix available
    :return:
    """

    v = Vulnerability()
    v.id = 'CVE-2020-9760'
    v.severity = 'High'
    v.description = 'Some nasty bug'
    v.namespace_name = 'debian:9'
    v.link = 'https://security-tracker.debian.org/tracker/CVE-2020-9760'
    v.created_at = v.updated_at = datetime.datetime.utcnow()
    v.metadata_json = {"NVD": {"CVSSv2": {"Score": 7.5, "Vectors": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}}}
    v.cvss2_vectors = 'AV:N/AC:L/Au:N/C:P/I:P/A:P'
    v.cvss2_score = 7.5

    f = FixedArtifact()
    f.namespace_name = v.namespace_name
    f.name = 'weechat'
    f.vulnerability_id = v.id
    f.created_at = f.updated_at = v.created_at
    f.parent = v
    f.version = 'None'
    f.version_format = 'dpkg'
    f.epochless_version = 'None'
    f.include_later_versions = True
    f.vendor_no_advisory = True
    f.fix_metadata = None
    f.fix_observed_at = None

    v.fixed_in = [f]
    v.vulnerable_in = None
    return v


@pytest.fixture
def simple_unfixed_distro_vulnerability():
    """
    Standard distro vuln with fixed artifacts indicating fix available
    :return:
    """

    v = Vulnerability()
    v.id = 'CVE-2020-9760'
    v.severity = 'High'
    v.description = 'Some nasty bug'
    v.namespace_name = 'debian:9'
    v.link = 'https://security-tracker.debian.org/tracker/CVE-2020-9760'
    v.created_at = v.updated_at = datetime.datetime.utcnow()
    v.metadata_json = {"NVD": {"CVSSv2": {"Score": 7.5, "Vectors": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}}}
    v.cvss2_vectors = 'AV:N/AC:L/Au:N/C:P/I:P/A:P'
    v.cvss2_score = 7.5

    f = FixedArtifact()
    f.namespace_name = v.namespace_name
    f.name = 'weechat'
    f.vulnerability_id = v.id
    f.created_at = f.updated_at = v.created_at
    f.parent = v
    f.version = 'None'
    f.version_format = 'dpkg'
    f.epochless_version = 'None'
    f.include_later_versions = True
    f.vendor_no_advisory = False # Changed from actual data to indicate a fix will come
    f.fix_metadata = None
    f.fix_observed_at = None

    v.fixed_in = [f]
    v.vulnerable_in = None
    return v


@pytest.fixture
def simple_vuln_record_advisory():
    """
    Vulnerability record that has no fixed artifacts, only vulnerable artifacts
    :return:
    """
    v = Vulnerability()
    v.fixed_in = None
    v.vulnerable_in = []
    return v


def test_map_cpe2_vuln(simple_nvd_vulnerability):
    dest = vulnerabilities.ReportVulnerability()
    src = simple_nvd_vulnerability.vulnerable_cpes[0]
    vulnerabilities.map_cpe2_vuln(dest, src)

    assert dest is not None
    assert src is not None
    assert dest.severity == simple_nvd_vulnerability.severity
    assert dest.id == src.vulnerability_id


def test_map_vulndb_vuln(simple_vulndb_vulnerability):
    dest = vulnerabilities.ReportVulnerability()
    src = simple_vulndb_vulnerability.vulnerable_cpes[0]
    vulnerabilities.map_vulndb_vuln(dest, src)

    assert dest is not None
    assert src is not None
    assert dest.severity == simple_vulndb_vulnerability.severity
    assert dest.id == src.vulnerability_id


def test_generate_vuln_report():
    """
    Test full report generation

    :return:
    """
    img = Image()
    packages = []
    img.packages = packages

    report = vulnerabilities.get_vulnerability_report(img)
    assert report is not None
    assert report.image_id is not None
    assert report.image_digest is not None
    assert report.vulnerabilities is not None
    assert len(report.vulnerabilities) > 0
