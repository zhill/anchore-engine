import copy
import pytest
import datetime

from anchore_engine.db.entities.policy_engine import Vulnerability, ImagePackageVulnerability, ImageCpe, ImagePackage, FixedArtifact, VulnerableArtifact, CpeV2Vulnerability, VulnDBCpe, NvdV2Metadata, Image
from anchore_engine.services.policy_engine.engine.vulnerabilities import VulnerabilityMatch, ImagePackage, ReportVulnerability, ImageVulnerabilityReport, VulnerablePackage, CVSSMetadata
from anchore_engine.services.policy_engine.engine.policy.gates.vulnerabilities import SeverityCheck, SEVERITY_ORDERING, OPERATORS, compare_severity, OSPackageCheck, NonOSPackageCheck, FixAgeCheck, FixAvailableCheck, BaseScoreCheck, ExploitScoreCheck, ImpactScoreCheck, VulnAgeCheck
from anchore_engine.common import os_package_types, nonos_package_types

from anchore_engine.subsys import logger
logger.enable_test_logging(level='DEBUG')


@pytest.fixture
def image_vulnerability():
    v = Vulnerability()
    v.id = 'CVE-1'
    v.namespace_name = 'rhel:8'
    v.severity = 'High'
    v.description = 'Some test vuln'
    v.link = 'https://nvd.nist.gov/cves/cve-1'
    v.metadata_json = {}
    v.cvss2_score = 8.0
    v.cvss2_vectors = ''
    v.vulnerable_in = []
    v.fixed_in = [FixedArtifact()]
    f = v.fixed_in[0]
    f.name = 'lib1'
    f.version = '1.0.1'
    f.namespace_name = 'rhel:8'
    f.vulnerability_id = v.id
    f.epochless_version = '1.0.1'
    f.fix_observed_at = datetime.datetime.utcnow() - datetime.timedelta(days=5)
    f.created_at = datetime.datetime.utcnow() - datetime.timedelta(days=5)
    f.include_later_versions = True
    f.parent = v
    f.version_format = 'rpm'

    ip = ImagePackageVulnerability()
    ip.package = ImagePackage()
    ip.package.name = 'lib1'
    ip.package.version = '1.0.0'
    ip.package.pkg_type = 'rpm'
    ip.package.pkg_path = 'rpmdb'
    ip.package.metadata_json = {}
    ip.package.arch = 'amd64'
    ip.package.distro_name = 'centos'
    ip.package.distro_version = '8'
    ip.package.fullversion = '1.0.0.el8'
    ip.package.license = 'mit'
    ip.package.like_distro = 'rhel'
    ip.package.src_pkg = 'lib1'
    ip.package.normalized_src_pkg = 'lib1'
    ip.vulnerability = v
    ip.vulnerability_id = v.id
    ip.vulnerability_namespace_name = v.namespace_name

    return ip


def rhel_vuln_reports():
    image = Image()
    image.id = '1'
    image.user_id = 'account'
    image.created_at = datetime.datetime.utcnow()
    image.distro_name = 'centos'
    image.distro_version = '8'

    pkg = VulnerablePackage()
    pkg.name = 'lib1'
    pkg.version = '0:1.1.1g-1.el8'
    pkg.type = 'rpm'
    pkg.path = 'rpmdb'
    pkg.vendor = 'redhat'
    pkg.source_package_name = 'lib1'
    pkg.full_version = '0:1.1.1g-1.el8.x86_64'
    pkg.matched_version = pkg.version
    pkg.matched_name = pkg.name
    pkg.namespace = 'rhel:8'

    v = ReportVulnerability()
    v.id = 'CVE-1'
    v.namespace = 'rhel:8'
    v.severity = 'high'
    v.created_at = datetime.datetime.utcnow() - datetime.timedelta(days=10)
    v.fixed_at_date = v.created_at
    v.fix_version = '0:1.1.2g-1.el8'
    v.cvss = None
    v.will_not_fix = False

    vulnerabilities = [
        VulnerabilityMatch(package=pkg, vuln=v)
    ]

    report = ImageVulnerabilityReport(image=image, vulnerabilities=vulnerabilities)
    return [report]


def debian_vuln_reports():
    return []


manual_severity_checks = [
    ('unknown', '=', 'unknown', True),
    ('unknown', '=', 'low', False),
    ('unknown', '!=', 'low', True),
    ('unknown', '!=', 'unknown', False),
    ('unknown', '<=', 'unknown', True),
    ('unknown', '<=', 'low', True),
    ('low', '<=', 'unknown', False),
    ('unknown', '<', 'low', True),
    ('unknown', '<', 'unknown', False),
    ('low', '<', 'unknown', False),
    ('low', '>', 'unknown', True),
    ('unknown', '>', 'low', False),
    ('unknown', '>', 'unknown', False),
    ('unknown', '>=', 'unknown', True),
    ('unknown', '>=', 'low', False),
    ('low', '>=', 'unknown', True)
]


@pytest.mark.parametrize('lval, op, rval, expected', manual_severity_checks)
def test_compare_severity(lval, op, rval, expected):
    assert compare_severity(lval, op, rval) is expected


def severity_vuln_match(sev):
    """
    Return a vuln match with given severity

    :param sev:
    :return:
    """
    pkg = VulnerablePackage()
    pkg.name = 'lib1'
    pkg.version = '0:1.1.1g-1.el8'
    pkg.type = 'rpm'
    pkg.path = 'rpmdb'
    pkg.vendor = 'redhat'
    pkg.source_package_name = 'lib1'
    pkg.full_version = '0:1.1.1g-1.el8.x86_64'
    pkg.matched_version = pkg.version
    pkg.matched_name = pkg.name
    pkg.namespace = 'rhel:8'

    v = ReportVulnerability()
    v.id = 'CVE-1'
    v.namespace = 'rhel:8'
    v.severity = sev
    v.created_at = datetime.datetime.utcnow() - datetime.timedelta(days=10)
    v.fixed_at_date = v.created_at
    v.fix_version = '0:1.1.2g-1.el8'
    v.cvss = CVSSMetadata(base=2.0, exploit=1.0, impact=1.0, version='3')
    v.will_not_fix = False
    return VulnerabilityMatch(pkg, v)


def severity_matrix():
    """
    Generates a matrix of severities and comparisons for testing.
    Returns a list of tuples of form [(expected_comparison_result, vulnerability severity, operator, check rule severity), ....]

    :return:
    """
    test_matrix = []
    for vuln_sev in SEVERITY_ORDERING:
        for op in OPERATORS.keys():
            for rule_sev in SEVERITY_ORDERING:
                expected = compare_severity(vuln_sev, op, rule_sev)
                test_matrix.append((expected, vuln_sev, op, rule_sev))
    return test_matrix


@pytest.mark.parametrize('expected, vuln_severity, comparison, rule_severity', severity_matrix())
def test_match_severity_check(expected: bool, vuln_severity: str, comparison: str, rule_severity: str):
    match = severity_vuln_match(vuln_severity)
    check = SeverityCheck(rule_severity, comparison)
    assert check.matches(match) is expected, '{}({}, {}) != {}'.format(comparison, match.vulnerability.severity, rule_severity, expected)


@pytest.mark.parametrize('pkg_type, expected', [(x, True) for x in os_package_types] + [(x, False) for x in nonos_package_types])
def test_os_package_check(pkg_type: str, expected: bool):
    check = OSPackageCheck()
    m = severity_vuln_match('low') # Doesn't matter, just create a vuln match
    m.package.type = pkg_type
    assert check.matches(m) is expected


@pytest.mark.parametrize('pkg_type, expected', [(x, False) for x in os_package_types] + [(x, True) for x in nonos_package_types])
def test_non_os_package_check(pkg_type: str, expected: bool):
    check = NonOSPackageCheck()
    m = severity_vuln_match('low') # Doesn't matter, just create a vuln match
    m.package.type = pkg_type
    assert check.matches(m) is expected


def test_fix_available_check():
    check = FixAvailableCheck(True)
    m = severity_vuln_match('low')
    assert check.matches(m) is True

    m = severity_vuln_match('low')
    m.vulnerability.fix_version = None
    assert check.matches(m) is False

    m.vulnerability.fix_version = 'None'
    assert check.matches(m) is False

    m.vulnerability.fix_version = None
    assert check.matches(m) is False

    check = FixAvailableCheck(False)
    m = severity_vuln_match('low')
    assert check.matches(m) is False

    m.vulnerability.fix_version = None
    assert check.matches(m) is True

    m.vulnerability.fix_version = 'None'
    assert check.matches(m) is True


def test_fix_age_check():
    check = FixAgeCheck(1)
    m = severity_vuln_match('low')
    m.vulnerability.fixed_at_date = datetime.datetime.utcnow() - datetime.timedelta(days=5)
    assert check.matches(m) is True

    check = FixAgeCheck(10)
    m = severity_vuln_match('low')
    m.vulnerability.fixed_at_date = datetime.datetime.utcnow() - datetime.timedelta(days=5)
    assert check.matches(m) is False

    check = FixAgeCheck(1)
    m = severity_vuln_match('low')
    m.vulnerability.fixed_at_date = datetime.datetime.utcnow() - datetime.timedelta(days=1)
    assert check.matches(m) is True

    check = FixAgeCheck(0)
    m = severity_vuln_match('low')
    m.vulnerability.fixed_at_date = datetime.datetime.utcnow() - datetime.timedelta(days=1)
    assert check.matches(m) is True

    m.vulnerability.fixed_at_date = datetime.datetime.utcnow()
    assert check.matches(m) is True


def test_vuln_age_check():
    check = VulnAgeCheck(1)
    m = severity_vuln_match('low')
    m.vulnerability.created_at = datetime.datetime.utcnow() - datetime.timedelta(days=5)
    assert check.matches(m) is True

    check = VulnAgeCheck(10)
    m = severity_vuln_match('low')
    m.vulnerability.created_at = datetime.datetime.utcnow() - datetime.timedelta(days=5)
    assert check.matches(m) is False

    check = VulnAgeCheck(1)
    m = severity_vuln_match('low')
    m.vulnerability.created_at = datetime.datetime.utcnow() - datetime.timedelta(days=1)
    assert check.matches(m) is True

    check = VulnAgeCheck(0)
    m = severity_vuln_match('low')
    m.vulnerability.created_at = datetime.datetime.utcnow() - datetime.timedelta(days=1)
    assert check.matches(m) is True

    m.vulnerability.created_at = datetime.datetime.utcnow()
    assert check.matches(m) is True


def test_base_score_check():
    check = BaseScoreCheck(7.0, '>')
    m = severity_vuln_match('low')
    m.vulnerability.cvss.base = 7.1
    assert check.matches(m) is True

    m.vulnerability.cvss.base = 6.0
    assert check.matches(m) is False

    m.vulnerability.cvss.base = 7.0
    assert check.matches(m) is False

    check = BaseScoreCheck(7.0, '<')
    m = severity_vuln_match('low')
    m.vulnerability.cvss.base = 6.0
    assert check.matches(m) is True

    m.vulnerability.cvss.base = 7.2
    assert check.matches(m) is False

    m.vulnerability.cvss.base = 7.0
    assert check.matches(m) is False



def test_impact_score_check():
    pass


def test_exploit_score_check():
    pass


def test_vendor_base_score_check():
    pass


def tset_vendor_impact_score_check():
    pass


def test_vendor_exploit_score_check():
    pass