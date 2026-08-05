from tests.factories import make_event
from tracerloom.detection.rules.cpu_password_cracking import CpuPasswordCrackingDetector
from tracerloom.detection.rules.dns_exfiltration import DnsExfiltrationDetector
from tracerloom.detection.rules.privileged_access import PrivilegedAccessDetector
from tracerloom.detection.rules.vpn_identity_anomaly import VpnIdentityAnomalyDetector
from tracerloom.detection.rules.web_scanning import WebScanningDetector
from tracerloom.detection.rules.web_service_escalation import WebServiceUserSwitchDetector
from tracerloom.detection.rules.webshell_activity import WebshellActivityDetector


def test_web_scanning_detects_high_volume_probing() -> None:
    detector = WebScanningDetector(min_requests=10, min_unique_paths=5, min_not_found_ratio=0.5)
    events = [
        make_event(
            line=i,
            source_type="web_access",
            source_ip="203.0.113.5",
            resource=f"/probe-path-{i}",
            outcome="404",
            seconds_offset=i,
        )
        for i in range(12)
    ]
    alerts = detector.detect(events)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "web.scanning.high_rate"


def test_web_scanning_ignores_normal_browsing() -> None:
    detector = WebScanningDetector(min_requests=10, min_unique_paths=5, min_not_found_ratio=0.5)
    events = [
        make_event(
            line=1, source_type="web_access", source_ip="203.0.113.5", resource="/", outcome="200"
        ),
        make_event(
            line=2,
            source_type="web_access",
            source_ip="203.0.113.5",
            resource="/about",
            outcome="200",
            seconds_offset=1,
        ),
    ]
    assert detector.detect(events) == []


def test_webshell_detects_command_query_param() -> None:
    detector = WebshellActivityDetector()
    events = [
        make_event(
            line=1,
            source_type="web_access",
            resource="/uploads/helper.php?cmd=id",
            source_ip="203.0.113.9",
        )
    ]
    alerts = detector.detect(events)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "web.webshell.command_heuristic"


def test_webshell_ignores_normal_request() -> None:
    detector = WebshellActivityDetector()
    events = [make_event(line=1, source_type="web_access", resource="/index.html?page=2")]
    assert detector.detect(events) == []


def test_web_service_escalation_detects_www_data_su() -> None:
    detector = WebServiceUserSwitchDetector()
    events = [
        make_event(
            line=1,
            source_type="auth",
            action="user_switch",
            outcome="success",
            principal="root",
            resource="www-data",
        )
    ]
    alerts = detector.detect(events)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "auth.escalation.user_switch_from_web_context"


def test_web_service_escalation_ignores_normal_admin_su() -> None:
    detector = WebServiceUserSwitchDetector()
    events = [
        make_event(
            line=1,
            source_type="auth",
            action="user_switch",
            outcome="success",
            principal="root",
            resource="sysadmin",
        )
    ]
    assert detector.detect(events) == []


def test_privileged_access_detects_shadow_file_reference() -> None:
    detector = PrivilegedAccessDetector()
    events = [
        make_event(
            line=1,
            source_type="auth",
            action="privileged_command",
            principal="testuser",
            resource="/usr/bin/cat /etc/shadow",
        )
    ]
    alerts = detector.detect(events)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "privilege.sensitive_access.command_or_file"


def test_privileged_access_ignores_benign_command() -> None:
    detector = PrivilegedAccessDetector()
    events = [
        make_event(
            line=1,
            source_type="auth",
            action="privileged_command",
            principal="testuser",
            resource="/usr/bin/apt update",
        )
    ]
    assert detector.detect(events) == []


def test_dns_exfiltration_detects_high_entropy_subdomain_burst() -> None:
    detector = DnsExfiltrationDetector(
        min_suspicious_queries=3, min_label_length=15, min_entropy_bits_per_char=3.0
    )
    labels = [
        "kQ8x2mZ9pL4wR7vT",
        "bN3jY6cH1sD5eF8g",
        "mP2qA9zX4tL7wK1n",
        "hJ5rC8vB3nM6xQ2s",
    ]
    events = [
        make_event(
            line=i,
            source_type="dns",
            event_type="dns_query",
            resource=f"{label}.exfil-test.invalid",
            source_ip="198.51.100.7",
            seconds_offset=i,
        )
        for i, label in enumerate(labels)
    ]
    alerts = detector.detect(events)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "dns.exfiltration.entropy_heuristic"


def test_dns_exfiltration_ignores_normal_lookups() -> None:
    detector = DnsExfiltrationDetector(
        min_suspicious_queries=3, min_label_length=15, min_entropy_bits_per_char=3.0
    )
    events = [
        make_event(
            line=1,
            source_type="dns",
            event_type="dns_query",
            resource="www.example-test.invalid",
            source_ip="198.51.100.7",
        )
    ]
    assert detector.detect(events) == []


def test_cpu_detector_detects_sustained_high_load() -> None:
    detector = CpuPasswordCrackingDetector(high_pct_threshold=0.8, min_consecutive_samples=3)
    events = [
        make_event(line=i, source_type="monitoring_cpu", outcome="0.95", seconds_offset=i * 45)
        for i in range(5)
    ]
    alerts = detector.detect(events)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "host.cpu.sustained_high_load"


def test_cpu_detector_ignores_normal_load() -> None:
    detector = CpuPasswordCrackingDetector(high_pct_threshold=0.8, min_consecutive_samples=3)
    events = [
        make_event(line=i, source_type="monitoring_cpu", outcome="0.10", seconds_offset=i * 45)
        for i in range(5)
    ]
    assert detector.detect(events) == []


def test_vpn_anomaly_detects_ip_outside_baseline() -> None:
    detector = VpnIdentityAnomalyDetector(baseline_session_count=2)
    events = [
        make_event(
            line=1,
            source_type="vpn",
            principal="synthuser",
            source_ip="198.51.100.1",
            seconds_offset=0,
        ),
        make_event(
            line=2,
            source_type="vpn",
            principal="synthuser",
            source_ip="198.51.100.1",
            seconds_offset=60,
        ),
        make_event(
            line=3,
            source_type="vpn",
            principal="synthuser",
            source_ip="203.0.113.200",
            seconds_offset=120,
        ),
    ]
    alerts = detector.detect(events)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "vpn.identity.baseline_deviation"


def test_vpn_anomaly_ignores_consistent_baseline_ip() -> None:
    detector = VpnIdentityAnomalyDetector(baseline_session_count=2)
    events = [
        make_event(
            line=1,
            source_type="vpn",
            principal="synthuser",
            source_ip="198.51.100.1",
            seconds_offset=0,
        ),
        make_event(
            line=2,
            source_type="vpn",
            principal="synthuser",
            source_ip="198.51.100.1",
            seconds_offset=60,
        ),
        make_event(
            line=3,
            source_type="vpn",
            principal="synthuser",
            source_ip="198.51.100.1",
            seconds_offset=120,
        ),
    ]
    assert detector.detect(events) == []
