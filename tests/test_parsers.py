from tracerloom.parsing.parsers.apache_access_log import ApacheAccessLogParser
from tracerloom.parsing.parsers.apache_error_log import ApacheErrorLogParser
from tracerloom.parsing.parsers.audit_log import AuditLogParser
from tracerloom.parsing.parsers.auth_log import AuthLogParser
from tracerloom.parsing.parsers.dnsmasq_log import DnsmasqLogParser
from tracerloom.parsing.parsers.monitoring_cpu_log import MonitoringCpuLogParser
from tracerloom.parsing.parsers.openvpn_log import OpenVpnLogParser


def test_auth_log_parses_su_login() -> None:
    parser = AuthLogParser(reference_year=2031)
    line = (
        "Jun  1 08:05:11 authhost su[202]: pam_unix(su:session): session opened "
        "for user targetacct by testuser(uid=1000)"
    )
    outcome = parser.parse_line("d", "authhost", "auth.log", 3, line)
    assert outcome.event is not None
    assert outcome.event.action == "user_switch"
    assert outcome.event.principal == "targetacct"
    assert outcome.event.timestamp.year == 2031


def test_auth_log_dead_letters_garbage() -> None:
    parser = AuthLogParser(reference_year=2031)
    outcome = parser.parse_line("d", "authhost", "auth.log", 6, "not syslog at all")
    assert outcome.event is None
    assert outcome.dead_letter is not None
    assert outcome.dead_letter.line_number == 6


def test_dnsmasq_parses_query_line() -> None:
    parser = DnsmasqLogParser(reference_year=2031)
    line = "Jun  1 08:00:00 dnsmasq[500]: query[A] www.example-test.invalid from 10.0.0.9"
    outcome = parser.parse_line("d", "dnshost", "dnsmasq.log", 1, line)
    assert outcome.event is not None
    assert outcome.event.event_type == "dns_query"
    assert outcome.event.resource == "www.example-test.invalid"
    assert outcome.event.source_ip == "10.0.0.9"


def test_dnsmasq_dead_letters_unrecognized_line() -> None:
    parser = DnsmasqLogParser(reference_year=2031)
    outcome = parser.parse_line("d", "dnshost", "dnsmasq.log", 4, "not a dnsmasq line")
    assert outcome.event is None
    assert outcome.dead_letter is not None


def test_openvpn_parses_identity_verification() -> None:
    parser = OpenVpnLogParser()
    line = "2031-06-01 08:00:01 198.51.100.20:40000 VERIFY OK: depth=0, CN=synthuser"
    outcome = parser.parse_line("d", "vpnhost", "openvpn.log", 2, line)
    assert outcome.event is not None
    assert outcome.event.principal == "synthuser"
    assert outcome.event.event_type == "vpn_identity_verified"


def test_openvpn_dead_letters_unrecognized_line() -> None:
    parser = OpenVpnLogParser()
    outcome = parser.parse_line("d", "vpnhost", "openvpn.log", 4, "totally malformed vpn line")
    assert outcome.event is None


def test_apache_access_parses_status_and_path() -> None:
    parser = ApacheAccessLogParser()
    line = (
        '198.51.100.7 - - [01/Jun/2031:08:00:02 +0000] "POST /uploads/shell.php?cmd=id HTTP/1.1" '
        '200 12 "-" "curl/7.68.0"'
    )
    outcome = parser.parse_line("d", "webhost", "site-access.log", 3, line)
    assert outcome.event is not None
    assert outcome.event.resource == "/uploads/shell.php?cmd=id"
    assert outcome.event.outcome == "200"
    assert outcome.event.action == "POST"


def test_apache_access_dead_letters_malformed_line() -> None:
    parser = ApacheAccessLogParser()
    outcome = parser.parse_line(
        "d", "webhost", "site-access.log", 4, "this is not a valid access log line at all"
    )
    assert outcome.event is None


def test_apache_error_parses_client_and_module() -> None:
    parser = ApacheErrorLogParser()
    line = (
        "[Mon Jun 01 08:00:00.000000 2031] [authz_core:error] [pid 1] "
        "[client 198.51.100.7:1234] AH01630: denied"
    )
    outcome = parser.parse_line("d", "webhost", "error.log", 1, line)
    assert outcome.event is not None
    assert outcome.event.source_ip == "198.51.100.7"
    assert outcome.event.action == "authz_core:error"


def test_audit_log_parses_service_start() -> None:
    parser = AuditLogParser()
    line = (
        "type=SERVICE_START msg=audit(1900000000.100:1): "
        "pid=1 uid=0 auid=4294967295 ses=4294967295 "
        'msg=\'unit=synthsvc comm="systemd" exe="/lib/systemd/systemd" '
        "hostname=? addr=? terminal=? res=success'"
    )
    outcome = parser.parse_line("d", "sharehost", "audit.log", 1, line)
    assert outcome.event is not None
    assert outcome.event.resource == "synthsvc"
    assert outcome.event.outcome == "success"


def test_audit_log_dead_letters_garbage() -> None:
    parser = AuditLogParser()
    outcome = parser.parse_line(
        "d", "sharehost", "audit.log", 3, "garbage audit line without expected structure"
    )
    assert outcome.event is None


def test_monitoring_cpu_parses_pct_and_host() -> None:
    parser = MonitoringCpuLogParser()
    line = (
        '{"@timestamp": "2031-06-01T08:00:45.000Z", '
        '"host": {"name": "webhost", "cpu": {"pct": 0.97}}, '
        '"system": {"cpu": {"total": {"pct": 0.97}}}}'
    )
    outcome = parser.parse_line("d", "monhost", "cpu.log", 2, line)
    assert outcome.event is not None
    assert outcome.event.host == "webhost"
    assert outcome.event.outcome == "0.97"


def test_monitoring_cpu_dead_letters_non_json() -> None:
    parser = MonitoringCpuLogParser()
    outcome = parser.parse_line("d", "monhost", "cpu.log", 3, "not json at all")
    assert outcome.event is None
