from __future__ import annotations

from dataclasses import dataclass, field

from tracerloom.parsing.base import LineParser
from tracerloom.parsing.parsers.apache_access_log import ApacheAccessLogParser
from tracerloom.parsing.parsers.apache_error_log import ApacheErrorLogParser
from tracerloom.parsing.parsers.audit_log import AuditLogParser
from tracerloom.parsing.parsers.auth_log import AuthLogParser
from tracerloom.parsing.parsers.dnsmasq_log import DnsmasqLogParser
from tracerloom.parsing.parsers.monitoring_cpu_log import MonitoringCpuLogParser
from tracerloom.parsing.parsers.openvpn_log import OpenVpnLogParser


@dataclass(slots=True)
class ParserRegistry:
    parsers: list[LineParser] = field(default_factory=list)

    def register(self, parser: LineParser) -> None:
        self.parsers.append(parser)

    def find(self, relative_path: str) -> LineParser | None:
        for parser in self.parsers:
            if parser.matches(relative_path):
                return parser
        return None


def default_registry(reference_year: int) -> ParserRegistry:
    registry = ParserRegistry()
    registry.register(AuthLogParser(reference_year=reference_year))
    registry.register(DnsmasqLogParser(reference_year=reference_year))
    registry.register(OpenVpnLogParser())
    registry.register(ApacheAccessLogParser())
    registry.register(ApacheErrorLogParser())
    registry.register(AuditLogParser())
    registry.register(MonitoringCpuLogParser())
    return registry
