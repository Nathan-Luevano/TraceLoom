from __future__ import annotations

from tracerloom.detection.base import Detector
from tracerloom.detection.rules.cpu_password_cracking import CpuPasswordCrackingDetector
from tracerloom.detection.rules.dns_exfiltration import DnsExfiltrationDetector
from tracerloom.detection.rules.privileged_access import PrivilegedAccessDetector
from tracerloom.detection.rules.vpn_identity_anomaly import VpnIdentityAnomalyDetector
from tracerloom.detection.rules.web_scanning import WebScanningDetector
from tracerloom.detection.rules.web_service_escalation import WebServiceUserSwitchDetector
from tracerloom.detection.rules.webshell_activity import WebshellActivityDetector


def default_detectors() -> list[Detector]:
    return [
        WebScanningDetector(),
        WebshellActivityDetector(),
        WebServiceUserSwitchDetector(),
        PrivilegedAccessDetector(),
        DnsExfiltrationDetector(),
        CpuPasswordCrackingDetector(),
        VpnIdentityAnomalyDetector(),
    ]
