from __future__ import annotations

RECONNAISSANCE = "reconnaissance"
INITIAL_ACCESS = "initial_access"
PRIVILEGE_ESCALATION = "privilege_escalation"
COMMAND_EXECUTION = "command_execution"
EXFILTRATION = "exfiltration"

STAGE_ORDER: dict[str, int] = {
    RECONNAISSANCE: 0,
    INITIAL_ACCESS: 1,
    PRIVILEGE_ESCALATION: 2,
    COMMAND_EXECUTION: 3,
    EXFILTRATION: 4,
}

RULE_STAGE: dict[str, str] = {
    "web.scanning.high_rate": RECONNAISSANCE,
    "web.webshell.command_heuristic": INITIAL_ACCESS,
    "vpn.identity.baseline_deviation": INITIAL_ACCESS,
    "auth.escalation.user_switch_from_web_context": PRIVILEGE_ESCALATION,
    "host.cpu.sustained_high_load": PRIVILEGE_ESCALATION,
    "privilege.sensitive_access.command_or_file": COMMAND_EXECUTION,
    "dns.exfiltration.entropy_heuristic": EXFILTRATION,
}
