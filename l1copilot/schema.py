from dataclasses import dataclass, asdict, field

VERDICTS = ("true_positive", "false_positive")

MITRE = {
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1078": "Valid Accounts",
    "T1021.004": "Remote Services: SSH",
    "T1548.003": "Abuse Elevation Control: Sudo and Sudo Caching",
    "T1136.001": "Create Account: Local Account",
    "T1046": "Network Service Discovery",
    "none": "No technique (benign)",
}


@dataclass
class Triage:
    alert_id: str
    verdict: str
    mitre: str
    severity: str
    confidence: float
    reasoning: str
    engine: str = "mock"
    flags: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


def validate(d: dict) -> dict:
    """Coerce/validate LLM JSON output. Raises ValueError on bad output."""
    v = str(d.get("verdict", "")).lower().strip()
    if v not in VERDICTS:
        raise ValueError(f"bad verdict: {v!r}")
    m = str(d.get("mitre", "none")).strip()
    if m not in MITRE:
        m = "none" if v == "false_positive" else "T1110.001"
    sev = str(d.get("severity", "low")).lower()
    if sev not in ("low", "medium", "high", "critical"):
        sev = "medium"
    try:
        conf = max(0.0, min(1.0, float(d.get("confidence", 0.5))))
    except (TypeError, ValueError):
        conf = 0.5
    return {"verdict": v, "mitre": m, "severity": sev, "confidence": conf,
            "reasoning": str(d.get("reasoning", ""))[:600]}
