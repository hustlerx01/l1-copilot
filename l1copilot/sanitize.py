"""Guardrails: log fields are attacker-controlled (usernames, hostnames)."""
import re

INJECTION_PATTERNS = [
    r"ignore (all|any|previous|prior) (instructions|rules)",
    r"you are now", r"system prompt", r"mark (this|it) as (benign|false)",
    r"false[_ ]positive", r"</?(system|assistant|user)>", r"```",
]
_RX = re.compile("|".join(INJECTION_PATTERNS), re.I)


def sanitize_field(value, max_len: int = 200):
    s = str(value)
    s = "".join(ch for ch in s if ch.isprintable())[:max_len]
    return s.replace("{", "(").replace("}", ")")


def injection_suspected(alert: dict) -> bool:
    blob = " ".join(str(v) for v in alert.get("data", {}).values()) + " " + str(alert.get("full_log", ""))
    return bool(_RX.search(blob))
