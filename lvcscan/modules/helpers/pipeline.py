from __future__ import annotations

"""Shared execution context and envelope helpers for the probe → detect → exploit flow."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


DETECTION_VERDICTS = {
    "confirmed_vulnerable",
    "sink_reachable",
    "surface_present",
    "version_applicable",
    "precondition_detected",
    "blocked_by_control",
    "not_detected",
    "not_applicable",
    "not_exploitable_refusal",
    "inconclusive",
}

CONFIRMED_DETECTION_VERDICTS = {"confirmed_vulnerable"}

DETECTION_CONTRACT_KEYS = {
    "vulnerable", "status", "severity", "category", "endpoint", "evidence",
    "mitigation", "confidence", "requires", "requires_app_key", "artifacts",
    "provides", "consumes", "version_status", "verdict", "proof_type",
    "proof", "preconditions",
}

EXPLOIT_CONTRACT_KEYS = {
    "attempted", "success", "outcome", "vuln_class", "evidence", "detail",
    "artifacts", "requires", "reason", "oob_pending", "reattributed_cve",
    "outcome_tag", "command", "requires_app_key",
}


@dataclass
class PipelineContext:
    """Runtime envelope carried through detection and exploitation stages."""

    target_url: str
    laravel_info: Dict[str, Any] = field(default_factory=dict)
    discovery: Dict[str, Any] = field(default_factory=dict)
    request_budget: Dict[str, Any] = field(default_factory=dict)
    detector_evidence: List[Dict[str, Any]] = field(default_factory=list)
    artifacts: Dict[str, Any] = field(default_factory=dict)
    violations: List[str] = field(default_factory=list)
    detections: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def __post_init__(self):
        if self.discovery and not self.discovery.get("route_map") and isinstance(self.laravel_info, dict):
            # Keep compatibility for callers that pass discovery in laravel_info.
            self.discovery.setdefault("route_map", (self.laravel_info or {}).get("route_map", {}))

    @property
    def route_map(self) -> Dict[str, Any]:
        return (self.discovery or {}).get("route_map", {})

    @property
    def debug_mode(self) -> bool:
        return bool((self.discovery or {}).get("debug_mode", False))

    def record_request_cost(self, cve: str, stage: str, before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, int]:
        """Record and return the request delta for one stage of one CVE.

        `stage` is a logical label such as "detect" or "exploit". The delta is derived
        from generic stats snapshots where available.
        """
        delta = request_delta(after, before)
        bucket = self.request_budget.setdefault(cve, {})
        bucket[stage] = delta.get("total", 0)
        bucket["__raw__"] = delta
        return bucket

    def record_detection(self, cve: str, result: Dict[str, Any]) -> None:
        self.detector_evidence.append(result)
        if cve:
            self.detections[cve] = result

    def get_detection(self, cve: str) -> Optional[Dict[str, Any]]:
        if not cve:
            return None
        return self.detections.get(cve)

    def set_artifact(self, scope: str, key: str, value: Any) -> None:
        bucket = self.artifacts.setdefault(scope, {})
        bucket[key] = value

    def get_artifact(self, scope: str, key: str = None) -> Any:
        bucket = self.artifacts.get(scope, {})
        if key is None:
            return bucket
        return bucket.get(key)


def _text_list(value: Any) -> List[str]:
    if value in (None, "", [], {}):
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def detection_verdict(result: Any, *, vuln_class: Optional[str] = None) -> str:
    """Classify detector output without collapsing fingerprints into vulnerabilities.

    `confirmed_vulnerable` is intentionally narrow: it means current-target
    behavior proves the vulnerability exists. Version matches, component
    fingerprints, APP_KEY availability, and disputed/not-exploitable rows are
    modeled as separate states so reports can be honest about proof strength.
    """
    if not result:
        return "not_detected"

    if isinstance(result, list):
        return "confirmed_vulnerable" if result else "not_detected"

    if not isinstance(result, dict):
        return "inconclusive"

    explicit = result.get("verdict")
    if isinstance(explicit, str) and explicit in DETECTION_VERDICTS:
        return explicit

    status = str(result.get("status", "") or "").lower().replace("-", "_")
    version_status = str(result.get("version_status", "") or "").lower()
    methods = [m.lower() for m in _text_list(result.get("detection_methods"))]
    proof_type = str(result.get("proof_type", "") or "").lower()

    if status in DETECTION_VERDICTS:
        return status

    if vuln_class == "not_exploitable" or result.get("disputed"):
        if result.get("vulnerable") or result.get("detected") or version_status.startswith("vulnerable"):
            return "not_exploitable_refusal"

    if status in {"not_detected", "not_vulnerable", "clean", "safe", "no_reachable_component"}:
        return "not_detected"
    if status in {"protected", "patched", "blocked", "mitigated"} or version_status.startswith("patched"):
        return "blocked_by_control"
    if status in {"error", "unreachable", "login_failed"}:
        return "inconclusive"
    if status in {"fingerprint_only", "candidate", "not_confirmed"} or result.get("candidate"):
        return "surface_present"
    if status in {"redis_scaling_subscriber"}:
        return "precondition_detected"

    if proof_type in {"behavioral", "exploit_equivalent", "safe_active", "state_change"}:
        return "confirmed_vulnerable"
    if proof_type in {"sink_reachable", "upload_handshake", "inert_upload_readback"}:
        return "sink_reachable"
    if proof_type in {"version", "dependency", "fingerprint"}:
        return "version_applicable" if proof_type in {"version", "dependency"} else "surface_present"

    if result.get("vulnerable") or result.get("exploitable") or result.get("is_vulnerable"):
        version_only = bool(methods) and all(
            ("version" in m or "composer" in m or "dependency" in m)
            for m in methods
        )
        if version_only or version_status.startswith("vulnerable"):
            return "version_applicable"
        return "confirmed_vulnerable"

    if status == "vulnerable":
        return "confirmed_vulnerable"

    detected_flags = [v for k, v in result.items() if k == "detected" or k.endswith("_detected")]
    if detected_flags and any(bool(v) for v in detected_flags):
        return "surface_present"

    if version_status.startswith("vulnerable"):
        return "version_applicable"

    return "not_detected"


def is_confirmed_detection(verdict: Any) -> bool:
    return str(verdict) in CONFIRMED_DETECTION_VERDICTS


def is_forced_execution(options: Optional[Dict[str, Any]] = None, **kwargs: Any) -> bool:
    """Return True when the operator explicitly selected forced exploit execution."""
    options = options or {}
    return bool(
        options.get("force")
        or kwargs.get("force")
        or str(options.get("exploit_policy") or "").lower() == "forced"
        or str(kwargs.get("exploit_policy") or "").lower() == "forced"
    )


def normalize_detection_result(cve: Optional[str], result: Any, *, vuln_class: Optional[str] = None) -> Dict[str, Any]:
    """Normalize detector output to a conservative, contract-like shape."""
    verdict = detection_verdict(result, vuln_class=vuln_class)

    if isinstance(result, list):
        normalized = {
            "vulnerable": is_confirmed_detection(verdict),
            "status": verdict,
            "verdict": verdict,
            "severity": "None",
            "category": "unknown",
            "endpoint": None,
            "evidence": result,
            "confidence": "medium" if result else "low",
            "requires": [],
            "requires_app_key": False,
            "artifacts": {},
            "provides": [],
            "consumes": [],
            "version_status": "unknown",
            "proof_type": None,
            "proof": None,
            "preconditions": [],
            "raw": result,
        }
        if cve:
            normalized["cve"] = cve
        return normalized

    if not isinstance(result, dict):
        return {
            "vulnerable": False,
            "status": verdict,
            "verdict": verdict,
            "severity": "None",
            "category": "unknown",
            "endpoint": None,
            "evidence": [],
            "confidence": "low",
            "requires": [],
            "requires_app_key": False,
            "artifacts": {},
            "provides": [],
            "consumes": [],
            "version_status": "unknown",
            "proof_type": None,
            "proof": None,
            "preconditions": [],
            "raw": result,
        }

    artifacts = dict(result.get("artifacts") or {})
    for key in (
        "filemanager_url",
        "livewire_update_url",
        "upload_component_url",
        "signed_upload_url",
        "filemanager_component",
    ):
        if result.get(key) and key not in artifacts:
            artifacts[key] = result[key]

    normalized = {
        "vulnerable": is_confirmed_detection(verdict),
        "status": str(result.get("status", "") or "") or verdict,
        "verdict": verdict,
        "severity": result.get("severity") or "None",
        "category": result.get("category") or "unknown",
        "endpoint": result.get("endpoint") or result.get("url") or result.get("filemanager_url")
                    or result.get("upload_component_url") or result.get("livewire_update_url"),
        "evidence": result.get("evidence", []),
        "mitigation": result.get("mitigation"),
        "confidence": result.get("confidence") or "low",
        "requires": result.get("requires") or [],
        "requires_app_key": bool(result.get("requires_app_key") or "app_key" in (result.get("requires") or [])),
        "artifacts": artifacts,
        "provides": result.get("provides") or [],
        "consumes": result.get("consumes") or [],
        "version_status": result.get("version_status") or "unknown",
        "proof_type": result.get("proof_type"),
        "proof": result.get("proof"),
        "preconditions": result.get("preconditions") or [],
        "reason": result.get("reason"),
        "note": result.get("note"),
        "detection_methods": result.get("detection_methods") or [],
    }
    if cve:
        normalized["cve"] = cve
    return normalized


def normalize_exploit_result(cve: Optional[str], result: Any) -> Dict[str, Any]:
    """Normalize exploit output to a conservative, contract-like shape."""
    if not isinstance(result, dict):
        return {
            "attempted": False,
            "success": False,
            "outcome": None,
            "vuln_class": "unknown",
            "evidence": "",
            "detail": "non-dict exploit result",
            "artifacts": {},
            "requires": [],
            "reason": f"non-dict result: {type(result).__name__}",
            "oob_pending": False,
            "reattributed_cve": None,
            "outcome_tag": None,
            "command": None,
        }

    normalized = {
        "attempted": bool(result.get("attempted", False)),
        "success": bool(result.get("success", False)),
        "outcome": result.get("outcome"),
        "vuln_class": result.get("vuln_class") or "unknown",
        "evidence": result.get("evidence", ""),
        "detail": result.get("detail") or "",
        "artifacts": result.get("artifacts") or {},
        "requires": result.get("requires") or [],
        "reason": result.get("reason") or "",
        "oob_pending": bool(result.get("oob_pending", False)),
        "reattributed_cve": result.get("reattributed_cve"),
        "outcome_tag": result.get("outcome_tag"),
        "command": result.get("command") or result.get("detail") if isinstance(result.get("command"), str) else result.get("command"),
        "provides": result.get("provides") or [],
        "consumes": result.get("consumes") or [],
    }
    if cve:
        normalized["cve"] = cve
    return normalized


def request_delta(after: Dict[str, int], before: Dict[str, int]) -> Dict[str, int]:
    """Cheap, defensive delta between two request snapshots."""
    out = {
        "total": max(0, (after.get("total") or 0) - (before.get("total") or 0)),
    }
    out["detective_total"] = out["total"]
    for stage in ("detection", "exploit", "probe"):
        if stage in after or stage in before:
            out[stage] = max(0, (after.get(stage) or 0) - (before.get(stage) or 0))
    return out
