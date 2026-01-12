from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

REPO_ROOT = Path(r"C:\Dev\Genesis\Projects\UltraRack\ultrarack-ai")


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def stable_digest(obj: Any) -> str:
    return sha256_hex(canonical_json(obj))


@dataclass(frozen=True)
class AIRecommendation:
    """
    Recommendation-only output (UGOS-safe).
    Never performs actions. Never opens sockets.
    """
    rec_id: str
    ts: str
    source: str
    compliance_mode: str
    actor_fingerprint: str
    input_digest: str
    output_digest: str
    policy_version: str
    recommendation: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rec_id": self.rec_id,
            "ts": self.ts,
            "source": self.source,
            "compliance_mode": self.compliance_mode,
            "actor_fingerprint": self.actor_fingerprint,
            "input_digest": self.input_digest,
            "output_digest": self.output_digest,
            "policy_version": self.policy_version,
            "recommendation": self.recommendation,
        }


def _get_entry_kind_and_payload(entry: Any) -> Tuple[str, Dict[str, Any]]:
    # Support both dict-like entries and dataclass/object entries.
    if isinstance(entry, dict):
        kind = entry.get("kind") or entry.get("event_kind") or entry.get("type") or "unknown"
        payload = entry.get("payload") or entry.get("data") or {}
        if not isinstance(payload, dict):
            payload = {"payload": payload}
        return str(kind), payload

    kind = getattr(entry, "kind", None) or getattr(entry, "event_kind", None) or getattr(entry, "type", None) or "unknown"
    payload = getattr(entry, "payload", None) or getattr(entry, "data", None) or {}
    if not isinstance(payload, dict):
        payload = {"payload": payload}
    return str(kind), payload


class UltraAIEngine:
    """
    Phase 10A: Policy-bound AI engine skeleton.

    Inputs:
      - evidence entries (already collected by NOx/Signal/Control etc.)
      - compliance profile (from ultrarack-core)
      - actor identity (UGOS: no anonymous actions)

    Outputs:
      - recommendation-only AIRecommendation
      - can be appended to EvidenceLedger (append-only)
    """

    POLICY_VERSION = "10A-0.1"
    SOURCE = "ULTRARACK-AI"

    def __init__(self) -> None:
        pass

    def recommend(
        self,
        evidence_entries: Iterable[Any],
        *,
        ts: str,
        compliance_profile: Any,
        actor_identity: Any,
    ) -> AIRecommendation:
        # UGOS: no anonymous actions.
        if actor_identity is None:
            raise ValueError("actor_identity is required (UGOS: no anonymous actions)")

        # Extract stable compliance mode string
        mode_val = getattr(compliance_profile, "mode", None)
        if mode_val is None:
            raise ValueError("compliance_profile.mode is required")
        compliance_mode = getattr(mode_val, "value", None) or str(mode_val)

        # Actor fingerprint (stable)
        if hasattr(actor_identity, "stable_fingerprint"):
            actor_fp = actor_identity.stable_fingerprint()
        elif isinstance(actor_identity, dict):
            actor_fp = stable_digest(actor_identity)
        else:
            actor_fp = stable_digest({"actor": str(actor_identity)})

        # Normalize evidence (stable)
        normalized: List[Dict[str, Any]] = []
        for e in evidence_entries:
            kind, payload = _get_entry_kind_and_payload(e)
            normalized.append({"kind": kind, "payload": payload})

        input_material = {
            "ts": ts,
            "source": self.SOURCE,
            "policy_version": self.POLICY_VERSION,
            "compliance_mode": compliance_mode,
            "actor_fingerprint": actor_fp,
            "evidence": normalized,
        }
        input_digest = stable_digest(input_material)

        # Deterministic, recommendation-only policy rules (no I/O)
        rec = self._policy_rules(normalized, compliance_mode=compliance_mode)

        output_material = {
            "policy_version": self.POLICY_VERSION,
            "compliance_mode": compliance_mode,
            "recommendation": rec,
        }
        output_digest = stable_digest(output_material)

        rec_id = output_digest[:24]
        return AIRecommendation(
            rec_id=rec_id,
            ts=ts,
            source=self.SOURCE,
            compliance_mode=compliance_mode,
            actor_fingerprint=actor_fp,
            input_digest=input_digest,
            output_digest=output_digest,
            policy_version=self.POLICY_VERSION,
            recommendation=rec,
        )

    def _policy_rules(self, normalized: List[Dict[str, Any]], *, compliance_mode: str) -> Dict[str, Any]:
        """
        Pure deterministic ruleset. This is NOT an LLM.
        Goal: produce an auditable, stable recommendation envelope.
        """
        kinds = [x.get("kind", "unknown") for x in normalized]

        # "Best thing first" doctrine: safe-to-say-yes, provable, contained.
        actions: List[Dict[str, Any]] = []

        if "nox_observation" in kinds:
            actions.append(
                {
                    "type": "recommendation",
                    "id": "R-NOX-REVIEW-01",
                    "severity": "info",
                    "title": "Review passive NOx observations",
                    "detail": "Validate baseline drift and confirm observed deltas are expected. No active probing.",
                    "mode": "recommendation_only",
                }
            )

        if "signal_intake" in kinds:
            actions.append(
                {
                    "type": "recommendation",
                    "id": "R-SIGNAL-CORRELATE-01",
                    "severity": "info",
                    "title": "Correlate incoming signals with evidence chain",
                    "detail": "Group by source and event_digest; look for repeated patterns. No active network operations.",
                    "mode": "recommendation_only",
                }
            )

        if "control_change" in kinds or "change_request" in kinds:
            actions.append(
                {
                    "type": "recommendation",
                    "id": "R-CONTROL-VERIFY-01",
                    "severity": "medium",
                    "title": "Verify change request evidence completeness",
                    "detail": "Ensure actor identity, approvals, and rollback plan are present before execution.",
                    "mode": "recommendation_only",
                }
            )

        # Compliance tightening
        if compliance_mode in {"regulated", "government"}:
            actions.append(
                {
                    "type": "recommendation",
                    "id": "R-UGOS-ATTEST-01",
                    "severity": "medium",
                    "title": "Require explicit attestations for any privileged operation",
                    "detail": "Maintain disclosure + audit trail. Keep authority-sensitive capabilities disabled by default.",
                    "mode": "recommendation_only",
                }
            )

        if not actions:
            actions.append(
                {
                    "type": "recommendation",
                    "id": "R-NOOP-01",
                    "severity": "info",
                    "title": "No actionable recommendation",
                    "detail": "No relevant evidence kinds supplied. Continue passive collection and evidence chaining.",
                    "mode": "recommendation_only",
                }
            )

        return {
            "summary": "UltraAI policy-bound recommendation (no actions performed).",
            "compliance_mode": compliance_mode,
            "actions": actions,
        }


class EvidenceSink:
    """
    Adapter: append AI recommendations into the UltraRack evidence ledger.

    Requires ultrarack-evidence installed in the environment.
    """
    def __init__(self, ledger: Any) -> None:
        self._ledger = ledger

    def append_ai_recommendation(self, rec: AIRecommendation) -> Any:
        payload = rec.to_dict()
        return self._ledger.append("ai_recommendation", payload, ts=rec.ts)



