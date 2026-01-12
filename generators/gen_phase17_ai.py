from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(r"C:\Dev\Genesis\Projects\UltraRack\ultrarack-ai")


def _utc_now_iso() -> str:
    dt = datetime.now(timezone.utc)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def stable_digest(obj: Any) -> str:
    return _sha256_hex(_canonical_json(obj))


@dataclass(frozen=True)
class AiRecommendation:
    """
    Passive AI recommendation artifact (rule-based in Phase 17).

    Inputs are PROVIDED (no I/O / no collection):
      - signal/control/nox summaries (dicts)
      - ts (string)
      - source (string)

    Determinism:
      - decision_digest stable for identical inputs (including ts)
      - decision_id is first 24 hex of digest
    """
    decision_id: str
    ts: str
    source: str
    recommended_actions: List[str]
    confidence: float
    reasons: List[str]
    decision_digest: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "ts": self.ts,
            "source": self.source,
            "recommended_actions": self.recommended_actions,
            "confidence": self.confidence,
            "reasons": self.reasons,
            "decision_digest": self.decision_digest,
        }


class AiAdvisor:
    """
    Phase 17: deterministic, passive advisor (no sockets, no external calls).
    Rules are intentionally simple + inspectable.
    """
    def __init__(self, source: str) -> None:
        if not isinstance(source, str) or len(source.strip()) < 2:
            raise ValueError("source must be >= 2 chars")
        self._source = source.strip()

    @property
    def source(self) -> str:
        return self._source

    def advise(
        self,
        *,
        signal: Dict[str, Any],
        control: Dict[str, Any],
        nox: Dict[str, Any],
        ts: Optional[str] = None,
    ) -> AiRecommendation:
        if not isinstance(signal, dict):
            raise ValueError("signal must be a dict")
        if not isinstance(control, dict):
            raise ValueError("control must be a dict")
        if not isinstance(nox, dict):
            raise ValueError("nox must be a dict")

        ts_final = ts or _utc_now_iso()

        actions: List[str] = []
        reasons: List[str] = []

        # --- Minimal deterministic rules (Phase 17)
        sev = signal.get("sev")
        sig = signal.get("sig") or signal.get("msg") or "unknown"

        nox_status = nox.get("status") or "unknown"
        ctrl_priority = control.get("priority") or "unknown"
        ctrl_status = control.get("status") or "unknown"

        if isinstance(sev, (int, float)) and float(sev) >= 7:
            actions.append("isolate_affected_interface")
            actions.append("open_incident_bridge")
            reasons.append(f"high_severity_signal(sev={sev})")

        if isinstance(nox_status, str) and nox_status.lower() in {"degraded", "down"}:
            actions.append("collect_additional_diagnostics_provided_only")
            reasons.append(f"nox_status={nox_status}")

        if isinstance(ctrl_priority, str) and ctrl_priority.upper() in {"P0", "P1"}:
            actions.append("page_oncall")
            reasons.append(f"control_priority={ctrl_priority}")

        if isinstance(ctrl_status, str) and ctrl_status.lower() == "open":
            actions.append("ensure_ticket_owner_assigned")
            reasons.append("control_status=open")

        if not actions:
            actions.append("monitor_only")
            reasons.append("no_trigger_rules_matched")

        # Confidence heuristic: bounded and deterministic
        confidence = min(0.95, 0.40 + (0.15 * max(0, len(actions) - 1)))

        material = {
            "ts": ts_final,
            "source": self._source,
            "signal": signal,
            "control": control,
            "nox": nox,
            "recommended_actions": actions,
            "confidence": confidence,
            "reasons": reasons,
        }
        digest = stable_digest(material)
        did = digest[:24]

        return AiRecommendation(
            decision_id=did,
            ts=ts_final,
            source=self._source,
            recommended_actions=actions,
            confidence=float(confidence),
            reasons=reasons,
            decision_digest=digest,
        )


class EvidenceSink:
    """
    Adapter: append AI recommendations into the UltraRack evidence ledger.
    Requires ultrarack-evidence installed in the environment.
    """
    def __init__(self, ledger: Any) -> None:
        self._ledger = ledger

    def append_recommendation(self, rec: AiRecommendation) -> Any:
        return self._ledger.append("ai_recommendation_intake", rec.to_dict(), ts=rec.ts)


def write_repo_files() -> None:
    pkg_dir = REPO_ROOT / "src" / "ultrarack_ai"
    pkg_dir.mkdir(parents=True, exist_ok=True)

    # Write new Phase-17 module file
    (pkg_dir / "advisor.py").write_text(
        (REPO_ROOT / "generators" / "gen_phase17_ai.py").read_text(encoding="utf-8").split(
            "def write_repo_files()", 1
        )[0] + "\n",
        encoding="utf-8",
    )

    tests_dir = REPO_ROOT / "tests"
    tests_dir.mkdir(parents=True, exist_ok=True)

    (tests_dir / "test_phase17_ai_advisor.py").write_text(
        r'''from __future__ import annotations

import socket as _socket

import pytest

from ultrarack_ai.advisor import AiAdvisor, EvidenceSink
from ultrarack_evidence.ledger import EvidenceLedger


def test_phase17_ai_is_deterministic_and_emits_decision_id():
    adv = AiAdvisor("ULTRARACK-AI")
    ts = "2026-01-12T00:00:00.000Z"

    signal = {"sig": "ET MALWARE", "sev": 7}
    control = {"priority": "P2", "status": "open"}
    nox = {"status": "degraded"}

    r1 = adv.advise(signal=signal, control=control, nox=nox, ts=ts)
    r2 = adv.advise(signal=signal, control=control, nox=nox, ts=ts)

    assert r1.decision_digest == r2.decision_digest
    assert r1.decision_id == r2.decision_id
    assert len(r1.decision_id) == 24
    assert r1.source == "ULTRARACK-AI"
    assert r1.ts == ts


def test_phase17_ai_appends_to_evidence_ledger_and_chain_validates():
    led = EvidenceLedger("ULTRARACK-LEDGER-DEV")
    adv = AiAdvisor("ULTRARACK-AI")
    sink = EvidenceSink(led)

    ts = "2026-01-12T00:00:00.000Z"
    rec = adv.advise(
        signal={"sig": "ET MALWARE", "sev": 7},
        control={"priority": "P2", "status": "open"},
        nox={"status": "degraded"},
        ts=ts,
    )
    sink.append_recommendation(rec)

    assert len(led) == 1
    entry = led.entries()[0]
    assert entry.kind == "ai_recommendation_intake"
    led.validate_chain()


def test_phase17_ai_does_not_open_sockets(monkeypatch):
    def _boom(*args, **kwargs):
        raise AssertionError("Active network operation attempted (socket usage).")

    monkeypatch.setattr(_socket, "socket", _boom, raising=True)

    adv = AiAdvisor("ULTRARACK-AI")
    adv.advise(
        signal={"msg": "provided"},
        control={"status": "open"},
        nox={"status": "ok"},
        ts="2026-01-12T00:00:00.000Z",
    )
''',
        encoding="utf-8",
    )


if __name__ == "__main__":
    write_repo_files()
    print("Phase 17 UltraRack-AI files written (additive).")
