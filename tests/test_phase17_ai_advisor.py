from __future__ import annotations

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
