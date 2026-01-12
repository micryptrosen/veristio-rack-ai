from __future__ import annotations

import pytest

from ultrarack_ai.engine import UltraAIEngine, EvidenceSink
from ultrarack_evidence.ledger import EvidenceLedger

from ultrarack_core.core_types import ActorIdentity, ComplianceMode, ComplianceProfile


def test_phase10a_deterministic_input_and_output_digests():
    led = EvidenceLedger("ULTRARACK-LEDGER-DEV")
    led.append("nox_observation", {"snapshot_digest": "abc"}, ts="2026-01-12T00:00:00.000Z")

    engine = UltraAIEngine()
    actor = ActorIdentity(actor_id="ops-user-01", actor_type="human")
    profile = ComplianceProfile(mode=ComplianceMode.GOVERNMENT, locked=True)

    ts = "2026-01-12T00:00:00.000Z"
    r1 = engine.recommend(led.entries(), ts=ts, compliance_profile=profile, actor_identity=actor)
    r2 = engine.recommend(led.entries(), ts=ts, compliance_profile=profile, actor_identity=actor)

    assert r1.input_digest == r2.input_digest
    assert r1.output_digest == r2.output_digest
    assert r1.rec_id == r2.rec_id
    assert r1.source == "ULTRARACK-AI"
    assert r1.policy_version.startswith("10A-")


def test_phase10a_requires_actor_identity_ugos_no_anonymous_actions():
    engine = UltraAIEngine()
    profile = ComplianceProfile(mode=ComplianceMode.COMMERCIAL, locked=True)
    with pytest.raises(ValueError):
        engine.recommend([], ts="2026-01-12T00:00:00.000Z", compliance_profile=profile, actor_identity=None)


def test_phase10a_engine_does_not_open_sockets(monkeypatch):
    import socket as _socket

    def _boom(*args, **kwargs):
        raise AssertionError("Active network operation attempted (socket usage).")

    monkeypatch.setattr(_socket, "socket", _boom, raising=True)

    engine = UltraAIEngine()
    actor = ActorIdentity(actor_id="ops-user-01", actor_type="human")
    profile = ComplianceProfile(mode=ComplianceMode.REGULATED, locked=True)

    engine.recommend([], ts="2026-01-12T00:00:00.000Z", compliance_profile=profile, actor_identity=actor)


def test_phase10a_appends_ai_recommendation_to_evidence_ledger_and_chain_validates():
    led = EvidenceLedger("ULTRARACK-LEDGER-DEV")
    led.append("signal_intake", {"event_digest": "def"}, ts="2026-01-12T00:00:00.000Z")

    engine = UltraAIEngine()
    actor = ActorIdentity(actor_id="ops-user-01", actor_type="human")
    profile = ComplianceProfile(mode=ComplianceMode.GOVERNMENT, locked=True)

    ts = "2026-01-12T00:00:00.000Z"
    rec = engine.recommend(led.entries(), ts=ts, compliance_profile=profile, actor_identity=actor)

    sink = EvidenceSink(led)
    sink.append_ai_recommendation(rec)

    assert len(led) == 2
    assert led.entries()[-1].kind == "ai_recommendation"

    led.validate_chain()
