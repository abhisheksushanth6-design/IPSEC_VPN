"""Layer 04 state machine tests. Every transition needs packet evidence."""

from __future__ import annotations

from app.layers.layer03_protocol_analysis import analyze_capture
from app.layers.layer04_sa_lifecycle import discover

from packet_builders import DST4, SRC4, ah, esp, ethernet, ikev1, ikev2, ipv4, tcp, udp
from test_session_correlation import T0, pcap_at

CAP = "cap"
RSPI = b"\x02" * 8


def run(frames):
    _, packets = analyze_capture(pcap_at(frames), max_packets=10_000)
    return discover(packets, CAP).associations


def ike(*, src=SRC4, dst=DST4, **kw):
    return ethernet(ipv4(udp(ikev2(**kw), 500, 500), proto=17, src=src, dst=dst))


def esp_frame(*, src=SRC4, dst=DST4, **kw):
    return ethernet(ipv4(esp(**kw), proto=50, src=src, dst=dst))


def sa_init_req(t): return (ike(flags=0x08, message_id=0), t)
def sa_init_resp(t): return (ike(src=DST4, dst=SRC4, flags=0x20, message_id=0, r_spi=RSPI), t)
def auth_req(t): return (ike(exchange=35, payloads=[(46, b"\x00" * 40)], flags=0x08, message_id=1, r_spi=RSPI), t)
def auth_resp(t): return (ike(src=DST4, dst=SRC4, exchange=35, payloads=[(46, b"\x00" * 40)], flags=0x20, message_id=1, r_spi=RSPI), t)
def child_req(t): return (ike(exchange=36, payloads=[(46, b"\x00" * 40)], flags=0x08, message_id=2, r_spi=RSPI), t)
def child_resp(t): return (ike(src=DST4, dst=SRC4, exchange=36, payloads=[(46, b"\x00" * 40)], flags=0x20, message_id=2, r_spi=RSPI), t)
def plaintext_delete(t): return (ike(exchange=37, payloads=[(42, b"\x00" * 8)], flags=0x08, message_id=3, r_spi=RSPI), t)


def ike_sa(sas):
    return [s for s in sas if s.type == "IKE"]


def children(sas):
    return [s for s in sas if s.type == "CHILD"]


def states(sa):
    return [st for _, st in sa.state_history]


# ----- required transitions ------------------------------------------------ #

def test_detected_to_negotiating() -> None:
    sa = ike_sa(run([sa_init_req(T0)]))[0]
    assert states(sa) == ["DETECTED", "NEGOTIATING"]
    assert sa.state == "NEGOTIATING"
    assert sa.initiator == SRC4 and sa.responder == DST4


def test_negotiating_to_established() -> None:
    sa = ike_sa(run([sa_init_req(T0), sa_init_resp(T0 + 0.1), auth_req(T0 + 0.2), auth_resp(T0 + 0.3)]))[0]
    assert states(sa) == ["DETECTED", "NEGOTIATING", "ESTABLISHED"]
    assert sa.responder_spi == "02" * 8


def test_established_to_active_on_child_traffic() -> None:
    sas = run([sa_init_req(T0), sa_init_resp(T0 + 0.1), auth_req(T0 + 0.2), auth_resp(T0 + 0.3), (esp_frame(spi=0xA1, seq=1), T0 + 1)])
    parent = ike_sa(sas)[0]
    child = children(sas)[0]
    assert parent.state == "ACTIVE" and states(parent)[-2:] == ["ESTABLISHED", "ACTIVE"]
    assert child.state == "ACTIVE" and child.parent_sa_id == parent.id and child.association == "CORRELATED"
    assert parent.child_sa_ids == [child.id]
    assert any(e.event_type == "IPSEC TRAFFIC OBSERVED" for e in parent.timeline)


def test_active_to_rekeying_to_active() -> None:
    sas = run([sa_init_req(T0), sa_init_resp(T0 + 0.1), auth_req(T0 + 0.2), auth_resp(T0 + 0.3), (esp_frame(spi=0xA1, seq=1), T0 + 1),
               child_req(T0 + 5), child_resp(T0 + 5.1), (esp_frame(spi=0xA2, seq=1), T0 + 6)])
    parent = ike_sa(sas)[0]
    assert "REKEYING" in states(parent)
    assert states(parent)[-1] == "ACTIVE"
    assert parent.rekey_count == 1
    events = [e.event_type for e in parent.timeline]
    assert "REKEY START" in events and "REKEY COMPLETE" in events
    new_child = next(c for c in children(sas) if c.spi == "0x000000a2")
    assert new_child.timeline[-1].event_type == "CREATED AFTER REKEY"


def test_active_to_terminated_on_plaintext_delete() -> None:
    sas = run([sa_init_req(T0), sa_init_resp(T0 + 0.1), auth_req(T0 + 0.2), auth_resp(T0 + 0.3), (esp_frame(spi=0xA1, seq=1), T0 + 1), plaintext_delete(T0 + 9)])
    parent = ike_sa(sas)[0]
    assert parent.state == "TERMINATED"
    assert any(e.event_type == "DELETE OBSERVED" for e in parent.timeline)
    assert not any(e.event_type == "CAPTURE ENDED" for e in parent.timeline)


def test_negotiating_to_failed_on_notify_only_response() -> None:
    frames = [sa_init_req(T0), (ike(src=DST4, dst=SRC4, payloads=[(41, b"\x00" * 8)], flags=0x20, message_id=0), T0 + 0.1)]
    sa = ike_sa(run(frames))[0]
    assert sa.state == "FAILED"
    assert sa.failure["exchange"] == "IKE_SA_INIT" and sa.failure["packet_number"] == 2
    assert states(sa) == ["DETECTED", "NEGOTIATING", "FAILED"]


def test_unknown_when_exchange_unrecognized() -> None:
    sa = ike_sa(run([(ike(exchange=99), T0)]))[0]
    assert sa.state == "DETECTED"  # detected, but nothing further can be established
    assert any(e.event_type == "UNRECOGNIZED EXCHANGE" for e in sa.timeline)


# ----- required negative cases -------------------------------------------- #

def test_capture_end_is_not_termination() -> None:
    sa = ike_sa(run([sa_init_req(T0), sa_init_resp(T0 + 0.1), auth_req(T0 + 0.2), auth_resp(T0 + 0.3)]))[0]
    assert sa.state == "ESTABLISHED"
    assert sa.capture_ended_in_state is True
    assert sa.timeline[-1].event_type == "CAPTURE ENDED"


def test_no_traffic_is_not_expired() -> None:
    sas = run([sa_init_req(T0), sa_init_resp(T0 + 0.1), auth_req(T0 + 0.2), auth_resp(T0 + 0.3)])
    assert all(s.state != "EXPIRED" for s in sas)


def test_ike_packet_is_not_established() -> None:
    assert ike_sa(run([sa_init_req(T0)]))[0].state == "NEGOTIATING"
    assert ike_sa(run([sa_init_req(T0), sa_init_resp(T0 + 0.1)]))[0].state == "NEGOTIATING"
    assert ike_sa(run([sa_init_req(T0), sa_init_resp(T0 + 0.1), auth_req(T0 + 0.2)]))[0].state == "NEGOTIATING"


def test_new_spi_alone_is_not_rekey() -> None:
    sas = run([sa_init_req(T0), sa_init_resp(T0 + 0.1), auth_req(T0 + 0.2), auth_resp(T0 + 0.3),
               (esp_frame(spi=0xA1, seq=1), T0 + 1), (esp_frame(spi=0xA2, seq=1), T0 + 2)])
    parent = ike_sa(sas)[0]
    assert parent.rekey_count == 0 and "REKEYING" not in states(parent)
    assert all(not any(e.event_type == "CREATED AFTER REKEY" for e in c.timeline) for c in children(sas))


def test_esp_without_ike_has_unknown_parent_and_no_security_claim() -> None:
    sas = run([(esp_frame(spi=0xB1, seq=1), T0), (esp_frame(spi=0xB1, seq=2), T0 + 1)])
    assert len(sas) == 1
    child = sas[0]
    assert child.type == "CHILD" and child.state == "ACTIVE"
    assert child.parent_sa_id is None and child.association == "UNKNOWN"
    text = " ".join(child.observations).lower()
    assert "secure" not in text and "vulnerab" not in text and "risk" not in text


def test_traffic_does_not_promote_a_merely_negotiating_ike_sa() -> None:
    sas = run([sa_init_req(T0), (esp_frame(spi=0xC1, seq=1), T0 + 1)])
    parent = ike_sa(sas)[0]
    assert parent.state == "NEGOTIATING"
    assert any("may belong to an earlier IKE SA" in o for o in parent.observations)


def test_encrypted_delete_is_not_seen() -> None:
    # IKEv2 INFORMATIONAL with SK: whatever is inside is invisible.
    frames = [sa_init_req(T0), sa_init_resp(T0 + 0.1), auth_req(T0 + 0.2), auth_resp(T0 + 0.3),
              (ike(exchange=37, payloads=[(46, b"\x00" * 16)], flags=0x08, message_id=2, r_spi=RSPI), T0 + 5)]
    sa = ike_sa(run(frames))[0]
    assert sa.state == "ESTABLISHED"
    assert any(e.event_type == "INFORMATIONAL" for e in sa.timeline)


# ----- identity, IKEv1, AH, exclusions ------------------------------------- #

def test_sa_ids_stable_and_distinct() -> None:
    frames = [sa_init_req(T0), (esp_frame(spi=0xA1), T0 + 1), (esp_frame(spi=0xA2), T0 + 2)]
    a, b = run(frames), run(frames)
    assert [s.id for s in a] == [s.id for s in b]
    assert len({s.id for s in a}) == 3 and all(s.id.startswith("SA-") for s in a)


def test_ikev1_main_mode_then_quick_modes() -> None:
    v1 = lambda ex, **kw: (ethernet(ipv4(udp(ikev1(exchange=ex, **kw), 500, 500), proto=17)), kw.pop("t", T0))  # noqa: E731
    frames = [
        (ethernet(ipv4(udp(ikev1(exchange=2), 500, 500), proto=17)), T0),
        (ethernet(ipv4(udp(ikev1(exchange=32, payloads=[(8, b"\x00" * 16)]), 500, 500), proto=17)), T0 + 1),
        (ethernet(ipv4(udp(ikev1(exchange=32, payloads=[(8, b"\x00" * 16)]), 500, 500), proto=17)), T0 + 50),
    ]
    sa = ike_sa(run(frames))[0]
    assert sa.ike_version == "1.0"
    assert "ESTABLISHED" in states(sa) and sa.rekey_count == 1
    assert sa.state == "ESTABLISHED"


def test_ah_child_sa() -> None:
    sas = run([(ethernet(ipv4(ah(spi=0x77, seq=5), proto=51)), T0)])
    assert sas[0].protocol == "AH" and sas[0].spi == "0x00000077" and sas[0].state == "ACTIVE"


def test_non_ipsec_packets_yield_nothing() -> None:
    assert run([(ethernet(ipv4(tcp(), proto=6)), T0)]) == []


def test_history_is_append_only_and_timeline_cites_packets() -> None:
    sas = run([sa_init_req(T0), sa_init_resp(T0 + 0.1), auth_req(T0 + 0.2), auth_resp(T0 + 0.3), plaintext_delete(T0 + 2)])
    sa = ike_sa(sas)[0]
    assert states(sa) == ["DETECTED", "NEGOTIATING", "ESTABLISHED", "TERMINATED"]
    transitions = [e for e in sa.timeline if e.previous_state != e.new_state]
    assert all(e.packet_number is not None for e in transitions)
    assert [e.new_state for e in transitions] == ["DETECTED", "NEGOTIATING", "ESTABLISHED", "TERMINATED"]


def test_security_parameters_not_claimed() -> None:
    sa = ike_sa(run([sa_init_req(T0)]))[0]
    assert sa.security_parameters_available is False and sa.traffic_selectors_available is False
