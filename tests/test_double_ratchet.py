"""Double Ratchet for direct messages (v3): a new DH key at every change of turn."""

import copy
import json
import os

import pytest
from test_e2e import Harness, messages, run, until

from crptochat import client as client_mod
from crptochat import crypto
from crptochat.protocol import b64d, b64e

AD = crypto.dm_v3_aad("alice", "bob")
DA = crypto.dm_v3_aad("bob", "alice")


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("CRPTOCHAT_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr(crypto, "SCRYPT_N", 2 ** 10)
    return tmp_path


def pair():
    ia, ib = os.urandom(32), os.urandom(32)
    da, db = crypto.x_generate(), crypto.x_generate()
    root = crypto.pair_key(da, crypto.x_pub(db), ia, ib)
    assert root == crypto.pair_key(db, crypto.x_pub(da), ia, ib)
    return (crypto.DoubleRatchet(root, ia, ib, da, crypto.x_pub(db)),
            crypto.DoubleRatchet(root, ib, ia, db, crypto.x_pub(da)))


def header(body):
    return body[1:33], int.from_bytes(body[33:37], "big"), int.from_bytes(body[37:41], "big")


def test_either_side_may_speak_first_and_keys_turn_over():
    for first in ("alice", "bob"):
        alice, bob = pair()
        if first == "bob":
            assert alice.decrypt(bob.encrypt(b"oi", DA), DA) == b"oi"
        keys = set()
        for i in range(4):          # a conversation that changes turn every message
            m = alice.encrypt(f"a{i}".encode(), AD)
            keys.add(header(m)[0])
            assert bob.decrypt(m, AD) == f"a{i}".encode()
            m = bob.encrypt(f"b{i}".encode(), DA)
            keys.add(header(m)[0])
            assert alice.decrypt(m, DA) == f"b{i}".encode()
        assert len(keys) == 8                                   # one fresh DH key per turn


def test_out_of_order_across_turns_and_no_replay():
    alice, bob = pair()
    a1, a2, a3 = (alice.encrypt(t, AD) for t in (b"a1", b"a2", b"a3"))
    assert bob.decrypt(a3, AD) == b"a3"                         # a1 and a2 still in flight
    b1 = bob.encrypt(b"b1", DA)
    assert alice.decrypt(b1, DA) == b"b1"
    a4 = alice.encrypt(b"a4", AD)                               # alice changed turn: new key
    assert header(a4)[0] != header(a1)[0] and header(a4)[1] == 3   # pn: 3 sent on the last chain
    assert bob.decrypt(a4, AD) == b"a4"
    assert bob.decrypt(a1, AD) == b"a1"                         # late ones still open...
    assert bob.decrypt(a2, AD) == b"a2"
    for old in (a1, a2, a3, a4):                                # ...but exactly once
        with pytest.raises(crypto.CryptoError):
            bob.decrypt(old, AD)


def test_failures_leave_the_state_untouched():
    alice, bob = pair()
    good = alice.encrypt(b"ok", AD)
    before = copy.copy(bob.__dict__)
    bad = bytearray(good)
    bad[-1] ^= 1
    for body in (bytes(bad), good[:20], b"\x02" + good[1:]):
        with pytest.raises(crypto.CryptoError):
            bob.decrypt(body, AD)
    with pytest.raises(crypto.CryptoError):
        bob.decrypt(good, DA)                                   # bound to who sends to whom
    forged = bytearray(good)
    forged[1:33] = crypto.x_pub(crypto.x_generate())            # a header the sender never wrote
    with pytest.raises(crypto.CryptoError):
        bob.decrypt(bytes(forged), AD)
    assert bob.__dict__ == before
    assert bob.decrypt(good, AD) == b"ok"


def test_gaps_are_bounded():
    alice, bob = pair()
    for _ in range(crypto.MAX_CHAIN_SKIP + 1):
        alice.encrypt(b"x", AD)
    with pytest.raises(crypto.CryptoError):
        bob.decrypt(alice.encrypt(b"longe demais", AD), AD)


def test_stolen_state_heals_after_a_round_trip():
    """Post-compromise security: an attacker copies bob's whole state and keeps
    following the conversation (sees every envelope on the server). It reads
    until bob makes a DH key it never saw and alice answers to that key."""
    alice, bob = pair()
    bob.decrypt(alice.encrypt(b"antes", AD), AD)
    thief = object.__new__(crypto.DoubleRatchet)
    thief.__dict__.update(copy.deepcopy(bob.__dict__))          # the attacker copies everything

    def relay(sender, receiver, text, ad):
        body = sender.encrypt(text, ad)
        assert receiver.decrypt(body, ad) == text
        return body

    # still exposed: keys that existed when the state leaked
    assert thief.decrypt(relay(alice, bob, b"exposta 1", AD), AD) == b"exposta 1"
    relay(bob, alice, b"bob ainda na chave vazada", DA)
    exposed = relay(alice, bob, b"exposta 2", AD)               # alice answers to the leaked key
    assert thief.decrypt(exposed, AD) == b"exposta 2"
    # bob turns over with a key made after the leak; alice answers to it
    relay(bob, alice, b"chave nova do bob", DA)
    healed = relay(alice, bob, b"depois da cura", AD)
    with pytest.raises(crypto.CryptoError):
        thief.decrypt(healed, AD)


def test_keys_already_used_are_gone():
    alice, bob = pair()
    sent = [alice.encrypt(f"m{i}".encode(), AD) for i in range(3)]
    for m in sent:
        bob.decrypt(m, AD)
    bob.decrypt(alice.encrypt(b"x", AD), AD)
    clone = object.__new__(crypto.DoubleRatchet)
    clone.__dict__.update(copy.deepcopy(bob.__dict__))
    for m in sent:
        with pytest.raises(crypto.CryptoError):
            clone.decrypt(m, AD)
    assert not clone.skipped


def v3_bodies(h, to):
    out = []
    for frame in h.wire:
        msg = json.loads(frame)
        if msg.get("t") == "direct" and msg.get("to", "").lower() == to:
            body = b64d(msg["body"])
            if body[:1] == b"\x03":
                out.append(body)
    return out


def test_clients_move_to_the_double_ratchet(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await alice.send_dm("bob", "primeira")                     # v1, advertising "dr"
            await until(lambda: messages(bob, "@alice"))
            for i in range(3):
                await bob.send_dm("alice", f"b{i}")
                await until(lambda: len(messages(alice, "@bob")) == i + 1)
                await alice.send_dm("bob", f"a{i}")
                await until(lambda: len(messages(bob, "@alice")) == i + 2)
            assert messages(bob, "@alice") == [("alice", "primeira"), ("alice", "a0"), ("alice", "a1"), ("alice", "a2")]
            to_bob, to_alice = v3_bodies(h, "bob"), v3_bodies(h, "alice")
            assert len(to_bob) == 3 and len(to_alice) == 3             # everything after the first is v3
            assert len({header(b)[0] for b in to_bob + to_alice}) >= 5  # the keys keep turning over
            assert not any("primeira" in f for f in h.wire)
    run(main())


def test_v2_only_contacts_keep_v2(home, monkeypatch):
    async def main():
        async with Harness(home) as h:
            new = await h.client("novo")
            older = await h.client("antigo")
            older.caps = [c for c in client_mod.CLIENT_CAPS if c != "dr"]      # a 1.10 client
            await new.send_dm("antigo", "oi")
            await until(lambda: messages(older, "@novo"))
            await older.send_dm("novo", "oi de volta")
            await until(lambda: messages(new, "@antigo"))
            await new.send_dm("antigo", "segue em v2?")
            await until(lambda: len(messages(older, "@novo")) == 2)
            assert v3_bodies(h, "antigo") == [] and v3_bodies(h, "novo") == []
            assert new.peers["antigo"].dmr
    run(main())


def test_a_restored_session_key_continues_the_ratchet(home):
    """The server swaps the contact's session key and restores it: the ratchet
    of that pair of sessions continues, it never restarts (no key reuse)."""
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await alice.send_dm("bob", "abre")
            await until(lambda: messages(bob, "@alice"))
            await bob.send_dm("alice", "ok")
            await until(lambda: messages(alice, "@bob"))
            await alice.send_dm("bob", "um")
            await until(lambda: len(messages(bob, "@alice")) == 2)
            real = h.server.sessions["bob"].public()
            other = crypto.x_pub(crypto.x_generate())
            forged = {**real, "dh": b64e(other),
                      "dh_sig": b64e(crypto.sign(bob.identity.key, crypto.dh_message("bob", other)))}
            alice._learn(forged)
            alice._learn(real)
            await alice.send_dm("bob", "dois")
            await until(lambda: ("alice", "dois") in messages(bob, "@alice"))
            seen = [(header(b)[0], header(b)[2]) for b in v3_bodies(h, "bob")]
            assert len(seen) == len(set(seen)) == 2                    # no (key, index) used twice
    run(main())
