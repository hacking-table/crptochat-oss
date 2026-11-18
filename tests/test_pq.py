"""Post-quantum layer: ML-KEM-768 mixed with X25519 in the Double Ratchet and the mailbox."""

import copy
import json
import os

import pytest
from test_e2e import Harness, messages, run, until
from test_mailbox import back, leave, mail_rows, published

from crptochat import crypto
from crptochat.client import ChatError
from crptochat.protocol import b64d

pytestmark = pytest.mark.skipif(not crypto.HAS_MLKEM, reason="cryptography sem ML-KEM (precisa da 47+)")

AD = crypto.dm_v3_aad("alice", "bob")
DA = crypto.dm_v3_aad("bob", "alice")


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("CRPTOCHAT_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr(crypto, "SCRYPT_N", 2 ** 10)
    return tmp_path


def pq_pair():
    ia, ib = os.urandom(32), os.urandom(32)
    da, db = crypto.x_generate(), crypto.x_generate()
    ka, kb = crypto.kem_generate(), crypto.kem_generate()
    root = crypto.pair_key(da, crypto.x_pub(db), ia, ib)
    alice = crypto.DoubleRatchet(root, ia, ib, da, crypto.x_pub(db), ka, crypto.kem_pub(kb))
    bob = crypto.DoubleRatchet(root, ib, ia, db, crypto.x_pub(da), kb, crypto.kem_pub(ka))
    return alice, bob


def test_the_first_step_mixes_ml_kem_and_the_chain_carries_the_ciphertext():
    alice, bob = pq_pair()
    if alice.send_ct is None:                       # whoever plays Alice already mixed at the start
        alice, bob = bob, alice
    first, second = alice.encrypt(b"um", AD), alice.encrypt(b"dois", AD)
    assert first[0] == second[0] == crypto.DM_V3_PQ
    assert first[41:41 + crypto.KEM_CT] == second[41:41 + crypto.KEM_CT]     # same ciphertext on the chain
    assert bob.decrypt(second, AD) == b"dois"                                # either one may arrive first
    assert bob.decrypt(first, AD) == b"um"
    assert alice.pq and bob.pq
    answer = bob.encrypt(b"tres", DA)                # bob mixes once too, on his first step
    assert answer[0] == crypto.DM_V3_PQ and alice.decrypt(answer, DA) == b"tres"
    later = alice.encrypt(b"quatro", AD)            # both done: plain v3 from now on
    assert later[0] == crypto.DM_V3 and bob.decrypt(later, AD) == b"quatro"


def test_every_x25519_secret_is_not_enough():
    """Harvest now, decrypt later: someone who will break X25519 (all of bob's
    classical secrets) but not ML-KEM does not open what came after the mix."""
    alice, bob = pq_pair()
    if alice.send_ct is None:
        alice, bob = bob, alice
    body = alice.encrypt(b"segredo de longo prazo", AD)
    quantum = object.__new__(crypto.DoubleRatchet)
    quantum.__dict__.update(copy.copy(bob.__dict__))
    quantum.my_kem = crypto.kem_generate()            # every classical secret, the wrong ML-KEM key
    with pytest.raises(crypto.CryptoError):
        quantum.decrypt(body, AD)
    assert bob.decrypt(body, AD) == b"segredo de longo prazo"


def test_tampering_with_the_kem_ciphertext_is_refused():
    alice, bob = pq_pair()
    if alice.send_ct is None:
        alice, bob = bob, alice
    body = bytearray(alice.encrypt(b"x", AD))
    body[50] ^= 1
    before = dict(bob.__dict__)
    with pytest.raises(crypto.CryptoError):
        bob.decrypt(bytes(body), AD)
    assert bob.__dict__ == before
    plain = bytearray(alice.encrypt(b"y", AD))
    plain[0] = crypto.DM_V3                         # stripping the PQ type does not pass either
    with pytest.raises(crypto.CryptoError):
        bob.decrypt(bytes(plain), AD)


def direct_kinds(h, to):
    out = []
    for frame in h.wire:
        msg = json.loads(frame)
        if msg.get("t") == "direct" and msg.get("to", "").lower() == to:
            out.append(b64d(msg["body"])[0])
    return out


def test_clients_mix_ml_kem_into_their_ratchet(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await alice.send_dm("bob", "primeira")
            await until(lambda: messages(bob, "@alice"))
            for i in range(2):
                await bob.send_dm("alice", f"resposta {i}")
                await until(lambda: len(messages(alice, "@bob")) == i + 1)
                await alice.send_dm("bob", f"de novo {i}")
                await until(lambda: len(messages(bob, "@alice")) == i + 2)
            assert alice.peers["bob"]._cur["dr"].pq and bob.peers["alice"]._cur["dr"].pq
            assert crypto.DM_V3_PQ in direct_kinds(h, "bob") + direct_kinds(h, "alice")
            # once both sides have mixed, neither the 1.2 KB key nor the 1.1 KB ciphertext goes along
            await bob.send_dm("alice", "mais uma vez")
            await until(lambda: len(messages(alice, "@bob")) == 3)
            await alice.send_dm("bob", "leve")
            last = [json.loads(f) for f in h.wire if '"direct"' in f][-1]
            assert len(last["body"]) < 1000
    run(main())


def test_a_contact_without_the_layer_still_talks(home):
    async def main():
        async with Harness(home) as h:
            alice, older = await h.client("alice"), await h.client("antigo")
            older.caps = [c for c in older.caps if c != "pq"]               # like 1.12
            older._kem = None
            await alice.send_dm("antigo", "oi")
            await until(lambda: messages(older, "@alice"))
            for i in range(2):
                await older.send_dm("alice", f"r{i}")
                await until(lambda: len(messages(alice, "@antigo")) == i + 1)
                await alice.send_dm("antigo", f"a{i}")
                await until(lambda: len(messages(older, "@alice")) == i + 2)
            assert set(direct_kinds(h, "antigo")[1:] + direct_kinds(h, "alice")) == {crypto.DM_V3}
            assert not alice.peers["antigo"]._cur["dr"].pq
    run(main())


def test_mailbox_uses_the_ml_kem_prekey_and_refuses_a_downgrade(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await published(h, bob)
            row = h.server.db.execute("SELECT kem, kem_sig FROM prekeys WHERE nick_lower='bob'").fetchone()
            assert len(row[0]) == crypto.KEM_PUB and len(row[1]) == 64
            await alice.resolve("bob")
            await leave(h, bob)
            await alice.send_dm("bob", "selada também com ML-KEM")
            body = bytes(mail_rows(h, "bob")[0][1])
            assert body[0] == crypto.MAIL_PQ and len(body) > crypto.KEM_CT
            assert alice.store.uses_pq("bob")

            # the server strips the post-quantum prekey: alice refuses to fall back
            h.server.db.execute("UPDATE prekeys SET kem=NULL, kem_sig=NULL WHERE nick_lower='bob'")
            h.server.db.commit()
            alice.mail.out.clear()
            with pytest.raises(ChatError) as err:
                await alice.send_dm("bob", "não sai sem ML-KEM")
            assert err.value.code == "untrusted"
            assert len(mail_rows(h, "bob")) == 1

            bob2 = await back(h, "bob")
            await until(lambda: messages(bob2, "@alice"))
            assert messages(bob2, "@alice") == [("alice", "selada também com ML-KEM")]
            # and bob, back online, publishes his ML-KEM prekey again
            await until(lambda: h.server.db.execute(
                "SELECT kem IS NOT NULL FROM prekeys WHERE nick_lower='bob'").fetchone()[0] == 1)
    run(main())
