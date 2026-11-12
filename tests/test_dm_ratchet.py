"""Etapa 4: forward secrecy for direct messages (per-direction ratchet, negotiated per contact)."""

import asyncio
import json

import pytest
from test_e2e import Harness, messages, run, until

from crptochat import crypto
from crptochat.client import ChatClient
from crptochat.protocol import b64d


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("CRPTOCHAT_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr(crypto, "SCRYPT_N", 2 ** 10)
    return tmp_path


def bodies(h, sender_nick, to):
    """Direct envelopes relayed from sender to recipient, as the server saw them."""
    out = []
    for frame in h.wire:
        msg = json.loads(frame)
        if msg.get("t") == "direct" and msg.get("to", "").lower() == to:
            out.append(b64d(msg["body"]))
    return out


class OldClient(ChatClient):
    """Behaves like the 1.0.0 client: v1 envelopes only, no capability advertised."""

    def _direct_frame(self, peer, inner):
        from crptochat.protocol import b64e
        aad = b"crptochat-direct-v1|" + self.key.encode() + b"|" + peer.key.encode()
        body = crypto.seal(self._pair_key(peer), crypto.pad(json.dumps(inner).encode()), aad)
        return {"t": "direct", "to": peer.nick, "body": b64e(body)}

    def _open_direct(self, peer, body):
        aad = b"crptochat-direct-v1|" + peer.key.encode() + b"|" + self.key.encode()
        crypto.unseal(self._pair_key(peer), body, aad)          # raises on v2, like the old client
        return super()._open_direct(peer, body)


def test_new_clients_switch_to_the_ratchet_after_one_message(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await alice.send_dm("bob", "primeira")                     # v1, advertising v2
            await until(lambda: messages(bob, "@alice"))
            assert bob.peers["alice"].dmr
            await bob.send_dm("alice", "resposta")                     # already v2
            await until(lambda: messages(alice, "@bob"))
            assert alice.peers["bob"].dmr
            for i in range(3):
                await alice.send_dm("bob", "igual")
            await until(lambda: len(messages(bob, "@alice")) == 4)
            sent = bodies(h, "alice", "bob")
            # the first envelope is v1: it opens with the plain pairwise key
            inner = json.loads(crypto.unpad(crypto.unseal(bob._pair_key(bob.peers["alice"]), sent[0],
                                                          b"crptochat-direct-v1|alice|bob")))
            assert inner["x"] == "primeira" and "dmr" in inner["cv"]
            v2 = sent[1:]
            assert all(b[0] == crypto.DM_V2 for b in v2)
            assert [int.from_bytes(b[1:5], "big") for b in v2] == [0, 1, 2]       # one key per message
            assert len({b[5:] for b in v2}) == 3                                  # same text, different ciphertext
            assert messages(bob, "@alice") == [("alice", "primeira")] + [("alice", "igual")] * 3
    run(main())


def test_older_clients_keep_working_on_v1(home):
    async def main():
        async with Harness(home) as h:
            new = await h.client("novo")
            old = await h.client("antigo")
            old.__class__ = OldClient
            await new.send_dm("antigo", "oi")
            await until(lambda: messages(old, "@novo"))
            await old.send_dm("novo", "oi de volta")
            await until(lambda: messages(new, "@antigo"))
            await new.send_dm("antigo", "ainda v1?")
            await until(lambda: len(messages(old, "@novo")) == 2)
            assert not new.peers["antigo"].dmr
            # every envelope new -> old opens with the v1 key
            for body in bodies(h, "novo", "antigo"):
                aad = b"crptochat-direct-v1|novo|antigo"
                crypto.unseal(old._pair_key(old.peers["novo"]), body, aad)
    run(main())


def test_the_chain_state_alone_cannot_open_past_messages(home):
    """Per-message keys: the receiving chain moved on. (The session keys still in
    memory can recompute the root, so secrecy is per login: see the README.)"""
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await alice.send_dm("bob", "abre o v2")
            await bob.send_dm("alice", "ok")
            await until(lambda: alice.peers["bob"].dmr and bob.peers["alice"].dmr)
            await alice.send_dm("bob", "segredo 1")
            await alice.send_dm("bob", "segredo 2")
            await until(lambda: len(messages(bob, "@alice")) == 3)
            old = [b for b in bodies(h, "alice", "bob") if b[0] == crypto.DM_V2]
            _, _, recv = bob._chains(bob.peers["alice"])
            # an attacker who steals bob's ratchet state now gets nothing already read
            for body in old:
                with pytest.raises(crypto.CryptoError):
                    crypto.dm_decrypt(recv.copy(), "alice", "bob", body)
    run(main())


def test_reconnecting_starts_a_new_ratchet_and_old_traffic_stays_closed(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await alice.send_dm("bob", "um")
            await bob.send_dm("alice", "dois")
            await alice.send_dm("bob", "três")
            await until(lambda: len(messages(bob, "@alice")) == 2)
            before = [b for b in bodies(h, "alice", "bob") if b[0] == crypto.DM_V2]
            old_session = alice._dh

            h.server.sessions["alice"].close()                         # alice drops and comes back
            await until(lambda: not alice.online)
            await until(lambda: alice.online, timeout=10)
            assert alice._dh is not old_session                         # fresh X25519 session key
            await bob.resolve("alice")
            await alice.send_dm("bob", "depois de voltar")
            await until(lambda: ("alice", "depois de voltar") in messages(bob, "@alice"))
            # neither side can open the previous session's envelopes with what they hold now
            _, _, recv = bob._chains(bob.peers["alice"])
            for body in before:
                with pytest.raises(crypto.CryptoError):
                    crypto.dm_decrypt(recv.copy(), "alice", "bob", body)
            # and the long-term identity keys alone are useless: the pair key needs the
            # (discarded) session private keys
            with pytest.raises(crypto.CryptoError):
                fake_root = crypto.hkdf(crypto.ed_seed(alice.identity.key) + crypto.ed_seed(bob.identity.key), b"x")
                crypto.dm_decrypt(crypto.dm_chains(fake_root, bob.identity.ik, alice.identity.ik)[1],
                                  "alice", "bob", before[0])
    run(main())


def test_tampering_and_gaps(home):
    root = b"\x07" * 32
    a_ik, b_ik = b"\x01" * 32, b"\x02" * 32
    a_send, _ = crypto.dm_chains(root, a_ik, b_ik)
    _, b_recv = crypto.dm_chains(root, b_ik, a_ik)
    first = crypto.dm_encrypt(a_send, "alice", "bob", b"um")
    crypto.dm_encrypt(a_send, "alice", "bob", b"perdida")              # refused by the relay, never arrives
    third = crypto.dm_encrypt(a_send, "alice", "bob", b"tres")
    assert crypto.dm_decrypt(b_recv, "alice", "bob", first) == b"um"
    bad = bytearray(third)
    bad[-1] ^= 1
    with pytest.raises(crypto.CryptoError):
        crypto.dm_decrypt(b_recv, "alice", "bob", bytes(bad))
    assert b_recv.n == 1                                                # failure did not move the chain
    with pytest.raises(crypto.CryptoError):                             # bound to who sends to whom
        crypto.dm_decrypt(b_recv.copy(), "carol", "bob", third)
    assert crypto.dm_decrypt(b_recv, "alice", "bob", third) == b"tres" # skips the lost one
    with pytest.raises(crypto.CryptoError):
        crypto.dm_decrypt(b_recv, "alice", "bob", first)                # no replay


# ------------------------------------------------------- review fixes (#8)

async def establish(alice, bob):
    await alice.send_dm("bob", "abre")
    await until(lambda: messages(bob, "@alice"))
    await bob.send_dm("alice", "ok")                                   # bob already answers in v2
    await until(lambda: messages(alice, "@bob"))
    await alice.send_dm("bob", "v2 também")
    await until(lambda: len(messages(bob, "@alice")) == 2)
    assert alice.peers["bob"].dmr and alice.peers["bob"].got_v2 and bob.peers["alice"].got_v2


def v2_indexes(h, to):
    return [int.from_bytes(b[1:5], "big") for b in bodies(h, None, to) if b[:1] == b"\x02"]


def test_swapping_and_restoring_a_session_key_never_restarts_the_chain(home):
    """Server replays another (validly signed) session key of the contact, then
    restores the real one. The chain must continue: restarting at n=0 under the
    same root would reuse key and nonce (keystream and Poly1305 key)."""
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await establish(alice, bob)
            await alice.send_dm("bob", "um")
            await alice.send_dm("bob", "dois")
            await until(lambda: len(messages(bob, "@alice")) == 4)
            real = h.server.sessions["bob"].public()
            other = crypto.x_pub(crypto.x_generate())
            from crptochat.protocol import b64e
            forged = {**real, "dh": b64e(other), "dh_sig": b64e(crypto.sign(bob.identity.key,
                                                                            crypto.dh_message("bob", other)))}
            alice._learn(forged)                                       # swapped...
            assert not alice.peers["bob"].dmr                          # unknown session: v2 re-learned
            alice._learn(real)                                         # ...and restored
            assert alice.peers["bob"].dmr and alice.peers["bob"].got_v2
            await alice.send_dm("bob", "três")
            await until(lambda: ("alice", "três") in messages(bob, "@alice"))
            indexes = v2_indexes(h, "bob")
            assert indexes == sorted(set(indexes)) == list(range(len(indexes)))   # never repeated
    run(main())


def test_contact_back_on_an_older_client_gets_v1_again(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await establish(alice, bob)
            h.server.sessions["bob"].close()
            await until(lambda: not bob.online)
            bob.__class__ = OldClient                                 # reinstalled an old version
            await until(lambda: bob.online, timeout=10)
            await alice.resolve("bob")                                 # new session key for bob
            assert not alice.peers["bob"].dmr
            await alice.send_dm("bob", "chegou?")
            await until(lambda: ("alice", "chegou?") in messages(bob, "@alice"))
    run(main())


def test_v1_envelopes_are_refused_once_v2_started(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await alice.send_dm("bob", "primeira, ainda v1")
            await until(lambda: messages(bob, "@alice"))
            first_v1 = bodies(h, "alice", "bob")[0]
            await bob.send_dm("alice", "ok")
            await until(lambda: messages(alice, "@bob"))
            await alice.send_dm("bob", "agora v2")
            await until(lambda: len(messages(bob, "@alice")) == 2)
            assert bob.peers["alice"].got_v2
            # the server replays the old v1 envelope: it must not be delivered again
            bob._on_direct({"from": "alice", "body": crypto_b64(first_v1)})
            await asyncio.sleep(0.3)
            assert messages(bob, "@alice") == [("alice", "primeira, ainda v1"), ("alice", "agora v2")]
    run(main())


def crypto_b64(data):
    from crptochat.protocol import b64e
    return b64e(data)


def test_a_new_peer_has_all_its_attributes():
    from crptochat.client import Peer
    peer = Peer("bob", b"\x01" * 32)
    for name, value in {"dropped": False, "guest": False, "role": "user", "away": False, "_pair": None,
                        "dmr": False, "got_v2": False, "trusted": True, "pending_ik": None}.items():
        assert getattr(peer, name) == value, name
