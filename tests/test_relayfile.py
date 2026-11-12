"""Etapa 5: files through the relay (default) and P2P on request."""

import asyncio
import hashlib
import json
import os
import time

import pytest
from test_e2e import Harness, messages, run, until

from crptochat import crypto
from crptochat.client import ChatClient, ChatError
from crptochat.protocol import b64d, b64e
from crptochat.relayfile import safe_name, unique_path
from crptochat.store import Identity


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("CRPTOCHAT_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr(crypto, "SCRYPT_N", 2 ** 10)
    return tmp_path


def offers(client):
    return [d for k, d in client.events if k == "file_offer" and d.get("relay")]


def systems(client):
    return [d["text"] for k, d in client.events if k == "system"]


def make_file(home, name="dados.bin", size=300_000):
    data = os.urandom(size)
    path = home / name
    path.write_bytes(data)
    return path, data


def tree(folder):
    return sorted(os.path.relpath(os.path.join(d, f), folder) for d, _, fs in os.walk(folder) for f in fs)


def test_names_are_sanitized_and_paths_stay_inside():
    assert safe_name("../../etc/passwd") == "passwd"
    assert safe_name("..") == safe_name("") == "arquivo"
    assert safe_name("C:\\Windows\\evil.exe") == "evil.exe"
    assert safe_name(".bashrc") == "bashrc"
    assert safe_name("CON.txt") == "_CON.txt"
    assert safe_name("a\x00b\nc|d?.txt") == "a_b_c_d_.txt"


def test_relay_transfer_end_to_end(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            src, data = make_file(home, "relatório secreto.bin")
            before = tree(home / "srv")
            await alice.relay.offer("bob", str(src))
            await until(lambda: offers(bob))
            offer = offers(bob)[0]
            assert offer["name"] == "relatório secreto.bin" and offer["size"] == len(data)

            dest = home / "escolhida"
            tr = await bob.relay.accept(offer["id"], str(dest))
            await until(lambda: tr.state == "done")
            assert (dest / "relatório secreto.bin").read_bytes() == data
            assert not list(dest.glob("*.part"))
            sent = next(iter(alice.relay.transfers.values()))
            await until(lambda: sent.state == "done")
            assert any("conferido" in t for t in systems(alice))

            # the server saw only ciphertext and never wrote the file anywhere
            assert tree(home / "srv") == before
            relayed = b"".join(b64d(json.loads(f)["d"]) for f in h.wire if '"t": "file_chunk"' in f)
            assert len(relayed) >= len(data) and data[:64] not in relayed and data[-64:] not in relayed
            assert not any("relatório" in f for f in h.wire)          # the name is end to end too
            assert not h.server.transfers                               # nothing left in memory
            assert h.server.counters["files"] == 1
    run(main())


def test_nothing_is_relayed_before_the_recipient_accepts(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            src, _ = make_file(home)
            await alice.relay.offer("bob", str(src))
            await until(lambda: offers(bob))
            tid = next(iter(alice.relay.transfers))
            with pytest.raises(ChatError) as err:
                await alice.request({"t": "file_chunk", "tid": tid, "i": 0, "last": True, "d": b64e(b"x" * 40)})
            assert err.value.code == "not_accepted"
            assert not [f for f in h.wire if '"t": "file_chunk"' in f and "bob" in f]
            await bob.relay.reject(offers(bob)[0]["id"])
            await until(lambda: alice.relay.transfers[tid].state == "failed")
            assert not h.server.transfers
    run(main())


def test_size_and_bandwidth_limits_from_the_admin(home):
    async def main():
        async with Harness(home) as h:
            assert "error" in h.server.admin({"op": "ratelimit", "set": {"file_burst_kb": 64}})   # < one chunk
            h.server.admin({"op": "ratelimit", "set": {"file_max_mb": 0.25, "file_kbps": 200, "file_burst_kb": 128}})
            alice, bob = await h.client("alice"), await h.client("bob")
            big, _ = make_file(home, "grande.bin", 300_000)
            with pytest.raises(ChatError, match="grande demais"):
                await alice.relay.offer("bob", str(big))               # refused locally (from the welcome)
            with pytest.raises(ChatError) as err:                       # and by the server
                await alice.request({"t": "file_open", "tid": "ab" * 16, "to": "bob", "size": 300_000})
            assert err.value.code == "too_big"

            # under the cap: the sender paces itself to the bandwidth limit
            small, data = make_file(home, "pequeno.bin", 200_000)
            started = time.monotonic()
            await alice.relay.offer("bob", str(small))
            await until(lambda: offers(bob))
            tr = await bob.relay.accept(offers(bob)[0]["id"], str(home / "dl"))
            await until(lambda: tr.state == "done", timeout=10)
            assert time.monotonic() - started > 0.8                     # paced to ~180 KiB/s
            assert (home / "dl" / "pequeno.bin").read_bytes() == data
            assert h.server.counters["rate_limited"] == 0

            h.server.admin({"op": "ratelimit", "set": {"file_max_mb": 0}})
            with pytest.raises(ChatError):
                await alice.request({"t": "file_open", "tid": "cd" * 16, "to": "bob", "size": 10})
    run(main())


def test_a_sender_that_ignores_the_window_or_the_bandwidth_is_cut(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            src, _ = make_file(home, "x.bin", 4 * 1024 * 1024)
            await alice.relay.offer("bob", str(src))
            await until(lambda: offers(bob))
            tid = next(iter(alice.relay.transfers))
            alice.relay.transfers[tid].state = "failed"                 # we drive the stream by hand
            await bob.relay.accept(offers(bob)[0]["id"], str(home / "dl"))
            bob.relay.on_chunk = lambda msg: None                       # bob just never acks
            await until(lambda: h.server.transfers.get(tid, {}).get("accepted"))
            for i in range(20):                                         # never waits for an ack
                alice._send({"t": "file_chunk", "tid": tid, "i": i, "last": False, "d": b64e(b"\0" * 1000)})
            await until(lambda: tid not in h.server.transfers)
            assert any("janela" in t for t in systems(bob))
            await until(lambda: not list((home / "dl").glob("*.part")))  # partial file removed
    run(main())


def test_channel_offer_reaches_capable_members_each_decides(home):
    async def main():
        async with Harness(home) as h:
            alice, bob, carol = [await h.client(n) for n in ("alice", "bob", "carol")]
            for c in (alice, bob, carol):
                await c.join("#lobby")
            await until(lambda: len(alice.channels["#lobby"].members) == 2)
            src, data = make_file(home, "ata.txt", 5_000)
            sent = await alice.relay.offer("#lobby", str(src))
            assert sorted(sent) == ["bob", "carol"]
            await until(lambda: offers(bob) and offers(carol))
            assert offers(bob)[0]["buffer"] == "#lobby"
            tr = await bob.relay.accept(offers(bob)[0]["id"], str(home / "bob"))
            await carol.relay.reject(offers(carol)[0]["id"])
            await until(lambda: tr.state == "done")
            assert (home / "bob" / "ata.txt").read_bytes() == data
            assert not (home / "carol").exists()
    run(main())


def test_hostile_names_land_inside_the_chosen_folder(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            src, data = make_file(home, "x.bin", 1000)
            await alice.relay.offer("bob", str(src))
            await until(lambda: offers(bob))
            # a malicious sender could put anything in the (encrypted) offer
            tr = next(iter(bob.relay.transfers.values()))
            assert tr.name == "x.bin"
            tr.name = safe_name("../../../../tmp/pwned")
            (home / "dl").mkdir()
            (home / "dl" / "pwned").write_text("já existia")
            got = await bob.relay.accept(tr.id, str(home / "dl"))
            await until(lambda: got.state == "done")
            assert got.path == str(home / "dl" / "pwned.1")              # never overwrites, never escapes
            assert (home / "dl" / "pwned").read_text() == "já existia"
            with pytest.raises(ValueError):
                unique_path(str(home / "dl"), "../fora")
    run(main())


def test_ttl_expires_the_offer_and_deletes_the_received_file(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await alice.set_dm_ttl("bob", 1)
            await until(lambda: bob.dm_ttl("alice") == 1)
            src, _ = make_file(home, "efemero.bin", 2000)
            await alice.relay.offer("bob", str(src))
            await until(lambda: offers(bob))
            assert offers(bob)[0]["ttl"] == 1
            await asyncio.sleep(1.2)
            with pytest.raises(ChatError, match="expirado"):
                await bob.relay.accept(offers(bob)[0]["id"], str(home / "dl"))

            await alice.set_dm_ttl("bob", 2)
            await until(lambda: bob.dm_ttl("alice") == 2)
            await alice.relay.offer("bob", str(src))
            await until(lambda: len(offers(bob)) == 2)
            tr = await bob.relay.accept(offers(bob)[1]["id"], str(home / "dl"))
            await until(lambda: tr.state == "done")
            assert os.path.exists(tr.path)
            assert any("será apagado do disco" in t for t in systems(bob))
            await until(lambda: not os.path.exists(tr.path), timeout=5)
    run(main())


def test_older_clients_are_skipped_with_a_hint_and_p2p_still_works(home):
    async def main():
        async with Harness(home) as h:
            alice, old = await h.client("alice"), await h.client("antigo")

            def deaf(self, peer, body, _orig=ChatClient._open_direct):
                inner = json.loads(crypto.unpad(crypto.unseal(self._pair_key(peer), body,
                                    b"crptochat-direct-v1|" + peer.key.encode() + b"|" + self.key.encode())))
                if inner.get("k") in ("hi", "fo2"):
                    return                                              # 1.0.0 does not know these
                return _orig(self, peer, body)
            old._open_direct = deaf.__get__(old)
            src, data = make_file(home, "p2p.bin", 50_000)
            assert await alice.relay.offer("antigo", str(src)) == []    # nobody capable to send to
            assert any("versão antiga" in t and "--p2p" in t for t in systems(alice))
            assert not h.server.transfers
            await alice.files.offer("antigo", str(src))                 # /send --p2p
            await until(lambda: any(k == "file_offer" and not d.get("relay") for k, d in old.events))
            await old.files.accept()
            tr = next(iter(old.files.transfers.values()))
            await until(lambda: tr.state == "done")
            assert open(tr.path, "rb").read() == data
    run(main())


def test_disconnect_mid_transfer_cleans_up_both_sides(home):
    async def main():
        async with Harness(home) as h:
            h.server.admin({"op": "ratelimit", "set": {"file_kbps": 100, "file_burst_kb": 128}})
            alice, bob = await h.client("alice"), await h.client("bob")
            src, _ = make_file(home, "lento.bin", 1_000_000)
            await alice.relay.offer("bob", str(src))
            await until(lambda: offers(bob))
            tr = await bob.relay.accept(offers(bob)[0]["id"], str(home / "dl"))
            await until(lambda: tr.done > 0)
            h.server.sessions["alice"].close()
            await until(lambda: tr.state == "failed")
            assert not list((home / "dl").glob("*")) and not h.server.transfers
    run(main())


def test_a_receiver_that_acks_without_reading_cannot_grow_the_server_queue(home):
    async def main():
        async with Harness(home) as h:
            h.server.limits.set("out_queue_kb", 1024)
            h.server.limits.set("file_burst_kb", 1 << 20)
            h.server.limits.set("file_kbps", 1 << 20)
            alice, bob = await h.client("alice"), await h.client("bob")
            src, _ = make_file(home, "big.bin", 8 * 1024 * 1024)
            await alice.relay.offer("bob", str(src))
            await until(lambda: offers(bob))
            tid = next(iter(alice.relay.transfers))
            alice.relay.transfers[tid].state = "failed"                 # we drive the stream by hand
            await bob.relay.accept(offers(bob)[0]["id"], str(home / "dl"))
            await until(lambda: h.server.transfers.get(tid, {}).get("accepted"))
            bob.relay.on_chunk = lambda msg: None                       # bob's client stays quiet
            # bob's socket stops being read: the server's writer for him blocks
            stuck = asyncio.Event()
            bob_sess = h.server.sessions["bob"]
            bob_sess.writer.drain = stuck.wait
            chunk = b64e(b"\0" * 64 * 1024)
            for i in range(60):                                         # ~5 MiB of base64, acked blindly
                if tid not in h.server.transfers:
                    break
                alice._send({"t": "file_chunk", "tid": tid, "i": i, "last": False, "d": chunk})
                await asyncio.sleep(0.01)
                if tid in h.server.transfers:
                    h.server._dispatch(bob_sess, {"t": "file_ack", "tid": tid, "i": i, "ok": False})
            await until(lambda: tid not in h.server.transfers)
            assert bob_sess.queued <= 1024 * 1024                       # never above the byte limit
            assert not bob_sess.closed                                  # the transfer was cut, not bob
            assert any("não está lendo" in w for w in h.wire) or any("não está lendo" in t for t in systems(alice))
            stuck.set()
    run(main())


def test_the_byte_limit_closes_a_session_that_never_reads(home):
    async def main():
        async with Harness(home) as h:
            h.server.limits.set("out_queue_kb", 1024)
            await h.client("alice")
            sess = h.server.sessions["alice"]
            stuck = asyncio.Event()
            sess.writer.drain = stuck.wait
            for _ in range(100):
                sess.send({"t": "notice", "msg": "x" * 30_000})
            assert sess.closed and sess.queued <= 1024 * 1024
            assert h.server.counters["slow_closed"] >= 1
            stuck.set()
    run(main())
