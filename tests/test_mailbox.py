"""Messages for someone offline: prekeys, the mailbox and what the server sees."""

import json
import time

import pytest
from test_e2e import Harness, messages, run, until

from crptochat import crypto, mailbox
from crptochat.client import ChatError
from crptochat.protocol import b64d, b64e
from crptochat.store import Identity


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("CRPTOCHAT_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr(crypto, "SCRYPT_N", 2 ** 10)
    return tmp_path


def opk_count(h, nick):
    return h.server.db.execute("SELECT COUNT(*) FROM onetime_keys WHERE nick_lower=?", (nick,)).fetchone()[0]


def mail_rows(h, nick=None):
    sql = "SELECT to_lower, body FROM mailbox" + (" WHERE to_lower=?" if nick else "")
    return h.server.db.execute(sql, (nick,) if nick else ()).fetchall()


async def leave(h, client):
    nick = client.key
    await client.close()
    for c, task in h.clients:
        if c is client:
            task.cancel()
    await until(lambda: nick not in h.server.sessions)


async def back(h, nick):
    return await h.client(nick, identity=Identity.load(nick, "pw"))


async def published(h, client):
    await until(lambda: opk_count(h, client.key) == mailbox.OPK_TARGET and not client.mail.busy)


def test_messages_wait_for_someone_offline(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await published(h, bob)
            await alice.resolve("bob")                                  # pinned while online
            await leave(h, bob)

            for text in ("oi, você sumiu", "liga quando voltar", "abraço"):
                await alice.send_dm("bob", text)
            mine = [d["text"] for k, d in alice.events if k == "message" and d["mine"]]
            assert mine == ["oi, você sumiu", "liga quando voltar", "abraço"]
            assert any(k == "system" and "caixa postal" in d["text"] for k, d in alice.events)
            await alice.set_dm_ttl("bob", 3600)                         # the timer waits too
            rows = mail_rows(h, "bob")
            assert len(rows) == 4
            assert opk_count(h, "bob") == mailbox.OPK_TARGET - 1        # one bundle for the whole batch

            # what the server keeps: recipient, time and opaque bytes. No sender, no text.
            dump = json.dumps([[r[0], bytes(r[1]).hex()] for r in rows])
            assert "alice" not in dump and alice.identity.ik.hex() not in dump
            for row in rows:
                assert bytes(row[1])[0] == (crypto.MAIL_PQ if crypto.HAS_MLKEM else crypto.MAIL_V1)
                assert b"alice" not in bytes(row[1]) and "sumiu".encode() not in bytes(row[1])
            columns = [c[1] for c in h.server.db.execute("PRAGMA table_info(mailbox)")]
            assert columns == ["id", "to_lower", "ts", "expires", "body"]

            bob2 = await back(h, "bob")
            await until(lambda: len(messages(bob2, "@alice")) == 3)
            got = [d for k, d in bob2.events if k == "message"]
            assert [d["text"] for d in got] == ["oi, você sumiu", "liga quando voltar", "abraço"]
            assert all(abs(d["sent"] - time.time()) < 60 for d in got)
            await until(lambda: bob2.store.dm_ttl("alice") == 3600)
            await until(lambda: mail_rows(h, "bob") == [])              # acknowledged, deleted
            # the one-time key used is gone from bob's disk too
            used = h.server.db.execute("SELECT key_id FROM onetime_keys WHERE nick_lower='bob'").fetchall()
            assert len(bob2.mail.store.data["opks"]) == len(used)

            # once both are online, back to live delivery
            await alice.send_dm("bob", "ao vivo")
            await until(lambda: ("alice", "ao vivo") in messages(bob2, "@alice"))
            assert mail_rows(h) == []
    run(main())


def test_replayed_or_forged_mail_is_refused(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await published(h, bob)
            await alice.resolve("bob")
            await leave(h, bob)
            await alice.send_dm("bob", "uma vez só")
            original = bytes(mail_rows(h, "bob")[0][1])

            bob2 = await back(h, "bob")
            await until(lambda: messages(bob2, "@alice"))
            await until(lambda: not bob2.mail.busy and mail_rows(h, "bob") == [])
            await leave(h, bob2)

            # the server hands the same envelope out again, plus a tampered copy
            tampered = bytearray(original)
            tampered[crypto.MAIL_HEADER - 1] ^= 5               # another index: not a copy, and it must not open
            now = int(time.time())
            for blob in (original, bytes(tampered)):
                h.server.db.execute("INSERT INTO mailbox (to_lower, ts, expires, body) VALUES ('bob',?,?,?)",
                                    (now, now + 3600, blob))
            h.server.db.commit()
            bob3 = await back(h, "bob")
            await until(lambda: not bob3.mail.busy and mail_rows(h, "bob") == [])
            assert messages(bob3, "@alice") == []
            assert any(k == "system" and "não pôde ser aberta" in d["text"] for k, d in bob3.events)
    run(main())


def test_the_server_cannot_slip_in_its_own_prekey(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await published(h, bob)
            await alice.resolve("bob")
            await leave(h, bob)
            mallory = crypto.x_pub(crypto.x_generate())
            h.server.db.execute("UPDATE prekeys SET spk=? WHERE nick_lower='bob'", (mallory,))
            h.server.db.commit()
            with pytest.raises(ChatError) as err:
                await alice.send_dm("bob", "não deveria sair")
            assert err.value.code == "untrusted"
            assert mail_rows(h) == []

            # nor present another identity for the nick: the pinned key wins
            key = crypto.ed_generate()
            h.server.db.execute("UPDATE users SET ik=? WHERE nick_lower='bob'", (crypto.ed_pub(key),))
            h.server.db.commit()
            alice.mail.out.clear()
            with pytest.raises(ChatError):
                await alice.send_dm("bob", "nem assim")
            assert mail_rows(h) == []
    run(main())


def test_mailbox_rules_on_the_server(home):
    async def main():
        async with Harness(home) as h:
            alice, bob, carol = await h.client("alice"), await h.client("bob"), await h.client("carol")
            await published(h, bob)
            body = b64e(b"\x04" + b"\x00" * 80)
            with pytest.raises(ChatError) as err:
                await alice.request({"t": "mail", "to": "bob", "body": body})
            assert err.value.code == "online"                           # online: send it live
            await leave(h, bob)
            with pytest.raises(ChatError) as err:
                await alice.request({"t": "mail", "to": "ghost", "body": body})
            assert err.value.code == "no_prekeys"

            h.server.limits.set("mail_per_sender", 3)
            h.server.limits.set("mail_per_user", 5)
            for _ in range(3):
                await alice.request({"t": "mail", "to": "bob", "body": body})
            with pytest.raises(ChatError) as err:
                await alice.request({"t": "mail", "to": "bob", "body": body})
            assert err.value.code == "mailbox_full"                     # per sender
            for _ in range(2):
                await carol.request({"t": "mail", "to": "bob", "body": body})
            with pytest.raises(ChatError) as err:
                await carol.request({"t": "mail", "to": "bob", "body": body})
            assert err.value.code == "mailbox_full"                     # per recipient

            # expired mail really goes away
            h.server.db.execute("UPDATE mailbox SET expires=0")
            assert h.server.purge_mail() == 5

            # one-time keys are handed out once, and bundles are rate limited
            before = opk_count(h, "bob")
            first = await alice.request({"t": "prekey_bundle", "nick": "bob"})
            second = await alice.request({"t": "prekey_bundle", "nick": "bob"})
            assert first["opk"]["id"] != second["opk"]["id"] and opk_count(h, "bob") == before - 2
            h.server.limits.set("prekey_fetch_per_hour", 2)
            with pytest.raises(ChatError) as err:
                await alice.request({"t": "prekey_bundle", "nick": "bob"})
            assert err.value.code == "rate"

            # a prekey with a bad signature is refused
            with pytest.raises(ChatError):
                await alice.request({"t": "prekeys", "spk_id": 9, "spk": b64e(b"\x01" * 32),
                                     "spk_sig": b64e(b"\x00" * 64)})

            # mailbox off: nothing is stored
            h.server.limits.set("mail_days", 0)
            with pytest.raises(ChatError) as err:
                await carol.request({"t": "mail", "to": "bob", "body": body})
            assert err.value.code == "no_mailbox"
    run(main())


def test_anonymous_users_have_no_mailbox(home):
    async def main():
        async with Harness(home) as h:
            ident = Identity("guest", crypto.ed_generate())
            anon = await h.client(crypto.guest_nick(ident.ik), identity=ident, guest=True)
            assert not anon.mail.available
            for req in ({"t": "prekey_status"}, {"t": "prekey_bundle", "nick": "alice"},
                        {"t": "mail", "to": "alice", "body": "AAAA"}):
                with pytest.raises(ChatError) as err:
                    await anon.request(req)
                assert err.value.code == "denied"
    run(main())


def test_invite_keys_wait_in_the_mailbox(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await published(h, bob)
            await alice.resolve("bob")
            await leave(h, bob)
            await alice.create("#cofre", crypto.random_passphrase())
            reply = await alice.invite("#cofre", "bob")
            assert reply["keys_left"]
            bob2 = await back(h, "bob")
            await until(lambda: "#cofre" in bob2.invites)
            await bob2.join("#cofre")
            assert bob2.channels["#cofre"].joined
    run(main())


def test_signed_prekeys_rotate_and_old_ones_still_open_mail(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await published(h, bob)
            await alice.resolve("bob")
            await leave(h, bob)
            await alice.send_dm("bob", "selada na prekey antiga")

            # a week later bob logs in: new signed prekey, the old one still opens the waiting mail
            store = mailbox.PreKeyStore(Identity.load("bob", "pw"), bob.store.server_id)
            old_id = store.data["spk"]["id"]
            store.data["spk"]["t"] -= mailbox.SPK_ROTATE + 60
            store.save()
            bob2 = await back(h, "bob")
            await until(lambda: messages(bob2, "@alice"))
            assert bob2.mail.store.data["spk"]["id"] != old_id
            assert [o["id"] for o in bob2.mail.store.data["old"]] == [old_id]
            row = h.server.db.execute("SELECT spk_id FROM prekeys WHERE nick_lower='bob'").fetchone()
            assert row[0] == bob2.mail.store.data["spk"]["id"]

            # retired keys are forgotten once nothing sealed to them can be waiting
            later = time.time() + mailbox.SPK_KEEP + 60
            bob2.mail.store.data["spk"]["t"] = later        # keep the current one
            assert bob2.mail.store.rotate(later)
            assert bob2.mail.store.data["old"] == []
    run(main())


def test_prekeys_are_sealed_at_rest(home):
    ident = Identity.create("neo", "pw")
    store = mailbox.PreKeyStore(ident, "srv:7777")
    store.rotate()
    store.new_onetime(3)
    store.save()
    raw = open(store.path, "rb").read()
    priv = store.data["spk"]["priv"]
    assert priv.encode() not in raw and b"opks" not in raw
    assert "neo" not in store.path and "srv" not in store.path
    again = mailbox.PreKeyStore(Identity.load("neo", "pw"), "srv:7777")
    assert again.data == store.data
    other = mailbox.PreKeyStore(Identity.create("trinity", "pw"), "srv:7777")
    assert other.data["spk"] is None                                    # its own, separate file
    assert b64d(priv)
