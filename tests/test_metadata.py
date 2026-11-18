"""What the relay can learn from sizes."""

import json

import pytest
from test_e2e import Harness, messages, run, until

from crptochat import crypto


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("CRPTOCHAT_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr(crypto, "SCRYPT_N", 2 ** 10)
    return tmp_path


def test_padding_buckets():
    sizes = {crypto.padded_size(n) for n in range(0, 4096)}
    assert sizes == {64, 128, 256, 512, 1024, 2048, 4096}
    for n in range(0, 20000, 7):
        padded = crypto.pad(b"\x01" * n)
        assert len(padded) == crypto.padded_size(n) and crypto.unpad(padded) == b"\x01" * n
        assert len(padded) <= max(2 * (n + 1), 64) and len(padded) - n <= max(n + 1, 64)
    # what older clients sent (multiples of 64) still opens
    old = b"oi" + b"\x80" + b"\x00" * 61
    assert crypto.unpad(old) == b"oi"


def test_short_and_long_messages_look_the_same(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await alice.join("#lobby")
            await bob.join("#lobby")
            await until(lambda: "bob" in alice.channels["#lobby"].recv and "alice" in bob.channels["#lobby"].recv)
            texts = ["ok", "sim", "chego em 10 min, me espera",
                     "x" * 60, "y" * 90]
            for text in texts:
                alice.send_message("#lobby", text)
            await until(lambda: len(messages(bob)) == len(texts))
            frames = [json.loads(f) for f in h.wire]
            sizes = [len(f["body"]) for f in frames if f.get("t") == "msg"]
            assert len(sizes) == len(texts)
            assert len(set(sizes[:3])) == 1           # "ok" and a 26-character sentence: same size
            assert sizes[3] == sizes[4] > sizes[0]    # 60 and 90 characters: the next bucket, together
    run(main())
