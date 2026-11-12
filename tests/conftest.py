import pytest


@pytest.fixture(autouse=True)
def no_desktop_notifications(monkeypatch):
    """Never pop real notifications on the machine running the tests."""
    from crptochat import notify
    sent = []
    monkeypatch.setattr(notify.Notifier, "_spawn", staticmethod(lambda argv, env: sent.append((argv, env))))
    return sent
