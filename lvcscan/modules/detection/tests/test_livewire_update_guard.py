"""Phase 6 — livewire_update must not crash on a 200 that isn't a Livewire envelope."""

import requests
import pytest

from modules.helpers import livewire_upload as lw


class _Resp:
    def __init__(self, status, payload=None, text="", raise_json=False):
        self.status_code = status
        self._payload = payload
        self.text = text
        self._raise_json = raise_json
        self.url = "http://t/livewire/update"

    def json(self):
        if self._raise_json:
            raise ValueError("no json")
        return self._payload


class _Sess:
    def __init__(self, resp):
        self._resp = resp

    def post(self, *a, **k):
        return self._resp


def _component():
    return {"snapshot": "{}", "csrf": "x", "csrf_header": "X-CSRF-TOKEN", "csrf_token_field": "tok"}


def test_non_livewire_200_json_raises_controlled():
    sess = _Sess(_Resp(200, payload={"unexpected": "shape"}))
    with pytest.raises(requests.RequestException):
        lw.livewire_update(sess, "http://t/livewire/update", _component(), calls=[])


def test_html_200_raises_controlled_not_valueerror():
    sess = _Sess(_Resp(200, raise_json=True, text="<html>blocked by WAF</html>"))
    with pytest.raises(requests.RequestException):
        lw.livewire_update(sess, "http://t/livewire/update", _component(), calls=[])


def test_malformed_200_tolerated_when_flag_set():
    sess = _Sess(_Resp(200, payload={"components": []}))
    snap, effects, status = lw.livewire_update(
        sess, "http://t/livewire/update", _component(), calls=[], tolerate_500=True)
    assert snap is None and status == 200
