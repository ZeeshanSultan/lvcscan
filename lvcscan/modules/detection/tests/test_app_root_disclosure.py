"""Unit tests for the whole-app-root static-disclosure harvester.

Pure, no network: a fake session routes app-root paths to canned bodies. Verifies:
  (a) a correctly public/-rooted target (only public assets reachable) -> None (no false positive)
  (b) a misconfigured app-root-as-static target -> finding with the right inventory + APP_KEY
  (c) the SQLite magic-byte gate rejects an HTML-200 masquerading as the database
  (d) the breadth gate: a lone .env does not trip the systemic finding (env_exposure's job)
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from modules.detection.app_root_disclosure import scan


_ENV = "APP_NAME=lab\nAPP_KEY=base64:e7MhHQX6Wm/x2Vu7i8tFchUTqYoiz4dU4HHmnYaID7o=\nDB_PASSWORD=s3cret\n"
_LOCK = '{"packages":[{"name":"laravel/framework","version":"v11.0.0"}]}'
_ARTISAN = "#!/usr/bin/env php\n<?php\n"
_WEB = "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::get('/', fn () => 1);\n"
_SQLITE = b"SQLite format 3\x00" + b"\x00" * 100
_HTML404 = "<html><head><title>404 Not Found</title></head><body>nginx</body></html>"


class FakeResp:
    def __init__(self, status=200, body=b""):
        self.status_code = status
        self.content = body if isinstance(body, bytes) else body.encode()
        self.text = self.content.decode("utf-8", "replace")
        self.headers = {}
        self.cookies = []


def _sess(routes):
    """routes: dict suffix -> bytes/str body (200). Anything else -> 404."""
    class S:
        headers = {}
        def get(self, url, **kw):
            for suffix, body in routes.items():
                if url.endswith(suffix):
                    return FakeResp(200, body)
            return FakeResp(404, _HTML404)
        def post(self, url, **kw):
            return FakeResp(404, _HTML404)
    return S()


def test_correctly_rooted_target_is_none():
    # public/ root: none of the app-root files are reachable -> no finding.
    res = scan("http://target.test", session=_sess({}))
    assert res is None


def test_app_root_exposed_full_inventory_and_appkey():
    routes = {
        "/.env": _ENV, "/composer.lock": _LOCK, "/artisan": _ARTISAN,
        "/routes/web.php": _WEB, "/database/database.sqlite": _SQLITE,
    }
    res = scan("http://target.test", session=_sess(routes))
    assert res is not None
    assert res["status"] == "exposed"
    assert res["exposed_count"] >= 5
    kinds = set(res["exposed_kinds"])
    assert {"secrets", "lockfile", "source", "database"}.issubset(kinds)
    # APP_KEY harvested into the loot chain
    assert res["artifacts"]["app_key"] == "base64:e7MhHQX6Wm/x2Vu7i8tFchUTqYoiz4dU4HHmnYaID7o="
    # the SQLite DB is in the inventory (validated by magic bytes)
    assert any(e["path"] == "/database/database.sqlite" and e["kind"] == "database"
               for e in res["exposed_files"])


def test_sqlite_magic_gate_rejects_html_masquerade():
    # A target that 200s HTML for /database/database.sqlite must NOT be counted as a DB.
    routes = {"/.env": _ENV, "/artisan": _ARTISAN,
              "/database/database.sqlite": _HTML404}
    res = scan("http://target.test", session=_sess(routes))
    assert res is not None  # .env + artisan still trip it
    assert not any(e["kind"] == "database" for e in res["exposed_files"]), \
        "HTML-200 must not be accepted as the SQLite database"


def test_lone_env_does_not_trip_systemic_finding():
    # A single .env is env_exposure's job; the breadth gate (>=2 files / a high-value file)
    # must keep the systemic-exposure finding from double-reporting it.
    res = scan("http://target.test", session=_sess({"/.env": _ENV}))
    assert res is None


def test_high_value_source_alone_trips_finding():
    # One high-value file (source) is enough even without breadth — the source tree leaking
    # is severe on its own.
    res = scan("http://target.test", session=_sess({"/artisan": _ARTISAN}))
    assert res is not None
    assert res["exposed_count"] == 1
    assert res["exposed_kinds"] == ["source"]
