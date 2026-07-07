import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from modules.cves.cve_2024_29291 import scan


class FakeResp:
    def __init__(self, status=200, body=""):
        self.status_code = status
        self.text = body
        self.content = body.encode()
        self.headers = {}


class FakeSession:
    def __init__(self, body, status=200):
        self.body = body
        self.status = status
        self.urls = []

    def get(self, url, **kwargs):
        self.urls.append(url)
        if url.endswith("/storage/logs/laravel.log"):
            return FakeResp(self.status, self.body)
        return FakeResp(404, "not found")


def test_cve_2024_29291_confirms_pdo_credential_leak():
    body = """[2026-06-17 10:00:00] production.ERROR: SQLSTATE[HY000]
#0 /var/www/html/vendor/laravel/framework/src/Illuminate/Database/Connectors/Connector.php(70): PDO->__construct('mysql:host=db;dbname=prod', 'prod_user', 'prod_password', Array)
#1 /var/www/html/vendor/laravel/framework/src/Illuminate/Database/Connectors/Connector.php(46): Illuminate\\Database\\Connectors\\Connector->createPdoConnection()
"""
    res = scan("http://target.test", session=FakeSession(body))
    assert res["verdict"] == "confirmed_vulnerable"
    assert res["vulnerable"] is True
    assert any("pdo_construct" in item for item in res["evidence"])


def test_cve_2024_29291_requires_credentials_not_just_readable_log():
    body = """[2026-06-17 10:00:00] production.ERROR: RuntimeException: generic failure
#0 /var/www/html/vendor/laravel/framework/src/Illuminate/Foundation/Application.php(1): example()
#1 /var/www/html/public/index.php(1): require()
"""
    res = scan("http://target.test", session=FakeSession(body))
    assert res["verdict"] == "surface_present"
    assert res["vulnerable"] is False
    assert any("no DB credential evidence" in item for item in res["evidence"])


def test_cve_2024_29291_confirms_env_style_db_secret_leak():
    body = """[2026-06-17 10:00:00] local.ERROR: leaked env dump
DB_HOST=127.0.0.1
DB_DATABASE=app
DB_USERNAME=app_user
DB_PASSWORD=supersecret
"""
    res = scan("http://target.test", session=FakeSession(body))
    assert res["verdict"] == "confirmed_vulnerable"
    assert any("env_db_credentials" in item for item in res["evidence"])
