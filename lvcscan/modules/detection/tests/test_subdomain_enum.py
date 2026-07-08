"""Subdomain enumeration — offline (mocked resolver / crt.sh / probe), edge-case focused."""
import json

from modules.recon import subdomain_enum as se


def test_normalize_domain():
    assert se.normalize_domain("https://Example.COM/foo?x=1") == "example.com"
    assert se.normalize_domain("app.example.com:8080") == "app.example.com"
    assert se.normalize_domain("http://user@host.example.com") == "host.example.com"
    assert se.normalize_domain("1.2.3.4") is None          # IP
    assert se.normalize_domain("10.0.0.0/24") is None       # CIDR-ish / IP
    assert se.normalize_domain("localhost") is None         # no dot
    assert se.normalize_domain("") is None


def test_ip_target_rejected():
    r = se.enumerate_subdomains("http://1.2.3.4", resolver=lambda h: set())
    assert r["ok"] is False and "domain" in r["error"]


def test_wildcard_dns_is_filtered():
    WILD = {"1.1.1.1"}

    def resolver(host):
        specific = {"api.example.com": {"2.2.2.2"}}      # real, non-wildcard host
        if host in specific:
            return specific[host]
        if host.endswith(".example.com"):                # everything else = wildcard answer
            return WILD
        return set()

    r = se.enumerate_subdomains("example.com", resolver=resolver, use_crtsh=False)
    assert r["ok"] and r["wildcard"] is True and r["wildcard_ips"] == ["1.1.1.1"]
    hosts = {s["host"] for s in r["subdomains"]}
    assert hosts == {"api.example.com"}                  # only the non-wildcard IP survives
    assert r["dropped_wildcard"] > 0


def test_crtsh_merge_and_offdomain_rejected():
    def resolver(host):
        return {"9.9.9.9"} if host in {"admin.example.com", "www.example.com"} else set()

    def crtsh_fetch(url):
        return json.dumps([
            {"name_value": "admin.example.com\n*.example.com"},
            {"name_value": "evil.attacker.com"},          # off-domain — must be rejected
            {"name_value": "example.com"},                # apex — not a sub
        ])

    r = se.enumerate_subdomains("example.com", resolver=resolver, crtsh_fetch=crtsh_fetch, use_crtsh=True)
    hosts = {s["host"] for s in r["subdomains"]}
    assert "admin.example.com" in hosts                  # crt.sh name, resolved
    assert not any("attacker.com" in h for h in hosts)   # off-domain never included
    src = {s["host"]: s["source"] for s in r["subdomains"]}
    assert src.get("admin.example.com") == "crtsh"


def test_http_probe_tags_laravel():
    def resolver(host):
        return {"5.5.5.5"} if host == "app.example.com" else set()

    def probe(host):
        return {"status": 200, "https": True, "is_laravel": True}

    r = se.enumerate_subdomains("example.com", resolver=resolver, use_crtsh=False,
                                http_probe=probe, extra_labels=["app"])
    app = [s for s in r["subdomains"] if s["host"] == "app.example.com"]
    assert app and app[0]["is_laravel"] is True and app[0]["http_status"] == 200


def test_no_resolves_is_graceful():
    r = se.enumerate_subdomains("example.com", resolver=lambda h: set(), use_crtsh=False)
    assert r["ok"] and r["resolved"] == 0 and r["subdomains"] == []
