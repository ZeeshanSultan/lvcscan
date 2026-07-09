"""Phase 7 — recon hardening: private-IP tagging, wider wildcard sampling."""

from modules.recon import subdomain_enum as se


def test_is_private_ip():
    for ip in ("127.0.0.1", "10.1.2.3", "192.168.0.5", "172.16.0.1", "172.31.255.1", "169.254.1.1"):
        assert se._is_private_ip(ip) is True, ip
    for ip in ("8.8.8.8", "1.1.1.1", "172.32.0.1", "172.15.0.1", "93.184.216.34"):
        assert se._is_private_ip(ip) is False, ip


def test_wildcard_sampling_uses_more_labels():
    seen = []

    def resolver(host):
        seen.append(host)
        return {"5.6.7.8"}

    wc = se._detect_wildcard("example.com", resolver)
    assert len(seen) >= 8  # widened from 3
    assert wc == {"5.6.7.8"}


def test_private_host_is_tagged_not_dropped():
    def resolver(host):
        return {"10.0.0.5"} if host.startswith("internal.") else set()

    res = se.enumerate_subdomains(
        "example.com", use_crtsh=False, http_probe=None, resolver=resolver,
        extra_labels=["internal"], wordlist=_empty(), threads=2, resolve_timeout=0.3,
    )
    hosts = {s["host"]: s for s in res["subdomains"]}
    assert "internal.example.com" in hosts               # kept (internal recon preserved)
    assert hosts["internal.example.com"]["private"] is True


def _empty():
    import tempfile
    f = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
    f.close()
    return f.name
