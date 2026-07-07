from modules.cves import cve_2023_43661 as mod


class FakeResp:
    def __init__(self, status=200, text="", url="http://cachet.test/", data=None):
        self.status_code = status
        self.text = text
        self.url = url
        self._data = data
        self.headers = {"Content-Type": "text/html"}

    def json(self):
        if self._data is None:
            raise ValueError("no json")
        return self._data


class CaptureSession:
    def __init__(self):
        self.calls = []
        self.headers = {}

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        if url.endswith("/auth/login"):
            return FakeResp(
                text='<input type="hidden" name="_token" value="csrf123">',
                url=url,
            )
        if url.endswith("/dashboard/user"):
            return FakeResp(
                text='<input type="text" class="form-control" name="api_key" disabled value="cachetlabapikey0001">',
                url=url,
            )
        return FakeResp(status=404, url=url)

    def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return FakeResp(url="http://cachet.test/dashboard")


def test_credentials_login_flow_extracts_dashboard_api_key():
    session = CaptureSession()

    token, artifacts = mod._resolve_cachet_api_token(
        session,
        "http://cachet.test",
        username="admin@cachet.test",
        password="Password123",
    )

    assert token == "cachetlabapikey0001"
    assert artifacts["auth_flow"] == "dashboard_login_then_profile_api_key"
    assert artifacts["api_key_source"] == "dashboard_profile"
    post_call = [call for call in session.calls if call[0] == "POST"][0]
    assert post_call[2]["data"]["username"] == "admin@cachet.test"
    assert post_call[2]["data"]["password"] == "Password123"
    assert post_call[2]["data"]["_token"] == "csrf123"


def test_incident_route_probe_uses_extracted_token():
    session = CaptureSession()

    result = mod._probe_incident_route_control(
        session,
        "http://cachet.test",
        token="cachetlabapikey0001",
    )

    assert result["state"] == "reachable"
    assert result["auth"] == "X-Cachet-Token"
    post_call = session.calls[0]
    assert post_call[2]["headers"]["X-Cachet-Token"] == "cachetlabapikey0001"


def test_explicit_token_skips_dashboard_login():
    session = CaptureSession()

    token, artifacts = mod._resolve_cachet_api_token(
        session,
        "http://cachet.test",
        username="admin@cachet.test",
        password="Password123",
        options={"token": "explicit-token"},
    )

    assert token == "explicit-token"
    assert artifacts["api_key_source"] == "options"
    assert session.calls == []


def test_exploit_uses_credentials_to_extract_token_before_ssti_request():
    class Session(CaptureSession):
        def post(self, url, **kwargs):
            self.calls.append(("POST", url, kwargs))
            if url.endswith("/api/v1/incidents"):
                assert kwargs["headers"]["X-Cachet-Token"] == "cachetlabapikey0001"
                return FakeResp(
                    data={"data": {"message": "base64:AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKK="}},
                    url=url,
                )
            return FakeResp(url="http://cachet.test/dashboard")

    session = Session()

    result = mod.exploit(
        "http://cachet.test",
        username="admin@cachet.test",
        password="Password123",
        options={"secrets_only": True},
        session=session,
    )

    assert result["success"] is True
    assert result["outcome_tag"] == "secrets-disclosed"
    assert result["artifacts"]["app_key"].startswith("base64:")
    assert result["artifacts"]["auth_flow"]["api_key_source"] == "dashboard_profile"
    assert any(call[1].endswith("/dashboard/user") for call in session.calls if call[0] == "GET")
