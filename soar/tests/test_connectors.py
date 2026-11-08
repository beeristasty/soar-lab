import pytest, httpx, respx
from app.connectors import ti_abuseipdb, contain_ufw, ticket_github

@pytest.mark.asyncio
@respx.mock
async def test_enrich_scores(monkeypatch):
    monkeypatch.setattr(ti_abuseipdb, "ABUSEIPDB_KEY", "k")
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(200, json={"data": {"abuseConfidenceScore": 88, "totalReports": 12, "countryCode": "RU"}}))
    out = await ti_abuseipdb.run(ip="1.2.3.4")
    assert out["score"] == 88

@pytest.mark.asyncio
async def test_contain_skips_allowlisted():
    out = await contain_ufw.run(ip="9.9.9.9", safe_ips={"9.9.9.9"})
    assert out["blocked"] is False

@pytest.mark.asyncio
async def test_contain_rejects_garbage():
    out = await contain_ufw.run(ip="not-an-ip")
    assert out["blocked"] is False

@pytest.mark.asyncio
@respx.mock
async def test_ticket_retries_on_5xx(monkeypatch):
    monkeypatch.setattr(ticket_github, "GITHUB_TOKEN", "t")
    monkeypatch.setattr(ticket_github, "GITHUB_REPO", "me/r")
    route = respx.post("https://api.github.com/repos/me/r/issues")
    route.side_effect = [httpx.Response(502), httpx.Response(201, json={"html_url": "u", "number": 1})]
    out = await ticket_github.run(title="x", body="y")
    assert out["number"] == 1
