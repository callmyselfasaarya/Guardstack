import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.database import init_db



@pytest.mark.asyncio
async def test_health_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["service"] == "Guardstack"

@pytest.mark.asyncio
async def test_repositories_and_scan_flow():
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Create Repository
        repo_payload = {
            "name": "vulnerable-app",
            "full_name": "test-org/vulnerable-app",
            "clone_url": "https://github.com/test-org/vulnerable-app.git",
            "default_branch": "main"
        }
        res_repo = await client.post("/api/repositories", json=repo_payload)
        assert res_repo.status_code == 200
        repo_data = res_repo.json()
        repo_id = repo_data["id"]

        # 2. Trigger Scan
        scan_payload = {
            "repo_full_name": "test-org/vulnerable-app",
            "branch": "main",
            "commit_hash": "a1b2c3d",
            "scanners": ["semgrep", "gitleaks", "trivy"]
        }
        res_scan = await client.post("/api/scans", json=scan_payload)
        assert res_scan.status_code == 200
        scan_data = res_scan.json()
        assert scan_data["repo_id"] == repo_id
        assert scan_data["status"] in {"queued", "running"}

@pytest.mark.asyncio
async def test_dast_challenge_flow():
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        challenge_payload = {"target_url": "http://localhost:3000"}
        res = await client.post("/api/dast/challenge", json=challenge_payload)
        assert res.status_code == 200
        data = res.json()
        assert "verification_token" in data
        assert data["expected_path"] == "/.well-known/guardstack-challenge.txt"

@pytest.mark.asyncio
async def test_settings_endpoint():
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/settings")
        assert res.status_code == 200
        data = res.json()
        assert "llm_provider" in data
