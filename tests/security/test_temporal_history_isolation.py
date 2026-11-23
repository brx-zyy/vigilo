"""Integration proof: Temporal workflow inputs are readable from execution history.

This test uses synthetic values only. It models two tenants' workflows on the same
Temporal namespace and a second client with the same network-level access as an agent
subprocess. It does not contact a production Vigilo deployment.
"""
from __future__ import annotations

import pytest
from temporalio import workflow
from temporalio.client import WorkflowExecutionStatus
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker


@workflow.defn(name="SyntheticSecretWorkflow")
class SyntheticSecretWorkflow:
    @workflow.run
    async def run(self, payload: dict) -> str:
        return "completed"


@pytest.mark.asyncio
async def test_peer_temporal_client_can_read_another_run_redemption_key():
    """A peer with Temporal network access can list executions and read input history."""
    tenant_a_key = "SYNTHETIC_TENANT_A_KEY_DO_NOT_USE"
    tenant_b_key = "SYNTHETIC_TENANT_B_KEY_DO_NOT_USE"

    async with await WorkflowEnvironment.start_local() as env:
        async with Worker(
            env.client,
            task_queue="vigilo-security-history-test",
            workflows=[SyntheticSecretWorkflow],
        ):
            await env.client.start_workflow(
                SyntheticSecretWorkflow.run,
                {"secrets": {"ref": "synthetic-run-a", "key": tenant_a_key}},
                id="synthetic-run-a",
                task_queue="vigilo-security-history-test",
            )
            await env.client.start_workflow(
                SyntheticSecretWorkflow.run,
                {"secrets": {"ref": "synthetic-run-b", "key": tenant_b_key}},
                id="synthetic-run-b",
                task_queue="vigilo-security-history-test",
            )

            # A distinct client represents an agent process. No Vigilo JWT or
            # per-run redemption key is supplied to this client.
            peer = await env.client.connect()
            executions = [item async for item in peer.list_workflows(
                'WorkflowType = "SyntheticSecretWorkflow"'
            )]
            assert {item.id for item in executions} >= {
                "synthetic-run-a", "synthetic-run-b"
            }

            victim = peer.get_workflow_handle("synthetic-run-b")
            history = await victim.fetch_history()
            started = next(
                event for event in history.events
                if event.HasField("workflow_execution_started_event_attributes")
            )
            payload_bytes = b"".join(
                payload.data
                for payload in started.workflow_execution_started_event_attributes.input.payloads
            )
            assert tenant_b_key.encode() in payload_bytes
            assert tenant_a_key.encode() not in payload_bytes
