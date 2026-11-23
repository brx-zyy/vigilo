"""Probe run inside the actual Vigilo worker image as an untrusted agent process."""
from __future__ import annotations

import asyncio
import json
import os
import sys

from temporalio.client import Client
from src.ai.envguard import strip_secret_env


async def main() -> None:
    victim_run_id = sys.argv[1]

    # Match the environment handed to agent CLI subprocesses.
    agent_env = strip_secret_env(dict(os.environ))
    temporal_address = agent_env.get("TEMPORAL_ADDRESS")
    if not temporal_address:
        raise RuntimeError("TEMPORAL_ADDRESS was not preserved for the agent")
    if "VIGILO_INTERNAL_API_URL" in agent_env:
        raise RuntimeError("test setup mismatch: internal API URL was not scrubbed")

    client = await Client.connect(temporal_address)
    executions = [item async for item in client.list_workflows(
        'WorkflowType = "VigiloSyntheticSecretWorkflow"'
    )]
    if victim_run_id not in {item.id for item in executions}:
        raise RuntimeError("victim workflow was not visible to the agent client")

    history = await client.get_workflow_handle(victim_run_id).fetch_history()
    started = next(
        event for event in history.events
        if event.HasField("workflow_execution_started_event_attributes")
    )
    payload_bytes = b"".join(
        item.data
        for item in started.workflow_execution_started_event_attributes.input.payloads
    )
    payload = json.loads(payload_bytes.decode("utf-8"))
    key = payload["secrets"]["key"]

    print(json.dumps({
        "workflow_enumeration": True,
        "history_read": True,
        "temporal_address_survived_envguard": True,
        "internal_api_url_removed_by_envguard": True,
        "victim_run_id": victim_run_id,
        "redeemed_key_from_history": key,
    }))


if __name__ == "__main__":
    asyncio.run(main())
