"""Minimal workflow definition for the synthetic Temporal security test.

Keep this module free of test/client imports: Temporal's workflow sandbox
re-imports the module containing the workflow class.
"""
from temporalio import workflow


@workflow.defn(name="VigiloSyntheticSecretWorkflow")
class VigiloSyntheticSecretWorkflow:
    @workflow.run
    async def run(self, payload: dict) -> str:
        return "completed"
