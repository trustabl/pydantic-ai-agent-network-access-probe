"""Agent Network Access Probe capability (Trustabl Probe)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from pydantic_ai.capabilities import AbstractCapability
from pydantic_ai.exceptions import UserError
from pydantic_ai.tools import AgentDepsT, RunContext

from pydantic_ai_agent_network_access_probe._toolset import AgentNetworkAccessProbeToolset

_PROBE_INSTRUCTIONS = (
    'Before an agent tool ships, call `probe_scan` on its directory. It returns a readiness score, '
    'a draft network allow list and findings worst-first, each with a fix hint. Apply the fix hints '
    'yourself; Probe does not change the code. Set `allow_write_tools` only when the user asks.'
)

_PROBE_VERSION = '0.5.0'


@dataclass
class AgentNetworkAccessProbe(AbstractCapability[AgentDepsT]):
    """Scans agent tool code for runtime and network-access problems with Trustabl Probe.

    Adds a `probe_scan` tool that runs Probe in the run's workspace and returns a
    readiness score, the draft network allow list (an OpenShell network policy)
    and findings with fix hints, so the agent fixes them before the tool ships.
    No model call and no API key: the agent applies the fixes.

    ```python
    from pydantic_ai import Agent
    from pydantic_ai.capabilities import LocalWorkspace
    from pydantic_ai_agent_network_access_probe import AgentNetworkAccessProbe

    agent = Agent(
        'anthropic:claude-sonnet-5',
        capabilities=[
            LocalWorkspace('.'),
            AgentNetworkAccessProbe(),
        ],
    )
    ```

    The pinned Probe release is downloaded and verified against the release's
    `checksums.txt` before anything is executed.
    """

    command: str | None = None
    """Path to a Probe (`autofix`) binary. `None` downloads the pinned release."""

    probe_version: str = _PROBE_VERSION
    """Probe release to download when `command` is not set.

    Pinned rather than tracking latest, so checksum verification stays meaningful
    and a bad Probe release cannot reach every user at once. Must be 0.2.3 or
    later, the first that runs without a model."""

    sandbox: Literal['docker', 'openshell'] | None = None
    """Also run the tool in a network-blocked sandbox with this runner, which must be
    ready in the workspace. `None` runs static analysis only."""

    timeout: float = 600.0
    """Maximum seconds for one scan. A first sandbox run also pulls the images."""

    guidance: str | None = None
    """Replaces the default instructions. `''` contributes none."""

    async def before_run(self, ctx: RunContext[AgentDepsT]) -> None:
        """Fail at the start of a run that has no workspace to scan."""
        if not ctx.workspace.attached:
            raise UserError(
                'AgentNetworkAccessProbe needs a workspace. Add one to the agent, for example '
                "`LocalWorkspace('.')`."
            )

    def get_toolset(self) -> AgentNetworkAccessProbeToolset[AgentDepsT]:
        """Build the toolset providing `probe_scan`."""
        return AgentNetworkAccessProbeToolset[AgentDepsT](
            command=self.command,
            probe_version=self.probe_version,
            sandbox=self.sandbox,
            timeout=self.timeout,
        )

    def get_instructions(self) -> str | None:
        """Scan-then-fix guidance, unless `guidance` overrides it."""
        if self.guidance is not None:
            return self.guidance or None
        return _PROBE_INSTRUCTIONS

    @classmethod
    def get_serialization_name(cls) -> str:
        """Name this capability answers to in an agent spec."""
        return 'AgentNetworkAccessProbe'
