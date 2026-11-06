"""Probe toolset -- runs Trustabl Probe on agent tool code and returns its findings."""

from __future__ import annotations

import json
import posixpath
import re

from pydantic import BaseModel

from pydantic_ai import RunContext
from pydantic_ai.exceptions import ModelRetry, ToolFailed, UserError
from pydantic_ai.tools import AgentDepsT
from pydantic_ai.toolsets import FunctionToolset, ToolsetTool
from pydantic_ai.workspaces import (
    SupportsCommands,
    Workspace,
    WorkspaceBackend,
    WorkspaceError,
    WorkspaceReadOnlyError,
    WorkspaceTimeoutError,
    WorkspaceUnavailableError,
    WrapperWorkspace,
)

FINDINGS_FILE = 'probe.findings.json'
ATTESTATION_FILE = 'autofix-attestation.json'
PROFILE_FILE = 'probe.profile.json'
POLICY_FILE = 'network_policies.draft.yaml'

MAX_FINDINGS = 50
"""Enough for the agent to act on; the rest stays in `probe.findings.json`."""

_NOT_FOUND_EXIT = 127
_ERROR_TAIL_CHARS = 2000
_MAX_EVIDENCE = 3
_MAX_EVIDENCE_CHARS = 300
_SEVERITY_RANK = {'critical': 3, 'warning': 2, 'info': 1}
_ANSI = re.compile(r'\x1b\[[0-9;?]*[A-Za-z]')
_NOTE = re.compile(r'sandbox skipped|sandbox unavailable|warning:', re.IGNORECASE)

_LAUNCHER = f'command -v "$1" > /dev/null 2>&1 || exit {_NOT_FOUND_EXIT}\nexec env "$@"'
"""Resolve the binary in the workspace, then exec it so the workspace timeout reaches it."""


class Finding(BaseModel):
    """One Probe finding, with the hint for fixing it."""

    severity: str
    title: str
    file: str = ''
    """Path relative to the scanned directory; empty for a finding about the whole run."""
    fix_hint: str = ''
    evidence: list[str] = []


class ProbeReport(BaseModel):
    """What one Probe scan found."""

    readiness_score: int | None = None
    """Production readiness, 0 to 100."""

    findings_total: int = 0
    by_severity: dict[str, int] = {}

    allow_list: list[str] = []
    """Draft network allow list as `host:port`, also written to `network_policies.draft.yaml`."""

    languages: list[str] = []

    sandbox: str = 'off (static only)'
    """Whether the tool also ran in the network-blocked sandbox."""

    findings: list[Finding] = []
    """Worst first, at most `MAX_FINDINGS`."""

    findings_truncated: int = 0
    """Findings left out of `findings`; every one is in `probe.findings.json`."""

    notes: list[str] = []


def probe_args(
    command: str, path: str, entrypoints: list[str] | None, runner: str | None, allow_write_tools: bool
) -> list[str]:
    """Arguments for one Probe scan. No model and no signing: the calling agent applies the fixes."""
    args = [command, 'fix', '--source', path, '--no-sign', '--output', 'json']
    for ep in entrypoints or []:
        if ep.strip():
            args += ['--entrypoint', ep.strip()]
    if runner:
        args += ['--sandbox', '--runner', runner]
    if allow_write_tools:
        args.append('--allow-write-tools')
    return args


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + '…'


def build_report(
    findings: dict, attestation: dict, profile: dict | None = None, *, runner: str | None = None, stderr: str = ''
) -> ProbeReport:
    """Turn Probe's report files into a `ProbeReport`, mirroring the Probe MCP server's summary."""
    raw = sorted(findings.get('findings') or [], key=lambda f: -_SEVERITY_RANK.get(f.get('severity', ''), 0))
    counts: dict[str, int] = {}
    for f in raw:
        counts[f.get('severity', 'unknown')] = counts.get(f.get('severity', 'unknown'), 0) + 1

    source = str(findings.get('source') or '').replace('\\', '/').rstrip('/')

    def rel(file: str) -> str:
        file = file.replace('\\', '/')
        return file[len(source) + 1 :] if source and file.startswith(source + '/') else file

    def evidence(f: dict) -> list[str]:
        out = []
        for e in (f.get('evidence') or [])[:_MAX_EVIDENCE]:
            label = f"{e['label']}: " if e.get('label') else ''
            out.append(f"[{e.get('source', '?')}] " + _clip(f"{label}{e.get('detail', '')}", _MAX_EVIDENCE_CHARS))
        return out

    kept = [
        Finding(
            severity=f.get('severity', 'unknown'),
            title=f.get('title', ''),
            file=rel(f.get('file') or ''),
            fix_hint=(f.get('fix_hint') or '').strip(),
            evidence=evidence(f),
        )
        for f in raw[:MAX_FINDINGS]
    ]

    ran = any(t.get('harness_id') for t in (profile or {}).get('tools') or [])
    if not runner:
        sandbox = 'off (static only)'
    elif ran:
        sandbox = f'ran with {runner}'
    else:
        sandbox = f'requested with {runner}, but no tool ran in it (see the findings and notes)'

    notes = list(dict.fromkeys(line.strip() for line in _ANSI.sub('', stderr).splitlines() if _NOTE.search(line)))
    if any((f.get('title') or '').startswith('Sandbox execution skipped') for f in raw):
        notes.append(
            'A tool that looks destructive was not run in the sandbox. To run it anyway, call probe_scan '
            'with allow_write_tools=true, only if the user asks, ideally with staging credentials.'
        )

    return ProbeReport(
        readiness_score=attestation.get('production_readiness_score'),
        findings_total=len(raw),
        by_severity=counts,
        allow_list=[f"{c['host']}:{c['port']}" for c in attestation.get('network_calls') or []],
        languages=attestation.get('languages_detected') or [],
        sandbox=sandbox,
        findings=kept,
        findings_truncated=len(raw) - len(kept),
        notes=notes,
    )


def _innermost_backend(workspace: Workspace) -> WorkspaceBackend:
    """The backend under any facades and wrappers."""
    current: WorkspaceBackend = workspace
    while isinstance(current, Workspace):
        current = current.wrapped if isinstance(current, WrapperWorkspace) else current.backend
    return current


def supports_commands(workspace: Workspace) -> bool:
    """Whether `workspace.run` can succeed and Probe can write its reports."""
    if not workspace.attached or workspace.read_only:
        return False
    return isinstance(_innermost_backend(workspace), SupportsCommands)


def _raise_tool_failure(error: WorkspaceError) -> None:
    """Report a workspace refusal to the model; a retry cannot fix any of these."""
    if isinstance(error, WorkspaceUnavailableError):
        raise error
    if isinstance(error, WorkspaceReadOnlyError):
        raise ToolFailed('The workspace is read-only; Probe needs to write its reports.') from error
    raise ToolFailed(str(error) or f'The workspace operation failed ({type(error).__name__}).') from error


_INSTALL_HINT = (
    'Trustabl Probe is not available in this workspace.\n'
    'The pinned Probe release was downloaded and verified on the host, but this workspace '
    'cannot see that path, which is normal for a sandbox.\n'
    'Add the `autofix` binary from https://github.com/trustabl/agent-network-access-probe/releases '
    'to the sandbox image, and pass its path as `command`.'
)


class AgentNetworkAccessProbeToolset(FunctionToolset[AgentDepsT]):
    """Exposes one tool that scans agent tool code with Trustabl Probe.

    Probe runs in the run's workspace, so it reads the code the agent is working
    on, local or sandboxed. Problems the model cannot fix -- no Probe in the
    workspace, a scan that failed -- raise `UserError`. A timeout raises
    `ModelRetry`.
    """

    def __init__(self, *, command: str | None, probe_version: str, sandbox: str | None, timeout: float) -> None:
        super().__init__()
        self._command = command
        self._probe_version = probe_version
        self._sandbox = sandbox
        self._timeout = timeout
        self.add_function(self.probe_scan, name='probe_scan')

    async def get_tools(self, ctx: RunContext[AgentDepsT]) -> dict[str, ToolsetTool[AgentDepsT]]:
        """Offer the tool only when the workspace can run commands and take the reports."""
        if not supports_commands(ctx.workspace):
            return {}
        return await super().get_tools(ctx)

    async def _resolve_command(self, ctx: RunContext[AgentDepsT]) -> str:
        """The pinned Probe, downloaded and checksum-verified on the host.

        Unlike the analyzer, an `autofix` on the workspace's PATH is not used: the
        name is too generic to trust as Probe. The host download is used only after
        confirming the workspace can see that path -- it is invisible to a sandbox.
        """
        if self._command is not None:
            return self._command

        from pydantic_ai_agent_network_access_probe._binary import ensure_binary

        path = ensure_binary(self._probe_version).as_posix()
        visible = await ctx.workspace.run(['sh', '-c', 'test -x "$1"', 'sh', path], timeout=30)
        if visible.exit_code != 0:
            raise UserError(_INSTALL_HINT)
        return path

    async def _read_json(self, ctx: RunContext[AgentDepsT], path: str, name: str) -> dict | None:
        try:
            return json.loads(await ctx.workspace.read_text(posixpath.join(path, name)))
        except (WorkspaceError, OSError, ValueError):
            return None

    async def probe_scan(
        self,
        ctx: RunContext[AgentDepsT],
        path: str = '.',
        entrypoints: list[str] | None = None,
        allow_write_tools: bool = False,
    ) -> ProbeReport:
        """Scan a directory of agent tool code with Trustabl Probe.

        Probe reads the code (Python, Go, JavaScript/TypeScript, Ruby, Shell) and
        flags problems such as missing timeouts, hardcoded credentials or unfiltered
        tool output, and drafts the network allow list the tool needs. When the
        sandbox is enabled it also runs the tool with its network blocked, which
        catches problems that only show up at runtime.

        Args:
            ctx: the current agent run context.
            path: directory with the tool code, relative to the workspace working directory.
            entrypoints: entry point files inside the directory, such as `['tool.py']`.
                Default: Probe discovers them.
            allow_write_tools: also run tools that look destructive (network writes,
                deletes, payments) in the sandbox. Only set this when the user asks.

        Returns:
            A readiness score, the draft network allow list and findings worst-first,
            each with a fix hint for you to apply; Probe does not change the code. It
            writes `probe.findings.json`, `network_policies.draft.yaml`,
            `probe.profile.json` and `autofix-attestation.json` into the directory.
        """
        command = await self._resolve_command(ctx)
        args = probe_args(command, path, entrypoints, self._sandbox, allow_write_tools)
        try:
            result = await ctx.workspace.run(['sh', '-c', _LAUNCHER, 'sh', *args], timeout=self._timeout)
        except WorkspaceTimeoutError:
            raise ModelRetry(
                f'Probe did not finish within {self._timeout}s. A first sandbox run also pulls the '
                'sandbox images; try again.'
            ) from None
        except WorkspaceError as e:
            _raise_tool_failure(e)

        tail = _ANSI.sub('', f'{result.stdout}\n{result.stderr}').strip()[-_ERROR_TAIL_CHARS:]
        if result.exit_code == _NOT_FOUND_EXIT and not result.stdout.strip():
            raise UserError(_INSTALL_HINT)
        if result.exit_code != 0:
            raise UserError(f'Probe exited with code {result.exit_code} on {path}.\n\nOutput:\n{tail}')

        findings = await self._read_json(ctx, path, FINDINGS_FILE)
        attestation = await self._read_json(ctx, path, ATTESTATION_FILE)
        if findings is None or attestation is None:
            raise UserError(f'Probe ran but did not write its reports to {path}.\n\nOutput:\n{tail}')
        profile = await self._read_json(ctx, path, PROFILE_FILE)
        return build_report(findings, attestation, profile, runner=self._sandbox, stderr=result.stderr)
