# pydantic-ai-agent-network-access-probe

Trustabl Probe for [Pydantic AI](https://ai.pydantic.dev): give your agent a tool that scans agent tool
code for problems that break tools in production, and drafts the network allow list the tool needs.

Probe reads the tool's code (Python, Go, JavaScript/TypeScript, Ruby and Shell) and flags problems such as
missing timeouts, hardcoded credentials or unfiltered tool output. It also drafts a network allow list (an
OpenShell network policy) from the code. With the sandbox enabled it runs the tool with its network blocked,
catching crashes, missing dependencies and blocked connection attempts that only show up at runtime. Every
finding comes with a fix hint, and the agent applies the fixes.

## Install

```bash
pip install pydantic-ai-agent-network-access-probe
```

Requires Python 3.10 or later and `pydantic-ai-slim` 2.0 or later.

## Use

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

The capability adds one tool, `probe_scan(path='.', entrypoints=None, allow_write_tools=False)`, which returns
a readiness score (0 to 100), the draft network allow list and findings worst-first, each with a fix hint.
Probe does not change the code. It writes `probe.findings.json`, `network_policies.draft.yaml`,
`probe.profile.json` and `autofix-attestation.json` into the scanned directory, so the workspace must be
writable.

| Input | Meaning |
|---|---|
| `path` | Directory with the tool code, relative to the workspace. |
| `entrypoints` | Entry point files inside the directory, such as `['tool.py']`. Default: Probe finds them. |
| `allow_write_tools` | Also run tools that look destructive (network writes, deletes, payments) in the sandbox. The instructions tell the agent to set it only when you ask. |

| Option | Default | Meaning |
|---|---|---|
| `command` | `None` | Probe (`autofix`) binary to run. `None` downloads the pinned release. |
| `probe_version` | `0.5.0` | Probe release to download. Must be `0.2.3` or later. |
| `sandbox` | `None` | `'docker'` or `'openshell'` to also run the tool in a network-blocked sandbox. The runner must be ready where the workspace runs. `None` is static analysis only. |
| `timeout` | `600` | Seconds for one scan. A first sandbox run also pulls the images. |
| `guidance` | `None` | Replaces the default instructions. `''` adds none. |

## How it runs

The tool runs Probe inside the agent's workspace. It downloads the pinned
[Probe release](https://github.com/trustabl/agent-network-access-probe/releases), checks it against the
release's `checksums.txt` (a mismatch is a hard failure and nothing is executed) and caches it in
`~/.trustabl-probe/`, the same folder the Probe MCP server uses. A sandboxed workspace cannot see that host
path: add the `autofix` binary to the sandbox image and pass its path as `command`.

No model call, no API key and no telemetry. Your code is analyzed where the workspace runs and is never
uploaded; attestation signing is off, so nothing goes to a transparency log. With the sandbox on, Probe pulls
the sandbox images from Docker Hub and, for a Python tool that declares dependencies, installs them from PyPI
before the run.

## Related

- [agent-network-access-probe](https://github.com/trustabl/agent-network-access-probe): Probe itself, and the
  same scan as an MCP server for Claude Code, Cursor and other MCP clients.
- [pydantic-ai-agent-reliability-skills](https://github.com/trustabl/pydantic-ai-agent-reliability-skills):
  generate a pre-coding reliability skill for an agent repository with Trustabl Forge.
- [pydantic-ai-trustabl](https://github.com/trustabl/pydantic-ai-tool): scan an agent repository for
  reliability and safety weaknesses.

License: Apache-2.0.
