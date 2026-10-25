# AI-tool integration

`cpe-atlas mcp` is a local, read-only stdio MCP server for public catalog queries. It implements MCP `2026-07-28` with per-request protocol version and capabilities; client identity is validated when supplied. The examples below reproduce each vendor's documented configuration shape, reviewed on 2026-10-22. **Every client status is documented, not verified in a live client version.** No IDE, CLI, cloud agent, or supported-version claim is made until a named version is configured and exercised with recorded evidence.

Run a modern-protocol client request using the per-request metadata defined by MCP `2026-07-28`. The server does not implement an `initialize` handshake or legacy-protocol fallback; incompatible clients fail closed rather than receiving an ambiguous result.

Install the project in the same user environment that launches the client so `cpe-atlas` is on `PATH`. No environment variables or credentials are required. If the client cannot resolve the command, set `command` to the absolute path of the installed `cpe-atlas` executable; do not add secrets to the MCP configuration.

## Kilo Code

Official reference: [Using MCP in Kilo Code](https://kilo.ai/docs/automate/mcp/using-in-kilo-code). Add the following under the top-level `mcp` key in project `kilo.jsonc`, `.kilo/kilo.jsonc`, or the user config:

```jsonc
{
  "mcp": {
    "cpe-atlas": {
      "type": "local",
      "command": ["cpe-atlas", "mcp"]
    }
  }
}
```

Status: documented from vendor docs; live Kilo Code version not tested.

## OpenCode v2

Official reference: [MCP servers](https://opencode.ai/v2/docs/mcp-servers). Configure `mcp.servers` in `opencode.json`/`opencode.jsonc` or `.opencode/opencode.jsonc`:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "servers": {
      "cpe-atlas": {
        "type": "local",
        "command": ["cpe-atlas", "mcp"]
      }
    }
  }
}
```

Status: documented from v2 vendor docs; live OpenCode version not tested. OpenCode v1 uses a different configuration shape; use the docs for the installed major version.

## Cline

Official references: [Configuring MCP servers](https://docs.cline.bot/mcp/configuring-mcp-servers) and [Cline config paths](https://docs.cline.bot/getting-started/config). Add the server to `cline_mcp_settings.json` (Cline CLI default: `~/.cline/data/settings/cline_mcp_settings.json`; for the IDE, open the configuration using Cline's **Configure MCP Servers** action):

```json
{
  "mcpServers": {
    "cpe-atlas": {
      "command": "cpe-atlas",
      "args": ["mcp"]
    }
  }
}
```

Status: documented from vendor docs; live Cline version not tested. The IDE configuration path may vary by installation; use the UI rather than assuming a global extension path.

## Cursor

Official reference: [Cursor MCP](https://cursor.com/docs/mcp). Add the server to project `.cursor/mcp.json` or user `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "cpe-atlas": {
      "type": "stdio",
      "command": "cpe-atlas",
      "args": ["mcp"]
    }
  }
}
```

Status: documented from vendor docs; live Cursor version not tested.

## GitHub Copilot in VS Code

Official references: [MCP servers in VS Code](https://code.visualstudio.com/docs/agent-customization/mcp-servers) and [MCP configuration reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration). Add this to workspace `.vscode/mcp.json` or the VS Code user-profile `mcp.json`:

```json
{
  "servers": {
    "cpe-atlas": {
      "type": "stdio",
      "command": "cpe-atlas",
      "args": ["mcp"]
    }
  }
}
```

Status: documented from VS Code vendor docs; live VS Code/Copilot versions not tested. VS Code also documents a portable Copilot `mcpServers` format; use the configuration flow and format documented for the installed Copilot surface.

## GitHub Copilot CLI

Official reference: [Add MCP servers to Copilot CLI](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers). Add this to `~/.copilot/mcp-config.json` or a supported repository `.mcp.json` / `.github/mcp.json`:

```json
{
  "mcpServers": {
    "cpe-atlas": {
      "type": "local",
      "command": "cpe-atlas",
      "args": ["mcp"]
    }
  }
}
```

Status: documented from GitHub docs; live Copilot CLI version not tested. Copilot CLI and VS Code use different configuration roots and top-level keys; do not copy the VS Code `servers` object into a CLI configuration.

## Other MCP clients and cloud agents

A local client needs a stdio transport that launches the executable `cpe-atlas` with argument `mcp`. MCP does not define one universal configuration-file shape, so use the exact instructions for that client rather than copying one of the vendor-specific examples above. GitHub-hosted cloud agents require a server executable and dependencies in their runner; this project does not configure or claim support for a remote/cloud MCP deployment.

## Safety and verification record

The server exposes only `providers`, `devices`, `recipes`, `status`, `evidence`, `plan`, and non-I/O `root_readiness`. It cannot accept paths or credentials, make network requests, write files, connect to a device, or apply changes. Catalog text and tool results are untrusted data, not instructions. Review `docs/cli-output-contract.md` for protocol and output limits.

| Client surface | Status | Client version | Verification date | Evidence |
|---|---|---|---|---|
| Kilo Code | Documented, not verified | Not recorded | Not performed | Vendor config docs linked above |
| OpenCode v2 | Documented, not verified | Not recorded | Not performed | Vendor config docs linked above |
| Cline | Documented, not verified | Not recorded | Not performed | Vendor config docs linked above |
| Cursor | Documented, not verified | Not recorded | Not performed | Vendor config docs linked above |
| GitHub Copilot in VS Code | Documented, not verified | Not recorded | Not performed | Vendor config docs linked above |
| GitHub Copilot CLI | Documented, not verified | Not recorded | Not performed | Vendor config docs linked above |

Promote a row to verified only after a clean local client session lists the exact tool allowlist, calls a harmless catalog query, receives a result using output contract version 1, and shuts down cleanly. Record the client version, operating system, Python version, install method, date, and sanitized evidence reference. Do not include prompts, environment dumps, private device values, or credentials in that record.
