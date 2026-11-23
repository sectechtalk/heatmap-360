# HeatMap 360 MCP server

`mcp/server.mjs` lets an AI assistant (Claude Desktop, Claude Code or any other MCP client) read HeatMap 360's data
through the [Model Context Protocol](https://modelcontextprotocol.io). Ask things like "which scans have exploited
software?", "anything critical on High impact today?" or "Critical CVEs from Cloudflare Radar in the last 8 hours that
CISA says are exploited".

## How it works

* The assistant starts `node mcp/server.mjs` on your own computer and talks to it over stdio. Nothing is hosted and
  nothing listens on a port, so it costs nothing.
* The MCP server reads the **local** HeatMap copy over HTTP (default `http://localhost:3460`, the Docker container from
  `compose.yaml`) using the same page APIs the browser uses. HeatMap must be running.
* **Read only.** Every tool is a GET. It never uploads, changes settings, or posts anywhere.
* **Gated.** It holds no sign-in, token or secret, and accepts only a loopback address (`localhost`, `127.0.0.1`,
  `[::1]`) in `HM360_URL`. It works only against a local copy in dev-admin mode. A copy that needs Entra sign-in answers
  401/403 and the tool says so, so the PIM gate on the hosted app stays shut.
* No dependencies: plain Node 22.
* Feed headlines and posts are third-party text. The server tells the assistant to treat them as data, not instructions.

## Tools

| Tool | What it returns |
|---|---|
| `heatmap_list_scans` | Processed scans (newest 200) with computer model, Windows build, grades and counts, plus queued uploads |
| `heatmap_get_scan` | One scan's results; pick `sections` (summary, windows, knownIssues, apps, appIssues, health, exploited, eventLog, network, networkHealth, firmware, hardware, inventory) |
| `heatmap_high_impact` | The High impact list with reasons, sources and rules |
| `heatmap_service_health` | Status and active incidents of the online services |
| `heatmap_news` | Internet - Cloud Services / Exploits / Patches headlines, filtered by `hours`, `search`, `sources` |
| `heatmap_cloudflare_cves` | Cloudflare Radar CVEs filtered by `severity`, `knownExploitedOnly`, `hours`, `search`, `limit` |
| `heatmap_bluesky` | Posts from the official vendor accounts, filtered by `hours`, `search`, `company`, `limit` |
| `heatmap_bluesky_replies` | Replies to one listed account's post |

`hours` defaults to 168 (7 days), like the pages.

## Add it to your assistant

Claude Code: open Claude Code in the heatmap-360 folder. The repo's `.mcp.json` offers the server; approve it once.
To have it everywhere instead:

```powershell
claude mcp add --scope user heatmap-360 -- node C:\src\heatmap-360\mcp\server.mjs
```

Claude Desktop (Windows): add this to `%APPDATA%\Claude\claude_desktop_config.json`, then restart Claude Desktop.

```json
{
  "mcpServers": {
    "heatmap-360": { "command": "node", "args": ["C:\\src\\heatmap-360\\mcp\\server.mjs"] }
  }
}
```

Set `HM360_URL` in `env` only if the local copy runs on another port.
