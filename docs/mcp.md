# GraphSentinel MCP Server

GraphSentinel exposes its own restricted MCP server using the official Model Context Protocol Python SDK `mcp==2.3.0`. The SDK's `MCPServer.tool` registration, `run(transport="stdio")`, and `Client` APIs were verified against that installed version. Python 3.11 or later is required.

## Start the server

Start FalkorDB and load the synthetic graph as described in the [README](../README.md), then launch from the repository root:

```sh
./.venv/bin/python -m graphsentinel.mcp_server
```

The server uses MCP stdio transport. It does not print application output to stdout while running, because stdout is the protocol stream. The MCP SDK's `Client` can be used in-process in tests; the server process can also be launched by a local MCP host.

## Tools

| Tool | Inputs | Purpose |
| --- | --- | --- |
| `get_alert_context` | `alert_id`, optional `limit` (1-200) | Read an alert and immediate outgoing graph context. |
| `trace_attack_paths` | `alert_id`, optional `max_depth` (1-6), `limit` (1-200) | Return bounded, directed graph paths. A path is a possible route, not proof of compromise. |
| `get_service_impact` | `service_id`, optional `max_depth` (1-6), `limit` (1-200) | Read downstream dependencies and upstream dependents. |
| `get_evidence` | `evidence_ids` (1-50), optional `limit` (1-200) | Read evidence records with sources, timestamps, polarity, linked nodes, and relationships. |
| `get_incident_memory` | `alert_id`, optional `limit` (1-200) | Read matching historical incidents and persisted investigation episodes. Matches state whether they came from shared entities or matching event types; similarity is contextual, not proof of the same attack. |

All tools call the existing `GraphRepository` through its read-only mode, which dispatches queries to FalkorDB's `GRAPH.RO_QUERY`. Inputs are typed, schema-constrained, validated again by Pydantic, and constrained by runtime configuration. Responses use structured Pydantic output. Missing records return empty data or an explicit tool error; no synthetic facts are invented.

There is deliberately no arbitrary Cypher, graph-write, reset, approval, execution, or verification tool. Consequential simulated actions remain in the separately authorized FastAPI response-action endpoints.

## MCP host configuration

Use the workspace's virtual environment and set `PYTHONPATH` so the module is importable regardless of the host process working directory. Replace the absolute paths with this checkout's paths. For a Claude Desktop-compatible stdio configuration:

```json
{
  "mcpServers": {
    "graphsentinel": {
      "command": "/absolute/path/to/GraphSentinel/.venv/bin/python",
      "args": ["-m", "graphsentinel.mcp_server"],
      "env": {
        "PYTHONPATH": "/absolute/path/to/GraphSentinel",
        "FALKORDB_HOST": "127.0.0.1",
        "FALKORDB_PORT": "6380",
        "FALKORDB_GRAPH": "graphsentinel"
      }
    }
  }
}
```

If this checkout uses the default FalkorDB port, configure `FALKORDB_PORT` as `6379`. If using another MCP host, configure the equivalent stdio command/arguments/environment fields. Do not add `OPENAI_API_KEY` to the MCP configuration: the MCP tools do not call the LLM.

## Verification

```sh
./.venv/bin/python -m pytest tests/test_mcp_server.py -q
```

The tests use the official MCP SDK `Client` with both an in-process server and a launched stdio subprocess, list the registered tools, invoke every tool against the live FalkorDB graph, inspect structured results, check generated bounds, and verify read-only state preservation.

## FalkorDB's official MCP server

FalkorDB also publishes [FalkorDB-MCPServer](https://github.com/FalkorDB/FalkorDB-MCPServer). Its current documentation describes query tools as well as graph data management and graph deletion tools, and offers a read-only mode for query tools. GraphSentinel needs a fixed application-specific read-only contract, so this project implements its own thin MCP adapter over the existing repository rather than exposing that server's broader tool surface. This is not a claim of wire-level integration with the FalkorDB server implementation.