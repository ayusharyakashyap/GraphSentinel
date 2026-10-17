"""Integration tests for the official MCP SDK server/client and live graph tools."""

import asyncio
import os
import sys
from pathlib import Path

import pytest
from mcp import Client
from mcp.client.stdio import StdioServerParameters

from graphsentinel.mcp_server import create_mcp_server
from graphsentinel.repository import GraphRepository
from graphsentinel.seed import connect_graph, load_fixture, seed_graph

EXPECTED_TOOLS = {
    "get_alert_context",
    "trace_attack_paths",
    "get_service_impact",
    "get_evidence",
    "get_incident_memory",
}


@pytest.fixture
def mcp_server():
    seed_graph(connect_graph(), load_fixture())
    return create_mcp_server(GraphRepository(connect_graph()))


def test_official_mcp_client_lists_and_invokes_read_only_tools(mcp_server) -> None:
    async def exercise_client() -> None:
        async with Client(mcp_server, raise_exceptions=True) as client:
            listed = await client.list_tools()
            tools = {tool.name: tool for tool in listed.tools}
            assert set(tools) == EXPECTED_TOOLS
            assert all(
                "query" not in tool.input_schema["properties"]
                and "cypher" not in tool.input_schema["properties"]
                for tool in listed.tools
            )
            assert "maximum" in tools["trace_attack_paths"].input_schema["properties"]["max_depth"]

            context = await client.call_tool(
                "get_alert_context",
                {"alert_id": "alert-2026-1015-001"},
            )
            paths = await client.call_tool(
                "trace_attack_paths",
                {"alert_id": "alert-2026-1015-001", "max_depth": 5, "limit": 40},
            )
            impact = await client.call_tool(
                "get_service_impact",
                {"service_id": "svc-deploy", "max_depth": 4},
            )
            evidence = await client.call_tool(
                "get_evidence",
                {"evidence_ids": ["ev-geo-ava"]},
            )
            memory = await client.call_tool(
                "get_incident_memory",
                {"alert_id": "alert-2026-1015-001"},
            )

            assert all(not result.is_error for result in (context, paths, impact, evidence, memory))
            assert context.structured_content["alert"]["id"] == "alert-2026-1015-001"
            assert len(paths.structured_content["paths"]) > 0
            assert "svc-artifact" in {
                node["id"] for node in impact.structured_content["dependencies"]
            }
            assert evidence.structured_content["records"][0]["evidence"]["id"] == "ev-geo-ava"
            assert "not proof" in memory.structured_content["matching_basis"]

    asyncio.run(exercise_client())


def test_mcp_rejects_out_of_bounds_input_and_exposes_no_mutation_tools(mcp_server) -> None:
    async def exercise_client() -> None:
        async with Client(mcp_server, raise_exceptions=True) as client:
            listed = await client.list_tools()
            names = {tool.name for tool in listed.tools}
            assert not names.intersection({"approve_response_action", "execute_response_action", "run_cypher"})
            result = await client.call_tool(
                "trace_attack_paths",
                {"alert_id": "alert-2026-1015-001", "max_depth": 99},
            )
            assert result.is_error

    asyncio.run(exercise_client())


def test_mcp_tools_do_not_mutate_security_state(mcp_server) -> None:
    repository = GraphRepository(connect_graph())
    before = repository.get_node("Identity", "id-ava-chen")
    assert before is not None

    async def exercise_client() -> None:
        async with Client(mcp_server, raise_exceptions=True) as client:
            await client.call_tool("get_alert_context", {"alert_id": "alert-2026-1015-001"})
            await client.call_tool(
                "trace_attack_paths",
                {"alert_id": "alert-2026-1015-001", "max_depth": 5},
            )
            await client.call_tool("get_service_impact", {"service_id": "svc-deploy"})
            await client.call_tool("get_evidence", {"evidence_ids": ["ev-geo-ava"]})
            await client.call_tool("get_incident_memory", {"alert_id": "alert-2026-1015-001"})

    asyncio.run(exercise_client())
    after = GraphRepository(connect_graph()).get_node("Identity", "id-ava-chen")
    assert after == before


def test_stdio_host_can_launch_server_and_call_tool() -> None:
    workspace_root = Path(__file__).resolve().parents[1]
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "graphsentinel.mcp_server"],
        cwd=workspace_root,
        env={**os.environ, "PYTHONPATH": str(workspace_root)},
    )

    async def exercise_subprocess_client() -> None:
        async with Client(parameters, raise_exceptions=True) as client:
            listed = await client.list_tools()
            assert {tool.name for tool in listed.tools} == EXPECTED_TOOLS
            result = await client.call_tool(
                "get_alert_context",
                {"alert_id": "alert-2026-1015-001"},
            )
            assert not result.is_error
            assert result.structured_content["alert"]["id"] == "alert-2026-1015-001"

    asyncio.run(exercise_subprocess_client())