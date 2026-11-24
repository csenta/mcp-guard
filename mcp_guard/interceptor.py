"""
JSON-RPC 2.0 Interceptor and Security Proxy for Model Context Protocol (MCP).
"""

import json
import logging
import sys
from typing import Any
from mcp_guard.policy import PolicyEngine, Verdict

logger = logging.getLogger("mcp_guard")


class MCPInterceptor:
    def __init__(self, policy_engine: PolicyEngine):
        self.engine = policy_engine

    def process_message(self, raw_line: str) -> tuple[str | None, Verdict]:
        """
        Parses and evaluates a raw JSON-RPC line.
        Returns (response_json_string_or_None, Verdict).
        If Verdict.allowed is False, returns a JSON-RPC 2.0 error response.
        """
        raw_line = raw_line.strip()
        if not raw_line:
            return None, Verdict(allowed=True)

        try:
            msg = json.loads(raw_line)
        except json.JSONDecodeError:
            # If not valid JSON, pass through or return parse error
            return None, Verdict(allowed=True)

        if not isinstance(msg, dict):
            return None, Verdict(allowed=True)

        # Check if message is a tools/call request
        method = msg.get("method")
        msg_id = msg.get("id")

        if method == "tools/call" or method == "call_tool":
            params = msg.get("params", {})
            tool_name = params.get("name") or params.get("tool") or "unknown"
            arguments = params.get("arguments") or {}

            verdict = self.engine.evaluate_tool_call(tool_name, arguments)

            if not verdict.allowed:
                error_response = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32001,
                        "message": f"MCP-Guard Security Violation: {verdict.reason}",
                        "data": {
                            "rule": verdict.rule,
                            "tool": tool_name,
                        },
                    },
                }
                return json.dumps(error_response), verdict

            return None, verdict

        return None, Verdict(allowed=True)
