"""
Policy engine for MCP-Guard.
Evaluates tool calls, paths, commands, and network targets against defined security rules.
"""

import os
import re
from dataclasses import dataclass
from typing import Any
import yaml


@dataclass
class Verdict:
    allowed: bool
    reason: str = ""
    rule: str = ""


class PolicyEngine:
    def __init__(self, policy_path: str | None = None):
        self.rules: dict[str, Any] = {}
        self.mode: str = "enforce"
        if policy_path and os.path.isfile(policy_path):
            self.load_policy(policy_path)

    def load_policy(self, path: str):
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        self.mode = data.get("mode", "enforce")
        self.rules = data.get("rules", {})

    def evaluate_tool_call(self, tool_name: str, arguments: dict[str, Any]) -> Verdict:
        """
        Inspects an incoming tool call and its arguments.
        """
        norm_tool = tool_name.lower()

        # 1. File Access Inspection (read_file, write_file, edit_file, delete_file, cat, etc.)
        if any(kw in norm_tool for kw in ("file", "read", "write", "edit", "path", "delete")):
            path_val = (
                arguments.get("path")
                or arguments.get("Path")
                or arguments.get("file_path")
                or arguments.get("filepath")
                or ""
            )
            if isinstance(path_val, str) and path_val:
                v = self._check_file_access(path_val)
                if not v.allowed:
                    return v

        # 2. Command Execution Inspection (run_command, bash, execute_command, terminal, sh)
        if any(kw in norm_tool for kw in ("command", "bash", "sh", "exec", "terminal", "shell", "cmd")):
            cmd_val = (
                arguments.get("command")
                or arguments.get("CommandLine")
                or arguments.get("cmd")
                or arguments.get("script")
                or ""
            )
            if isinstance(cmd_val, str) and cmd_val:
                v = self._check_command_execution(cmd_val)
                if not v.allowed:
                    return v

        # 3. Network Egress / HTTP Requests Inspection
        if any(kw in norm_tool for kw in ("http", "fetch", "request", "curl", "url", "web")):
            url_val = arguments.get("url") or arguments.get("Url") or arguments.get("endpoint") or ""
            if isinstance(url_val, str) and url_val:
                v = self._check_network_egress(url_val)
                if not v.allowed:
                    return v

        # Also inspect general string arguments for embedded command/file injection
        for k, val in arguments.items():
            if isinstance(val, str) and len(val) < 2048:
                if "command" in k.lower():
                    v = self._check_command_execution(val)
                    if not v.allowed:
                        return v
                elif "path" in k.lower() or "file" in k.lower():
                    v = self._check_file_access(val)
                    if not v.allowed:
                        return v

        return Verdict(allowed=True, reason="Call verified against security policy.")

    def _check_file_access(self, target_path: str) -> Verdict:
        deny_patterns = self.rules.get("file_access", {}).get("deny_patterns", [])
        for pattern in deny_patterns:
            if re.search(pattern, target_path, re.IGNORECASE):
                return Verdict(
                    allowed=False,
                    reason=f"Access to protected path '{target_path}' is denied by rule.",
                    rule=f"file_access:{pattern}",
                )
        return Verdict(allowed=True)

    def _check_command_execution(self, command_str: str) -> Verdict:
        deny_patterns = self.rules.get("command_execution", {}).get("deny_patterns", [])
        for pattern in deny_patterns:
            if re.search(pattern, command_str, re.IGNORECASE):
                return Verdict(
                    allowed=False,
                    reason=f"Execution of dangerous command pattern matched: '{pattern}'.",
                    rule=f"command_execution:{pattern}",
                )
        return Verdict(allowed=True)

    def _check_network_egress(self, target_url: str) -> Verdict:
        blocked_hosts = self.rules.get("network_egress", {}).get("blocked_hosts", [])
        for host in blocked_hosts:
            if host in target_url:
                return Verdict(
                    allowed=False,
                    reason=f"Network egress to restricted host '{host}' is blocked (SSRF / Cloud Metadata protection).",
                    rule=f"network_egress:{host}",
                )
        return Verdict(allowed=True)
