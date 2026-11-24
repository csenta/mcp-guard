#!/usr/bin/env python3
"""
CLI for MCP-Guard: Security Firewall & Proxy for Model Context Protocol.
"""

import argparse
import json
import os
import subprocess
import sys
import threading
from mcp_guard.policy import PolicyEngine
from mcp_guard.interceptor import MCPInterceptor


def find_default_policy() -> str:
    pkg_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    default_path = os.path.join(pkg_dir, "policies", "default_policy.yaml")
    return default_path if os.path.exists(default_path) else ""


def test_tool_call(engine: PolicyEngine, tool: str, args_json: str):
    try:
        arguments = json.loads(args_json)
    except json.JSONDecodeError:
        print(f"[!] Invalid JSON passed to --args: {args_json}")
        sys.exit(1)

    print(f"[*] Inspecting Tool Call: '{tool}' with arguments: {arguments}")
    verdict = engine.evaluate_tool_call(tool, arguments)

    if verdict.allowed:
        print("[+] VERDICT: ALLOWED")
        print(f"    Details: {verdict.reason}")
    else:
        print("[-] VERDICT: BLOCKED (Security Violation)")
        print(f"    Reason: {verdict.reason}")
        print(f"    Rule:   {verdict.rule}")


def run_stdio_proxy(policy_path: str, server_cmd: list[str]):
    """
    Spawns the target MCP server subprocess and intercepts stdin/stdout streams.
    """
    engine = PolicyEngine(policy_path)
    interceptor = MCPInterceptor(engine)

    print(f"[*] MCP-Guard starting in proxy mode...", file=sys.stderr)
    print(f"[*] Policy loaded: {policy_path}", file=sys.stderr)
    print(f"[*] Target MCP Server: {' '.join(server_cmd)}", file=sys.stderr)

    proc = subprocess.Popen(
        server_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
        bufsize=1,
    )

    def relay_stdout():
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()

    t = threading.Thread(target=relay_stdout, daemon=True)
    t.start()

    try:
        for line in sys.stdin:
            blocked_response, verdict = interceptor.process_message(line)
            if blocked_response:
                # Security violation: respond immediately to client without forwarding to server
                sys.stdout.write(blocked_response + "\n")
                sys.stdout.flush()
                print(f"[!] MCP-Guard blocked violation: {verdict.reason}", file=sys.stderr)
            else:
                # Allowed: forward directly to server stdin
                if proc.stdin and not proc.stdin.closed:
                    proc.stdin.write(line)
                    proc.stdin.flush()
    except (KeyboardInterrupt, BrokenPipeError):
        pass
    finally:
        proc.terminate()


def main():
    parser = argparse.ArgumentParser(
        description="MCP-Guard: Security Firewall & Proxy for Model Context Protocol"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: test
    test_parser = subparsers.add_parser("test", help="Test a single tool call against the security policy")
    test_parser.add_argument("--tool", required=True, help="Tool name (e.g. read_file, run_command)")
    test_parser.add_argument("--args", required=True, help='JSON formatted arguments (e.g. \'{"path":"/etc/passwd"}\')')
    test_parser.add_argument("--policy", default=find_default_policy(), help="Path to policy YAML")

    # Subcommand: proxy
    proxy_parser = subparsers.add_parser("proxy", help="Run as transparent stdio proxy wrapping an MCP server")
    proxy_parser.add_argument("--policy", default=find_default_policy(), help="Path to policy YAML")
    proxy_parser.add_argument("server_cmd", nargs=argparse.REMAINDER, help="MCP Server command and arguments")

    args = parser.parse_args()

    if args.command == "test":
        engine = PolicyEngine(args.policy)
        test_tool_call(engine, args.tool, args.args)
    elif args.command == "proxy":
        if not args.server_cmd:
            print("[!] Error: You must specify the MCP server command to run.")
            sys.exit(1)
        # Strip leading '--' if passed
        cmd = args.server_cmd[1:] if args.server_cmd[0] == "--" else args.server_cmd
        run_stdio_proxy(args.policy, cmd)


if __name__ == "__main__":
    main()
