from core import vectors
from core.utils import run_command
from core.printer import (
    print_section,
    print_critical,
    print_high,
    print_info,
    print_not_found
)

VECTOR_NAME = "Port Forwarding"

DANGEROUS_TOOLS = [
    "ssh",
    "socat",
    "nc",
    "ncat",
    "netcat",
    "chisel"
]


def run() -> list:
    print_section(VECTOR_NAME)

    results = []

    port_results = _check_listening_ports()
    tool_results = _check_port_forwarding_tools()

    results += port_results
    results += tool_results

    # Critical scenario
    localhost_found = any(
        r["vector"] == vectors.LOCALHOST_SERVICES
        for r in port_results
    )

    tools_found = any(
        r["vector"] == vectors.FORWARDING_TOOLS
        for r in tool_results
    )

    if localhost_found and tools_found:
        print_critical(
            "Port Forwarding Opportunity Detected",
            {
                "Risk": (
                    "Localhost-only services exist and tunneling tools "
                    "are installed. Internal services may be accessible "
                    "through port forwarding."
                ),
                "Next Step": [
                    "Review localhost services carefully",
                    "Check whether SSH, socat or chisel can be used for tunneling"
                ],
                "Reference":
                    "https://book.hacktricks.xyz/generic-methodologies-and-resources/tunneling-and-port-forwarding"
            }
        )

        results.append({
            "vector": "Port Forwarding Opportunity",
            "severity": "CRITICAL",
            "count": 1
        })

    if not results:
        print_not_found("Port Forwarding", {
            "Checked": "Listening ports and forwarding tools",
            "Result": "No interesting port forwarding opportunities found"
        })

        return [{
            "vector": "Port Forwarding",
            "severity": "CLEAN",
            "count": 0
        }]

    return results


# ─────────────────────────────────────────────
# Listening Ports
# ─────────────────────────────────────────────

def _check_listening_ports() -> list:
    raw = run_command(
        "ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null || netstat -plant 2>/dev/null" 
    )

    if not raw:
        return []

    lines = [
        line.strip()
        for line in raw.splitlines()
        if "LISTEN" in line.upper()
    ]

    if not lines:
        return []

    localhost_ports = []

    for line in lines:
        if (
            "127.0.0.1:" in line or
            "127.0.1.1:" in line or
            "::1:" in line or
            "[::1]:" in line or
            "localhost" in line.lower()
        ):
            localhost_ports.append(line)

    if localhost_ports:
        print_high("Localhost-Only Services Found", {
            "Ports": localhost_ports,
            "Risk": "Internal services may be reachable through port forwarding",
            "Next Step": "Review these services manually",
            "Reference": "https://book.hacktricks.xyz/generic-methodologies-and-resources/tunneling-and-port-forwarding"
        })

        return [{
            "vector": "Localhost Services",
            "severity": "HIGH",
            "count": len(localhost_ports)
        }]

    print_info("Listening Services Found", {
        "Ports": lines,
        "Result": "No localhost-only services detected"
    })

    return [{
        "vector": "Listening Services",
        "severity": "INFO",
        "count": len(lines)
    }]


# ─────────────────────────────────────────────
# Port Forwarding Tools
# ─────────────────────────────────────────────

def _check_port_forwarding_tools() -> list:
    found = set()

    for tool in DANGEROUS_TOOLS:
        path = run_command(f"command -v {tool} 2>/dev/null")

        if path:
            found.add(path.strip())

    if not found:
        return []

    print_info("Port Forwarding Tools Installed", {
        "Tools": sorted(found),
        "Result": "These tools may be useful during post-exploitation",
        "Reference": "https://book.hacktricks.xyz/generic-methodologies-and-resources/tunneling-and-port-forwarding"
    })

    return [{
        "vector": "Forwarding Tools",
        "severity": "INFO",
        "count": len(found)
    }]