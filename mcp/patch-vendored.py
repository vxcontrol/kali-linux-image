#!/usr/bin/env python3
"""Apply small compatibility fixes to the pinned upstream MCP servers.

The upstream commits are immutable, so every replacement is deliberately exact
and fails the image build if those sources drift. This keeps runtime logs clean
without hiding warnings globally and fixes bugs that affect real tool calls.
"""

from pathlib import Path


ROOT = Path("/opt/kali-mcp/servers")


def replace_exact(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(
            f"{path}: expected exactly one {label} block, found {count}; "
            "the pinned upstream source has drifted"
        )
    path.write_text(text.replace(old, new), encoding="utf-8")


def modernize_settings(relative_path: str, env_prefix: str) -> None:
    path = ROOT / "security-hub" / relative_path / "server.py"
    replace_exact(
        path,
        "from pydantic_settings import BaseSettings",
        "from pydantic_settings import BaseSettings, SettingsConfigDict",
        "BaseSettings import",
    )
    replace_exact(
        path,
        f"    class Config:\n        env_prefix = \"{env_prefix}\"\n",
        f"    model_config = SettingsConfigDict(env_prefix=\"{env_prefix}\")\n",
        "legacy Pydantic settings config",
    )


def main() -> None:
    # These are the security-hub servers actually exposed by gateway.yaml.
    # Their class-based config works today but emits a warning on every MCP
    # session and is removed by Pydantic 3.
    for relative_path, env_prefix in (
        ("reconnaissance/nmap-mcp", "NMAP_"),
        ("reconnaissance/masscan-mcp", "MASSCAN_"),
        ("reconnaissance/whatweb-mcp", "WHATWEB_"),
        ("web-security/nuclei-mcp", "NUCLEI_"),
        ("web-security/sqlmap-mcp", "SQLMAP_"),
        ("web-security/ffuf-mcp", "FFUF_"),
        ("exploitation/searchsploit-mcp", "SEARCHSPLOIT_"),
        ("binary-analysis/binwalk-mcp", "BINWALK_"),
    ):
        modernize_settings(relative_path, env_prefix)

    hashcat = ROOT / "hashcat-mcp" / "hashcat_mcp_server.py"
    replace_exact(
        hashcat,
        "                os.unlink(safe_filename)\n",
        "                os.unlink(os.path.join(HASHCAT_DIR, safe_filename))\n",
        "Hashcat identify temporary-file cleanup",
    )

    nmap = (
        ROOT
        / "security-hub"
        / "reconnaissance"
        / "nmap-mcp"
        / "server.py"
    )
    replace_exact(
        nmap,
        '                    "service": p.get("service", {}).get("name"),\n'
        '                    "version": p.get("service", {}).get("version"),\n',
        '                    "service": (p.get("service") or {}).get("name"),\n'
        '                    "version": (p.get("service") or {}).get("version"),\n',
        "Nmap optional service formatter",
    )
    replace_exact(
        nmap,
        '                if p.get("state", {}).get("state") == "open"\n',
        '                if (p.get("state") or {}).get("state") == "open"\n',
        "Nmap optional state formatter",
    )
    replace_exact(
        nmap,
        """    except asyncio.TimeoutError:
        result.status = "timeout"
        result.error = f"Scan timed out after {timeout or settings.default_timeout} seconds"
        result.completed_at = datetime.now()
        logger.error(f"Scan {scan_id} timed out")
""",
        """    except asyncio.TimeoutError:
        # asyncio.wait_for cancels communicate(), not the child process. Without
        # this, a timed-out scan keeps running and can continue probing the
        # target after the MCP call has returned.
        process.kill()
        await process.wait()
        result.status = "timeout"
        result.error = f"Scan timed out after {timeout or settings.default_timeout} seconds"
        result.completed_at = datetime.now()
        logger.error(f"Scan {scan_id} timed out")
""",
        "Nmap timeout handler",
    )

    masscan = (
        ROOT
        / "security-hub"
        / "reconnaissance"
        / "masscan-mcp"
        / "server.py"
    )
    replace_exact(
        masscan,
        '        "--rate", str(rate or settings.default_rate),\n'
        '        "-oJ", str(output_file),\n',
        '        "--rate", str(rate or settings.default_rate),\n'
        '        "--wait", "0",\n'
        '        "-oJ", str(output_file),\n',
        "Masscan post-scan wait",
    )
    replace_exact(
        masscan,
        """    except asyncio.TimeoutError:
        result.status = "timeout"
        result.error = f"Scan timed out"
        result.completed_at = datetime.now()
""",
        """    except asyncio.TimeoutError:
        # Do not leave a raw-socket scanner running after its MCP deadline.
        process.kill()
        await process.wait()
        result.status = "timeout"
        result.error = "Scan timed out"
        result.completed_at = datetime.now()
""",
        "Masscan timeout handler",
    )

    nuclei = (
        ROOT
        / "security-hub"
        / "web-security"
        / "nuclei-mcp"
        / "server.py"
    )
    replace_exact(
        nuclei,
        "        if process.returncode == 0 or len(result.findings) >= 0:\n",
        "        if process.returncode == 0:\n",
        "Nuclei always-true success condition",
    )
    replace_exact(
        nuclei,
        "    templates: list[str] | None = None,\n"
        "    tags: list[str] | None = None,\n",
        "    templates: list[str] | None = None,\n"
        "    template_paths: list[str] | None = None,\n"
        "    tags: list[str] | None = None,\n",
        "Nuclei explicit template-path argument",
    )
    replace_exact(
        nuclei,
        """    # Add templates path if exists
    if Path(settings.templates_dir).exists():
        cmd.extend(["-templates", settings.templates_dir])
""",
        """    # An explicit file avoids loading the entire template tree for a
    # targeted scan. Otherwise preserve upstream's category/tag behavior.
    if template_paths:
        for template_path in template_paths:
            cmd.extend(["-templates", template_path])
    elif Path(settings.templates_dir).exists():
        cmd.extend(["-templates", settings.templates_dir])
""",
        "Nuclei explicit template selection",
    )
    replace_exact(
        nuclei,
        '        "-rate-limit", str(rate_limit or settings.rate_limit),\n'
        '        "-silent",\n',
        '        "-rate-limit", str(rate_limit or settings.rate_limit),\n'
        '        "-silent",\n'
        '        "-disable-update-check",\n'
        '        "-no-interactsh",\n'
        '        "-no-stdin",\n',
        "Nuclei deterministic non-interactive flags and closed stdin",
    )
    replace_exact(
        nuclei,
        '''                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Filter by template tags (e.g., cve, rce, xss, sqli)",
                    },
''',
        '''                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Filter by template tags (e.g., cve, rce, xss, sqli)",
                    },
                    "template_paths": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Explicit template file paths for a targeted scan",
                    },
''',
        "Nuclei tool schema template paths",
    )
    replace_exact(
        nuclei,
        '                severity=arguments.get("severity"),\n'
        '                tags=arguments.get("tags"),\n',
        '                severity=arguments.get("severity"),\n'
        '                template_paths=arguments.get("template_paths"),\n'
        '                tags=arguments.get("tags"),\n',
        "Nuclei handler template paths",
    )
    replace_exact(
        nuclei,
        """    except asyncio.TimeoutError:
        result.status = "timeout"
        result.error = f"Scan timed out after {timeout or settings.default_timeout} seconds"
        result.completed_at = datetime.now()
        logger.error(f"Scan {scan_id} timed out")
""",
        """    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        result.status = "timeout"
        result.error = f"Scan timed out after {timeout or settings.default_timeout} seconds"
        result.completed_at = datetime.now()
        logger.error(f"Scan {scan_id} timed out")
""",
        "Nuclei timeout handler",
    )

    print("kali-mcp: patched pinned MCP sources")


if __name__ == "__main__":
    main()
