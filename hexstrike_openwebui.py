"""
title: HexStrike Nmap Scanner
author: HexStrike Team
version: 1.0.0
license: MIT
description: Nmap Port Scanner mit Live-Status
required_open_webui_version: 0.3.0
"""

from pydantic import BaseModel, Field
import requests
import time


class Tools:
    class Valves(BaseModel):
        hexstrike_api: str = Field(
            default="http://localhost:8888",
            description="HexStrike MCP Server URL"
        )
        default_timeout: int = Field(
            default=3600,
            description="Default timeout in seconds"
        )

    def __init__(self):
        self.valves = self.Valves()

    async def nmap_scan(
        self,
        target: str,
        scan_type: str = "-sV",
        ports: str = "",
        additional_args: str = "",
        __event_emitter__=None,
    ) -> str:
        """
        Execute an Nmap port scan against a target.

        Args:
            target: Target IP or hostname to scan
            scan_type: Nmap scan type (-sV, -sS, -sC, etc.)
            ports: Port specification (e.g., '80,443' or '1-1000')
            additional_args: Additional nmap arguments
        """

        # Status: Start
        if __event_emitter__:
            await __event_emitter__(
                {
                    "type": "status",
                    "data": {
                        "description": f"🚀 Nmap Scan wird gestartet für {target}...",
                        "done": False,
                    },
                }
            )

        # API Request
        try:
            session = requests.Session()
            session.headers.update({
                'Content-Type': 'application/json',
                'User-Agent': 'OpenWebUI-HexStrike/1.0'
            })

            url = f"{self.valves.hexstrike_api}/api/tools/nmap"
            payload = {
                "target": target,
                "scantype": scan_type,
                "ports": ports,
                "additionalargs": additional_args
            }

            start_time = time.time()

            # Status: Running
            if __event_emitter__:
                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {
                            "description": f"⏳ Nmap Scan läuft für {target}...",
                            "done": False,
                        },
                    }
                )

            response = session.post(url, json=payload, timeout=self.valves.default_timeout)
            response.raise_for_status()
            result = response.json()

            elapsed = time.time() - start_time

            # Status: Done
            if __event_emitter__:
                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {
                            "description": f"✅ Nmap Scan abgeschlossen ({int(elapsed)}s)",
                            "done": True,
                        },
                    }
                )

            # Format Output
            output = "═" * 60 + "\n"
            output += f"🔧 **TOOL:** Nmap Scanner\n"
            output += f"🎯 **TARGET:** {target}\n"
            output += f"⏱️ **LAUFZEIT:** {int(elapsed)}s ({elapsed/60:.1f} Min)\n"
            output += "═" * 60 + "\n\n"

            if result.get("success"):
                output += "✅ **STATUS:** Scan erfolgreich\n\n"

                if result.get("stdout"):
                    stdout = result["stdout"]
                    if len(stdout) > 6000:
                        output += f"📤 **OUTPUT:**\n```\n{stdout[:6000]}\n... (gekürzt, {len(stdout)} Zeichen gesamt)\n```\n"
                    else:
                        output += f"📤 **OUTPUT:**\n```\n{stdout}\n```\n"
            else:
                output += f"❌ **STATUS:** Fehler\n\n"
                output += f"🚫 **FEHLER:** {result.get('error', 'Unknown error')}\n"

                if result.get("stderr"):
                    stderr = result["stderr"][:1500]
                    output += f"\n📛 **ERROR OUTPUT:**\n```\n{stderr}\n```\n"

            output += "\n" + "═" * 60
            return output

        except requests.exceptions.Timeout:
            if __event_emitter__:
                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {
                            "description": "❌ Timeout - Scan dauerte zu lange",
                            "done": True,
                        },
                    }
                )
            return f"❌ **Timeout:** Scan dauerte länger als {self.valves.default_timeout}s"

        except Exception as e:
            if __event_emitter__:
                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {
                            "description": f"❌ Fehler: {str(e)}",
                            "done": True,
                        },
                    }
                )
            return f"❌ **Fehler:** {str(e)}"

    async def gobuster_scan(
        self,
        url: str,
        mode: str = "dir",
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        additional_args: str = "",
        __event_emitter__=None,
    ) -> str:
        """
        Gobuster Directory/DNS Fuzzing Scanner

        Args:
            url: Target URL
            mode: Mode (dir, dns, vhost, fuzz)
            wordlist: Path to wordlist file
            additional_args: Additional gobuster arguments
        """

        if __event_emitter__:
            await __event_emitter__(
                {
                    "type": "status",
                    "data": {
                        "description": f"🚀 Gobuster Scan wird gestartet...",
                        "done": False,
                    },
                }
            )

        try:
            session = requests.Session()
            session.headers.update({
                'Content-Type': 'application/json',
                'User-Agent': 'OpenWebUI-HexStrike/1.0'
            })

            api_url = f"{self.valves.hexstrike_api}/api/tools/gobuster"
            payload = {
                "url": url,
                "mode": mode,
                "wordlist": wordlist,
                "additionalargs": additional_args
            }

            start_time = time.time()

            if __event_emitter__:
                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {
                            "description": f"⏳ Gobuster läuft...",
                            "done": False,
                        },
                    }
                )

            response = session.post(api_url, json=payload, timeout=self.valves.default_timeout)
            response.raise_for_status()
            result = response.json()

            elapsed = time.time() - start_time

            if __event_emitter__:
                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {
                            "description": f"✅ Gobuster abgeschlossen ({int(elapsed)}s)",
                            "done": True,
                        },
                    }
                )

            output = "═" * 60 + "\n"
            output += f"🔧 **TOOL:** Gobuster Scanner\n"
            output += f"🎯 **TARGET:** {url}\n"
            output += f"⏱️ **LAUFZEIT:** {int(elapsed)}s\n"
            output += "═" * 60 + "\n\n"

            if result.get("success"):
                output += "✅ **STATUS:** Scan erfolgreich\n\n"
                if result.get("stdout"):
                    stdout = result["stdout"]
                    if len(stdout) > 6000:
                        output += f"📤 **OUTPUT:**\n```\n{stdout[:6000]}\n... (gekürzt)\n```\n"
                    else:
                        output += f"📤 **OUTPUT:**\n```\n{stdout}\n```\n"
            else:
                output += f"❌ **FEHLER:** {result.get('error')}\n"
                if result.get("stderr"):
                    output += f"\n📛 **ERROR:**\n```\n{result['stderr'][:1500]}\n```\n"

            return output + "\n" + "═" * 60

        except Exception as e:
            if __event_emitter__:
                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {
                            "description": f"❌ Fehler: {str(e)}",
                            "done": True,
                        },
                    }
                )
            return f"❌ **Fehler:** {str(e)}"

    async def nuclei_scan(
        self,
        target: str,
        severity: str = "",
        tags: str = "",
        template: str = "",
        additional_args: str = "",
        __event_emitter__=None,
    ) -> str:
        """
        Nuclei Vulnerability Scanner

        Args:
            target: Target URL or IP address
            severity: Severity filter (critical,high,medium,low,info)
            tags: Tags to filter (cve,rce,lfi,xss, etc.)
            template: Path to custom template
            additional_args: Additional nuclei arguments
        """

        if __event_emitter__:
            await __event_emitter__(
                {
                    "type": "status",
                    "data": {
                        "description": f"🚀 Nuclei Scan wird gestartet für {target}...",
                        "done": False,
                    },
                }
            )

        try:
            session = requests.Session()
            session.headers.update({
                'Content-Type': 'application/json',
                'User-Agent': 'OpenWebUI-HexStrike/1.0'
            })

            api_url = f"{self.valves.hexstrike_api}/api/tools/nuclei"
            payload = {
                "target": target,
                "severity": severity,
                "tags": tags,
                "template": template,
                "additionalargs": additional_args
            }

            start_time = time.time()

            if __event_emitter__:
                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {
                            "description": f"⏳ Nuclei Scan läuft...",
                            "done": False,
                        },
                    }
                )

            response = session.post(api_url, json=payload, timeout=self.valves.default_timeout)
            response.raise_for_status()
            result = response.json()

            elapsed = time.time() - start_time

            if __event_emitter__:
                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {
                            "description": f"✅ Nuclei abgeschlossen ({int(elapsed)}s)",
                            "done": True,
                        },
                    }
                )

            output = "═" * 60 + "\n"
            output += f"🔧 **TOOL:** Nuclei Scanner\n"
            output += f"🎯 **TARGET:** {target}\n"
            output += f"⏱️ **LAUFZEIT:** {int(elapsed)}s\n"
            output += "═" * 60 + "\n\n"

            if result.get("success"):
                output += "✅ **STATUS:** Scan erfolgreich\n\n"
                if result.get("stdout"):
                    stdout = result["stdout"]
                    if len(stdout) > 6000:
                        output += f"📤 **OUTPUT:**\n```\n{stdout[:6000]}\n... (gekürzt)\n```\n"
                    else:
                        output += f"📤 **OUTPUT:**\n```\n{stdout}\n```\n"
            else:
                output += f"❌ **FEHLER:** {result.get('error')}\n"
                if result.get("stderr"):
                    output += f"\n📛 **ERROR:**\n```\n{result['stderr'][:1500]}\n```\n"

            return output + "\n" + "═" * 60

        except Exception as e:
            if __event_emitter__:
                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {
                            "description": f"❌ Fehler: {str(e)}",
                            "done": True,
                        },
                    }
                )
            return f"❌ **Fehler:** {str(e)}"

    async def server_health(self, __event_emitter__=None) -> str:
        """
        Check HexStrike Server Health Status
        """

        if __event_emitter__:
            await __event_emitter__(
                {
                    "type": "status",
                    "data": {
                        "description": "🔍 Server-Status wird geprüft...",
                        "done": False,
                    },
                }
            )

        try:
            session = requests.Session()
            response = session.get(f"{self.valves.hexstrike_api}/health", timeout=10)
            response.raise_for_status()
            result = response.json()

            output = "═" * 60 + "\n🔧 **SERVER HEALTH**\n═" * 60 + "\n\n"
            output += f"✅ **Status:** {result.get('status', 'online')}\n"
            output += f"📦 **Version:** {result.get('version', 'unknown')}\n"
            output += f"⏰ **Uptime:** {result.get('uptime', 'unknown')}\n"
            output += "\n" + "═" * 60

            if __event_emitter__:
                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {
                            "description": "✅ Server online",
                            "done": True,
                        },
                    }
                )

            return output

        except Exception as e:
            if __event_emitter__:
                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {
                            "description": f"❌ Server offline: {str(e)}",
                            "done": True,
                        },
                    }
                )
            return f"❌ **Server offline:** {str(e)}"
