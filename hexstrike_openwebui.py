"""
title: HexStrike Security Tools - Open WebUI
author: Dx3One
version: 0.3.0
license: MIT
description: Open WebUI HexStrike MCP Integration 
required_open_webui_version: 0.3.0
"""

from pydantic import BaseModel, Field
import requests
import time


class Tools:
    class Valves(BaseModel):
        hexstrike_api: str = Field(
            default="http://YOUR-HEX-STRIKE-MCP:8888",
            description="HexStrike MCP Server URL"
        )
        default_timeout: int = Field(
            default=3600,
            description="Default timeout in seconds (1 hour)"
        )

    def __init__(self):
        self.valves = self.Valves()

    async def _execute_tool(self, tool_name: str, endpoint: str, params: dict, __event_emitter__=None) -> str:
        """Zentrale Tool-Ausführung mit Event Emitter"""

        if __event_emitter__:
            await __event_emitter__({
                "type": "status",
                "data": {
                    "description": f"🚀 {tool_name} wird ausgeführt...",
                    "done": False,
                }
            })

        try:
            session = requests.Session()
            session.headers.update({
                'Content-Type': 'application/json',
                'User-Agent': 'OpenWebUI-HexStrike/1.0'
            })

            url = f"{self.valves.hexstrike_api}/{endpoint}"
            start_time = time.time()

            if __event_emitter__:
                await __event_emitter__({
                    "type": "status",
                    "data": {
                        "description": f"⏳ {tool_name} läuft...",
                        "done": False,
                    }
                })

            response = session.post(url, json=params, timeout=self.valves.default_timeout)
            response.raise_for_status()
            result = response.json()

            elapsed = time.time() - start_time

            if __event_emitter__:
                await __event_emitter__({
                    "type": "status",
                    "data": {
                        "description": f"✅ {tool_name} abgeschlossen ({int(elapsed)}s)",
                        "done": True,
                    }
                })

            # Format Output
            output = "═" * 60 + "\n"
            output += f"🔧 **TOOL:** {tool_name}\n"
            output += f"⏱️ **LAUFZEIT:** {int(elapsed)}s ({elapsed/60:.1f} Min)\n"
            output += "═" * 60 + "\n\n"

            if result.get("success"):
                output += "✅ **STATUS:** Erfolgreich\n\n"
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
                await __event_emitter__({
                    "type": "status",
                    "data": {
                        "description": f"❌ Fehler: {str(e)}",
                        "done": True,
                    }
                })
            return f"❌ **Fehler:** {str(e)}"

    # ========== SCANNING TOOLS ==========

    async def nmap_scan(self, target: str, scan_type: str = "-sV", ports: str = "", 
                       additional_args: str = "", __event_emitter__=None) -> str:
        """
        Nmap Port Scanner

        Args:
            target: Target IP or hostname
            scan_type: Scan type (-sV, -sS, -sC, etc.)
            ports: Port specification (e.g., '80,443' or '1-1000')
            additional_args: Additional nmap arguments
        """
        return await self._execute_tool("Nmap", "api/tools/nmap", {
            "target": target, "scantype": scan_type, "ports": ports, "additionalargs": additional_args
        }, __event_emitter__)

    async def rustscan_fast_scan(self, target: str, ports: str = "", ulimit: int = 5000,
                                batchsize: int = 4500, timeout: int = 1500, scripts: bool = False,
                                additional_args: str = "", __event_emitter__=None) -> str:
        """
        RustScan Ultra-Fast Port Scanner

        Args:
            target: Target IP/hostname
            ports: Port range
            ulimit: File descriptor limit
            batchsize: Batch size
            timeout: Timeout in ms
            scripts: Enable NSE scripts
            additional_args: Additional arguments
        """
        return await self._execute_tool("RustScan", "api/tools/rustscan", {
            "target": target, "ports": ports, "ulimit": ulimit, "batchsize": batchsize,
            "timeout": timeout, "scripts": scripts, "additionalargs": additional_args
        }, __event_emitter__)

    async def masscan_highspeed(self, target: str, ports: str = "1-65535", rate: int = 1000,
                               interface: str = "", routermac: str = "", sourceip: str = "",
                               banners: bool = False, additional_args: str = "", __event_emitter__=None) -> str:
        """
        Masscan High-Speed Port Scanner

        Args:
            target: Target IP/network
            ports: Port range
            rate: Packets per second
            interface: Network interface
            routermac: Router MAC address
            sourceip: Source IP
            banners: Enable banner grabbing
            additional_args: Additional arguments
        """
        return await self._execute_tool("Masscan", "api/tools/masscan", {
            "target": target, "ports": ports, "rate": rate, "interface": interface,
            "routermac": routermac, "sourceip": sourceip, "banners": banners,
            "additionalargs": additional_args
        }, __event_emitter__)

    async def amass_scan(self, domain: str, mode: str = "enum", additional_args: str = "",
                        __event_emitter__=None) -> str:
        """
        Amass Subdomain Enumeration

        Args:
            domain: Target domain
            mode: Mode (enum, intel, viz)
            additional_args: Additional arguments
        """
        return await self._execute_tool("Amass", "api/tools/amass", {
            "domain": domain, "mode": mode, "additionalargs": additional_args
        }, __event_emitter__)

    async def subfinder_scan(self, domain: str, silent: bool = True, allsources: bool = False,
                            additional_args: str = "", __event_emitter__=None) -> str:
        """
        Subfinder Passive Subdomain Enumeration

        Args:
            domain: Target domain
            silent: Silent mode
            allsources: Use all sources
            additional_args: Additional arguments
        """
        return await self._execute_tool("Subfinder", "api/tools/subfinder", {
            "domain": domain, "silent": silent, "allsources": allsources,
            "additionalargs": additional_args
        }, __event_emitter__)

    # ========== WEB TOOLS ==========

    async def gobuster_scan(self, url: str, mode: str = "dir",
                           wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                           additional_args: str = "", __event_emitter__=None) -> str:
        """
        Gobuster Directory/DNS Fuzzing

        Args:
            url: Target URL
            mode: Mode (dir, dns, vhost, fuzz)
            wordlist: Wordlist path
            additional_args: Additional arguments
        """
        return await self._execute_tool("Gobuster", "api/tools/gobuster", {
            "url": url, "mode": mode, "wordlist": wordlist, "additionalargs": additional_args
        }, __event_emitter__)

    async def nuclei_scan(self, target: str, severity: str = "", tags: str = "",
                         template: str = "", additional_args: str = "", __event_emitter__=None) -> str:
        """
        Nuclei Vulnerability Scanner

        Args:
            target: Target URL or IP
            severity: Severity filter (critical,high,medium,low,info)
            tags: Tags (cve,rce,lfi,xss, etc.)
            template: Template path
            additional_args: Additional arguments
        """
        return await self._execute_tool("Nuclei", "api/tools/nuclei", {
            "target": target, "severity": severity, "tags": tags,
            "template": template, "additionalargs": additional_args
        }, __event_emitter__)

    async def ffuf_scan(self, url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                       mode: str = "directory", matchcodes: str = "200,204,301,302,307,401,403",
                       additional_args: str = "", __event_emitter__=None) -> str:
        """
        FFuf Web Fuzzer

        Args:
            url: Target URL (with FUZZ keyword)
            wordlist: Wordlist path
            mode: Mode (directory, vhost, parameter)
            matchcodes: HTTP status codes to match
            additional_args: Additional arguments
        """
        return await self._execute_tool("FFuf", "api/tools/ffuf", {
            "url": url, "wordlist": wordlist, "mode": mode,
            "matchcodes": matchcodes, "additionalargs": additional_args
        }, __event_emitter__)

    async def sqlmap_scan(self, url: str, data: str = "", additional_args: str = "",
                         __event_emitter__=None) -> str:
        """
        SQLMap SQL Injection Scanner

        Args:
            url: Target URL
            data: POST data
            additional_args: Additional arguments (e.g., --batch --risk=3)
        """
        return await self._execute_tool("SQLMap", "api/tools/sqlmap", {
            "url": url, "data": data, "additionalargs": additional_args
        }, __event_emitter__)

    async def nikto_scan(self, target: str, additional_args: str = "", __event_emitter__=None) -> str:
        """
        Nikto Web Server Scanner

        Args:
            target: Target URL or IP
            additional_args: Additional arguments
        """
        return await self._execute_tool("Nikto", "api/tools/nikto", {
            "target": target, "additionalargs": additional_args
        }, __event_emitter__)

    async def wpscan_analyze(self, url: str, additional_args: str = "", __event_emitter__=None) -> str:
        """
        WPScan WordPress Scanner

        Args:
            url: WordPress URL
            additional_args: Additional arguments (e.g., --enumerate u,p)
        """
        return await self._execute_tool("WPScan", "api/tools/wpscan", {
            "url": url, "additionalargs": additional_args
        }, __event_emitter__)

    async def dirb_scan(self, url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                       additional_args: str = "", __event_emitter__=None) -> str:
        """
        DIRB Directory Bruteforce

        Args:
            url: Target URL
            wordlist: Wordlist path
            additional_args: Additional arguments
        """
        return await self._execute_tool("DIRB", "api/tools/dirb", {
            "url": url, "wordlist": wordlist, "additionalargs": additional_args
        }, __event_emitter__)

    # ========== API SECURITY ==========

    async def api_fuzzer(self, base_url: str, endpoints: str = "",
                        methods: str = "GET,POST,PUT,DELETE",
                        wordlist: str = "/usr/share/wordlists/api/api-endpoints.txt",
                        __event_emitter__=None) -> str:
        """
        API Fuzzer for Endpoint Discovery

        Args:
            base_url: Base API URL
            endpoints: Known endpoints (comma-separated)
            methods: HTTP methods
            wordlist: Wordlist for fuzzing
        """
        return await self._execute_tool("API Fuzzer", "api/tools/apifuzzer", {
            "baseurl": base_url, "endpoints": endpoints,
            "methods": methods, "wordlist": wordlist
        }, __event_emitter__)

    async def graphql_scanner(self, endpoint: str, introspection: bool = True,
                             query_depth: int = 10, test_mutations: bool = True,
                             __event_emitter__=None) -> str:
        """
        GraphQL Security Scanner

        Args:
            endpoint: GraphQL endpoint
            introspection: Test introspection
            query_depth: Max query depth
            test_mutations: Test mutations
        """
        return await self._execute_tool("GraphQL Scanner", "api/tools/graphqlscanner", {
            "endpoint": endpoint, "introspection": introspection,
            "querydepth": query_depth, "testmutations": test_mutations
        }, __event_emitter__)

    async def jwt_analyzer(self, jwt_token: str, target_url: str = "", __event_emitter__=None) -> str:
        """
        JWT Token Analyzer

        Args:
            jwt_token: JWT token to analyze
            target_url: Target URL for testing
        """
        return await self._execute_tool("JWT Analyzer", "api/tools/jwtanalyzer", {
            "jwttoken": jwt_token, "targeturl": target_url
        }, __event_emitter__)

    # ========== CREDENTIAL ATTACKS ==========

    async def hydra_attack(self, target: str, service: str, username: str = "",
                          username_file: str = "", password: str = "", password_file: str = "",
                          additional_args: str = "", __event_emitter__=None) -> str:
        """
        Hydra Brute Force Attack

        Args:
            target: Target IP/hostname
            service: Service (ssh, ftp, http-get, etc.)
            username: Single username
            username_file: Username list file
            password: Single password
            password_file: Password list file
            additional_args: Additional arguments
        """
        return await self._execute_tool("Hydra", "api/tools/hydra", {
            "target": target, "service": service, "username": username,
            "usernamefile": username_file, "password": password,
            "passwordfile": password_file, "additionalargs": additional_args
        }, __event_emitter__)

    async def john_crack(self, hash_file: str, wordlist: str = "/usr/share/wordlists/rockyou.txt",
                        format_type: str = "", additional_args: str = "", __event_emitter__=None) -> str:
        """
        John the Ripper Password Cracker

        Args:
            hash_file: File containing hashes
            wordlist: Wordlist path
            format_type: Hash format (md5, sha256, etc.)
            additional_args: Additional arguments
        """
        return await self._execute_tool("John the Ripper", "api/tools/john", {
            "hashfile": hash_file, "wordlist": wordlist,
            "format": format_type, "additionalargs": additional_args
        }, __event_emitter__)

    # ========== NETWORK / SMB ==========

    async def netexec_scan(self, target: str, protocol: str = "smb", username: str = "",
                          password: str = "", hashvalue: str = "", module: str = "",
                          additional_args: str = "", __event_emitter__=None) -> str:
        """
        NetExec (CrackMapExec) Network Enumeration

        Args:
            target: Target IP/network
            protocol: Protocol (smb, ssh, winrm, ldap, etc.)
            username: Username
            password: Password
            hashvalue: Hash for pass-the-hash
            module: NetExec module
            additional_args: Additional arguments
        """
        return await self._execute_tool("NetExec", "api/tools/netexec", {
            "target": target, "protocol": protocol, "username": username,
            "password": password, "hash": hashvalue, "module": module,
            "additionalargs": additional_args
        }, __event_emitter__)

    async def smbmap_scan(self, target: str, username: str = "", password: str = "",
                         domain: str = "", additional_args: str = "", __event_emitter__=None) -> str:
        """
        SMBMap SMB Share Enumeration

        Args:
            target: Target IP
            username: Username
            password: Password
            domain: Domain
            additional_args: Additional arguments
        """
        return await self._execute_tool("SMBMap", "api/tools/smbmap", {
            "target": target, "username": username, "password": password,
            "domain": domain, "additionalargs": additional_args
        }, __event_emitter__)

    async def enum4linux_scan(self, target: str, additional_args: str = "-a",
                             __event_emitter__=None) -> str:
        """
        Enum4linux SMB Enumeration

        Args:
            target: Target IP
            additional_args: Additional arguments
        """
        return await self._execute_tool("Enum4linux", "api/tools/enum4linux", {
            "target": target, "additionalargs": additional_args
        }, __event_emitter__)

    # ========== CLOUD SECURITY ==========

    async def prowler_scan(self, provider: str = "aws", profile: str = "default",
                          region: str = "", checks: str = "", outputdir: str = "/tmp/prowler-output",
                          outputformat: str = "json", additional_args: str = "",
                          __event_emitter__=None) -> str:
        """
        Prowler Cloud Security Assessment

        Args:
            provider: Cloud provider (aws, azure, gcp)
            profile: AWS profile
            region: Region
            checks: Specific checks
            outputdir: Output directory
            outputformat: Output format (json, csv, html)
            additional_args: Additional arguments
        """
        return await self._execute_tool("Prowler", "api/tools/prowler", {
            "provider": provider, "profile": profile, "region": region,
            "checks": checks, "outputdir": outputdir, "outputformat": outputformat,
            "additionalargs": additional_args
        }, __event_emitter__)

    async def trivy_scan(self, scan_type: str = "image", target: str = "",
                        outputformat: str = "json", severity: str = "", outputfile: str = "",
                        additional_args: str = "", __event_emitter__=None) -> str:
        """
        Trivy Container/IaC Scanner

        Args:
            scan_type: Scan type (image, fs, repo, config)
            target: Target (image, path, repo)
            outputformat: Output format (json, table, sarif)
            severity: Severity filter
            outputfile: Output file
            additional_args: Additional arguments
        """
        return await self._execute_tool("Trivy", "api/tools/trivy", {
            "scantype": scan_type, "target": target, "outputformat": outputformat,
            "severity": severity, "outputfile": outputfile, "additionalargs": additional_args
        }, __event_emitter__)

    # ========== FORENSICS ==========

    async def volatility3_analyze(self, memory_file: str, plugin: str, output_file: str = "",
                                 additional_args: str = "", __event_emitter__=None) -> str:
        """
        Volatility3 Memory Forensics

        Args:
            memory_file: Memory dump file
            plugin: Plugin (windows.pslist, linux.bash, etc.)
            output_file: Output file
            additional_args: Additional arguments
        """
        return await self._execute_tool("Volatility3", "api/tools/volatility3", {
            "memoryfile": memory_file, "plugin": plugin,
            "outputfile": output_file, "additionalargs": additional_args
        }, __event_emitter__)

    async def binwalk_analyze(self, filepath: str, extract: bool = False,
                             additional_args: str = "", __event_emitter__=None) -> str:
        """
        Binwalk Firmware Analysis

        Args:
            filepath: File path
            extract: Extract files
            additional_args: Additional arguments
        """
        return await self._execute_tool("Binwalk", "api/tools/binwalk", {
            "filepath": filepath, "extract": extract, "additionalargs": additional_args
        }, __event_emitter__)

    async def exiftool_extract(self, filepath: str, outputformat: str = "", tags: str = "",
                              additional_args: str = "", __event_emitter__=None) -> str:
        """
        ExifTool Metadata Extraction

        Args:
            filepath: File path
            outputformat: Output format (json, xml, html)
            tags: Specific tags
            additional_args: Additional arguments
        """
        return await self._execute_tool("ExifTool", "api/tools/exiftool", {
            "filepath": filepath, "outputformat": outputformat,
            "tags": tags, "additionalargs": additional_args
        }, __event_emitter__)

    async def strings_extract(self, filepath: str, minlen: int = 4,
                             additional_args: str = "", __event_emitter__=None) -> str:
        """
        Strings Extraction from Binary

        Args:
            filepath: File path
            minlen: Minimum string length
            additional_args: Additional arguments
        """
        return await self._execute_tool("Strings", "api/tools/strings", {
            "filepath": filepath, "minlen": minlen, "additionalargs": additional_args
        }, __event_emitter__)

    # ========== EXPLOITATION ==========

    async def metasploit_run(self, module: str, options: dict = None, __event_emitter__=None) -> str:
        """
        Metasploit Module Execution

        Args:
            module: Module path (e.g., exploit/windows/smb/ms17_010_eternalblue)
            options: Module options as dict
        """
        if options is None:
            options = {}
        return await self._execute_tool("Metasploit", "api/tools/metasploit", {
            "module": module, "options": options
        }, __event_emitter__)

    # ========== BUG BOUNTY WORKFLOWS ==========

    async def bugbounty_recon_workflow(self, domain: str, scope: str = "",
                                      out_of_scope: str = "", program_type: str = "web",
                                      __event_emitter__=None) -> str:
        """
        Bug Bounty Reconnaissance Workflow

        Args:
            domain: Target domain
            scope: Scope (comma-separated)
            out_of_scope: Out-of-scope (comma-separated)
            program_type: Program type (web, api, mobile)
        """
        return await self._execute_tool("Bug Bounty Recon", "api/bugbounty/reconnaissance-workflow", {
            "domain": domain,
            "scope": scope.split(",") if scope else [],
            "outofscope": out_of_scope.split(",") if out_of_scope else [],
            "programtype": program_type
        }, __event_emitter__)

    async def bugbounty_comprehensive_assessment(self, domain: str, scope: str = "",
                                                priority_vulns: str = "rce,sqli,xss,idor,ssrf",
                                                include_osint: bool = True,
                                                include_business_logic: bool = True,
                                                __event_emitter__=None) -> str:
        """
        Comprehensive Bug Bounty Assessment

        Args:
            domain: Target domain
            scope: Scope (comma-separated)
            priority_vulns: Priority vulnerabilities (comma-separated)
            include_osint: Include OSINT
            include_business_logic: Include business logic tests
        """
        return await self._execute_tool("Bug Bounty Assessment", "api/bugbounty/comprehensive-assessment", {
            "domain": domain,
            "scope": scope.split(",") if scope else [],
            "priorityvulns": priority_vulns.split(",") if priority_vulns else [],
            "includeosint": include_osint,
            "includebusinesslogic": include_business_logic
        }, __event_emitter__)

    # ========== AI-POWERED WORKFLOWS ==========

    async def ai_reconnaissance_workflow(self, target: str, depth: str = "standard",
                                        __event_emitter__=None) -> str:
        """
        AI-Powered Reconnaissance Workflow

        Args:
            target: Target (domain/IP)
            depth: Depth (quick, standard, deep)
        """
        return await self._execute_tool("AI Reconnaissance", "api/intelligence/ai-recon-workflow", {
            "target": target, "depth": depth
        }, __event_emitter__)

    async def ai_vulnerability_assessment(self, target: str, focus_areas: str = "all",
                                         __event_emitter__=None) -> str:
        """
        AI-Powered Vulnerability Assessment

        Args:
            target: Target (domain/IP)
            focus_areas: Focus areas (all, web, network, api, etc.)
        """
        return await self._execute_tool("AI Vuln Assessment", "api/intelligence/ai-vuln-assessment", {
            "target": target, "focusareas": focus_areas
        }, __event_emitter__)

    async def intelligent_smart_scan(self, target: str, objective: str = "comprehensive",
                                    maxtools: int = 5, __event_emitter__=None) -> str:
        """
        AI Smart Scan (automatically optimizes tools)

        Args:
            target: Target
            objective: Objective (recon, exploit, comprehensive)
            maxtools: Maximum number of tools
        """
        return await self._execute_tool("AI Smart Scan", "api/intelligence/smart-scan", {
            "target": target, "objective": objective, "maxtools": maxtools
        }, __event_emitter__)

    async def analyze_target_intelligence(self, target: str, __event_emitter__=None) -> str:
        """
        AI-Powered Target Analysis

        Args:
            target: Target (domain/IP)
        """
        return await self._execute_tool("AI Target Analysis", "api/intelligence/analyze-target", {
            "target": target
        }, __event_emitter__)

    # ========== SYSTEM & UTILITIES ==========

    async def server_health(self, __event_emitter__=None) -> str:
        """Check HexStrike Server Health Status"""

        if __event_emitter__:
            await __event_emitter__({
                "type": "status",
                "data": {
                    "description": "🔍 Server-Status wird geprüft...",
                    "done": False,
                }
            })

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
                await __event_emitter__({
                    "type": "status",
                    "data": {
                        "description": "✅ Server online",
                        "done": True,
                    }
                })

            return output

        except Exception as e:
            if __event_emitter__:
                await __event_emitter__({
                    "type": "status",
                    "data": {
                        "description": f"❌ Server offline",
                        "done": True,
                    }
                })
            return f"❌ **Server offline:** {str(e)}"

    async def execute_command(self, command: str, __event_emitter__=None) -> str:
        """
        ⚠️ Execute Shell Command (DANGEROUS)

        Args:
            command: Shell command to execute
        """
        return await self._execute_tool("Shell Command", "api/command", {
            "command": command
        }, __event_emitter__)
