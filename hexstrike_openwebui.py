import requests
from typing import Dict, Any, List, Optional

HEXSTRIKE_API = "http://YOUR-HEX-STRIKE-MCP:8888"
TIMEOUT = 3000


class HexStrikeClient:
    def get(self, path: str):
        try:
            r = requests.get(f"{HEXSTRIKE_API}/{path}", timeout=TIMEOUT)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            return {"success": False, "error": str(e)}

    def post(self, path: str, data: Dict[str, Any]):
        try:
            r = requests.post(f"{HEXSTRIKE_API}/{path}", json=data, timeout=TIMEOUT)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            return {"success": False, "error": str(e)}


# 🔥 OPENWEBUI ENTRYPOINT
class Tools:
    def __init__(self):
        self.api = HexStrikeClient()

    # ---------- SYSTEM ----------
    def server_health(self):
        """Check HexStrike API health"""
        return self.api.get("health")

    def execute_command(self, command: str):
        """⚠️ Dangerous: Execute arbitrary shell command"""
        return self.api.post("api/command", {"command": command})

    # ---------- RECON ----------
    def nmap_scan(
        self,
        target: str,
        scan_type: str = "-sV",
        ports: str = "",
        additional_args: str = "",
    ):
        """Run Nmap scan"""
        return self.api.post(
            "api/tools/nmap",
            {
                "target": target,
                "scantype": scan_type,
                "ports": ports,
                "additionalargs": additional_args,
            },
        )

    def gobuster_scan(
        self,
        url: str,
        mode: str = "dir",
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        additional_args: str = "",
    ):
        """Run Gobuster scan"""
        return self.api.post(
            "api/tools/gobuster",
            {
                "url": url,
                "mode": mode,
                "wordlist": wordlist,
                "additionalargs": additional_args,
            },
        )

    def dirb_scan(
        self,
        url: str,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        additional_args: str = "",
    ):
        """Run Dirb scan"""
        return self.api.post(
            "api/tools/dirb",
            {"url": url, "wordlist": wordlist, "additionalargs": additional_args},
        )

    def nikto_scan(self, target: str, additional_args: str = ""):
        """Run Nikto web scan"""
        return self.api.post(
            "api/tools/nikto", {"target": target, "additionalargs": additional_args}
        )

    def wpscan_analyze(self, url: str, additional_args: str = ""):
        """Run WPScan"""
        return self.api.post(
            "api/tools/wpscan", {"url": url, "additionalargs": additional_args}
        )

    def enum4linux_scan(self, target: str, additional_args: str = "-a"):
        """Run enum4linux"""
        return self.api.post(
            "api/tools/enum4linux",
            {"target": target, "additionalargs": additional_args},
        )

    # ---------- EXPLOIT ----------
    def sqlmap_scan(self, url: str, data: str = "", additional_args: str = ""):
        """⚠️ Dangerous: Run SQLMap"""
        return self.api.post(
            "api/tools/sqlmap",
            {"url": url, "data": data, "additionalargs": additional_args},
        )

    def metasploit_run(self, module: str, options: Optional[Dict[str, Any]] = None):
        """⚠️ Dangerous: Run Metasploit module"""
        if options is None:
            options = {}
        return self.api.post(
            "api/tools/metasploit", {"module": module, "options": options}
        )

    # ---------- CREDENTIAL ATTACKS ----------
    def hydra_attack(
        self,
        target: str,
        service: str,
        username: str = "",
        username_file: str = "",
        password: str = "",
        password_file: str = "",
        additional_args: str = "",
    ):
        """⚠️ Dangerous: Run Hydra brute force"""
        return self.api.post(
            "api/tools/hydra",
            {
                "target": target,
                "service": service,
                "username": username,
                "usernamefile": username_file,
                "password": password,
                "passwordfile": password_file,
                "additionalargs": additional_args,
            },
        )

    def john_crack(
        self,
        hash_file: str,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        format_type: str = "",
        additional_args: str = "",
    ):
        """⚠️ Dangerous: Run John the Ripper"""
        return self.api.post(
            "api/tools/john",
            {
                "hashfile": hash_file,
                "wordlist": wordlist,
                "format": format_type,
                "additionalargs": additional_args,
            },
        )

    # ============================================================
    # ===========  ERWEITERTE TOOLS AUS MCP-CLIENT  ==============
    # ============================================================

    # ----- API & WEB SECURITY -----
    def api_fuzzer(
        self,
        base_url: str,
        endpoints: str = "",
        methods: str = "GET,POST,PUT,DELETE",
        wordlist: str = "/usr/share/wordlists/api/api-endpoints.txt",
    ):
        """Advanced API fuzzing / endpoint discovery"""
        return self.api.post(
            "api/tools/apifuzzer",
            {
                "baseurl": base_url,
                "endpoints": endpoints,
                "methods": methods,
                "wordlist": wordlist,
            },
        )

    def graphql_scanner(
        self,
        endpoint: str,
        introspection: bool = True,
        query_depth: int = 10,
        test_mutations: bool = True,
    ):
        """Advanced GraphQL security scanning"""
        return self.api.post(
            "api/tools/graphqlscanner",
            {
                "endpoint": endpoint,
                "introspection": introspection,
                "querydepth": query_depth,
                "testmutations": test_mutations,
            },
        )

    def jwt_analyzer(self, jwt_token: str, target_url: str = ""):
        """JWT token analysis & vuln testing"""
        return self.api.post(
            "api/tools/jwtanalyzer",
            {"jwttoken": jwt_token, "targeturl": target_url},
        )

    def api_schema_analyzer(self, schema_url: str, schema_type: str = "openapi"):
        """API schema analysis (OpenAPI/Swagger/GraphQL)"""
        return self.api.post(
            "api/tools/apischemaanalyzer",
            {"schemaurl": schema_url, "schematype": schema_type},
        )

    def comprehensive_api_audit(
        self,
        base_url: str,
        schema_url: str = "",
        jwt_token: str = "",
        graphql_endpoint: str = "",
    ):
        """Comprehensive API audit (fuzzer+schema+JWT+GraphQL)"""
        return self.api.post(
            "api/tools/api-comprehensive-audit",
            {
                "baseurl": base_url,
                "schemaurl": schema_url,
                "jwttoken": jwt_token,
                "graphqlendpoint": graphql_endpoint,
            },
        )

    def nuclei_scan(
        self,
        target: str,
        severity: str = "",
        tags: str = "",
        template: str = "",
        additional_args: str = "",
    ):
        """Run Nuclei vulnerability scanner"""
        return self.api.post(
            "api/tools/nuclei",
            {
                "target": target,
                "severity": severity,
                "tags": tags,
                "template": template,
                "additionalargs": additional_args,
            },
        )

    def ffuf_scan(
        self,
        url: str,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        mode: str = "directory",
        matchcodes: str = "200,204,301,302,307,401,403",
        additional_args: str = "",
    ):
        """Run FFuf web fuzzer"""
        return self.api.post(
            "api/tools/ffuf",
            {
                "url": url,
                "wordlist": wordlist,
                "mode": mode,
                "matchcodes": matchcodes,
                "additionalargs": additional_args,
            },
        )

    def http_framework_test(
        self,
        url: str,
        method: str = "GET",
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        action: str = "request",
    ):
        """Enhanced HTTP testing framework (Burp-like)"""
        if data is None:
            data = {}
        if headers is None:
            headers = {}
        if cookies is None:
            cookies = {}
        return self.api.post(
            "api/tools/http-framework",
            {
                "url": url,
                "method": method,
                "data": data,
                "headers": headers,
                "cookies": cookies,
                "action": action,
            },
        )

    def burpsuite_alternative_scan(
        self,
        target: str,
        scantype: str = "comprehensive",
        headless: bool = True,
        maxdepth: int = 3,
        maxpages: int = 50,
    ):
        """Comprehensive Burp Suite alternative scan"""
        return self.api.post(
            "api/tools/burpsuite-alternative",
            {
                "target": target,
                "scantype": scantype,
                "headless": headless,
                "maxdepth": maxdepth,
                "maxpages": maxpages,
            },
        )

    def browser_agent_inspect(
        self,
        url: str,
        headless: bool = True,
        waittime: int = 5,
        action: str = "navigate",
        proxyport: Optional[int] = None,
        activetests: bool = False,
    ):
        """AI-powered browser agent inspection"""
        return self.api.post(
            "api/tools/browser-agent",
            {
                "url": url,
                "headless": headless,
                "waittime": waittime,
                "action": action,
                "proxyport": proxyport,
                "activetests": activetests,
            },
        )

    # ----- DFIR / FORENSICS -----
    def volatility3_analyze(
        self,
        memory_file: str,
        plugin: str,
        output_file: str = "",
        additional_args: str = "",
    ):
        """Volatility3 memory forensics"""
        return self.api.post(
            "api/tools/volatility3",
            {
                "memoryfile": memory_file,
                "plugin": plugin,
                "outputfile": output_file,
                "additionalargs": additional_args,
            },
        )

    def volatility_analyze(
        self,
        memory_file: str,
        plugin: str,
        profile: str = "",
        additional_args: str = "",
    ):
        """Volatility (2.x) memory forensics"""
        return self.api.post(
            "api/tools/volatility",
            {
                "memoryfile": memory_file,
                "plugin": plugin,
                "profile": profile,
                "additionalargs": additional_args,
            },
        )

    def foremost_carve(
        self,
        input_file: str,
        output_dir: str = "/tmp/foremostoutput",
        filetypes: str = "",
        additional_args: str = "",
    ):
        """Foremost file carving"""
        return self.api.post(
            "api/tools/foremost",
            {
                "inputfile": input_file,
                "outputdir": output_dir,
                "filetypes": filetypes,
                "additionalargs": additional_args,
            },
        )

    def steghide_action(
        self,
        action: str,
        cover_file: str,
        embed_file: str = "",
        passphrase: str = "",
        output_file: str = "",
        additional_args: str = "",
    ):
        """Steghide steganography (extract/embed/info)"""
        return self.api.post(
            "api/tools/steghide",
            {
                "action": action,
                "coverfile": cover_file,
                "embedfile": embed_file,
                "passphrase": passphrase,
                "outputfile": output_file,
                "additionalargs": additional_args,
            },
        )

    def exiftool_extract(
        self,
        filepath: str,
        outputformat: str = "",
        tags: str = "",
        additional_args: str = "",
    ):
        """ExifTool metadata extraction"""
        return self.api.post(
            "api/tools/exiftool",
            {
                "filepath": filepath,
                "outputformat": outputformat,
                "tags": tags,
                "additionalargs": additional_args,
            },
        )

    def hashpump_attack(
        self,
        signature: str,
        data: str,
        keylength: str,
        appenddata: str,
        additional_args: str = "",
    ):
        """HashPump length extension attack"""
        return self.api.post(
            "api/tools/hashpump",
            {
                "signature": signature,
                "data": data,
                "keylength": keylength,
                "appenddata": appenddata,
                "additionalargs": additional_args,
            },
        )

    def binwalk_analyze(
        self, filepath: str, extract: bool = False, additional_args: str = ""
    ):
        """Binwalk firmware/file analysis"""
        return self.api.post(
            "api/tools/binwalk",
            {
                "filepath": filepath,
                "extract": extract,
                "additionalargs": additional_args,
            },
        )

    def ropgadget_search(
        self, binary: str, gadgettype: str = "", additional_args: str = ""
    ):
        """ROPgadget search"""
        return self.api.post(
            "api/tools/ropgadget",
            {
                "binary": binary,
                "gadgettype": gadgettype,
                "additionalargs": additional_args,
            },
        )

    def checksec_analyze(self, binary: str):
        """Checksec binary security features"""
        return self.api.post("api/tools/checksec", {"binary": binary})

    def xxd_hexdump(
        self,
        filepath: str,
        offset: str = "0",
        length: str = "",
        additional_args: str = "",
    ):
        """xxd hex dump"""
        return self.api.post(
            "api/tools/xxd",
            {
                "filepath": filepath,
                "offset": offset,
                "length": length,
                "additionalargs": additional_args,
            },
        )

    def strings_extract(
        self,
        filepath: str,
        minlen: int = 4,
        additional_args: str = "",
    ):
        """strings extraction from binaries/files"""
        return self.api.post(
            "api/tools/strings",
            {
                "filepath": filepath,
                "minlen": minlen,
                "additionalargs": additional_args,
            },
        )

    # ----- WEB RECON & HTTP -----
    def hakrawler_crawl(
        self,
        url: str,
        depth: int = 2,
        forms: bool = True,
        robots: bool = True,
        sitemap: bool = True,
        wayback: bool = False,
        additional_args: str = "",
    ):
        """Hakrawler web endpoint discovery"""
        return self.api.post(
            "api/tools/hakrawler",
            {
                "url": url,
                "depth": depth,
                "forms": forms,
                "robots": robots,
                "sitemap": sitemap,
                "wayback": wayback,
                "additionalargs": additional_args,
            },
        )

    def httpx_probe(
        self,
        targets: str = "",
        targetfile: str = "",
        ports: str = "",
        methods: str = "GET",
        statuscode: str = "",
        contentlength: bool = False,
        outputfile: str = "",
        additional_args: str = "",
    ):
        """HTTPx HTTP probing"""
        return self.api.post(
            "api/tools/httpx",
            {
                "targets": targets,
                "targetfile": targetfile,
                "ports": ports,
                "methods": methods,
                "statuscode": statuscode,
                "contentlength": contentlength,
                "outputfile": outputfile,
                "additionalargs": additional_args,
            },
        )

    def paramspider_discovery(
        self,
        domain: str,
        exclude: str = "",
        outputfile: str = "",
        level: int = 2,
        additional_args: str = "",
    ):
        """ParamSpider parameter discovery"""
        return self.api.post(
            "api/tools/paramspider",
            {
                "domain": domain,
                "exclude": exclude,
                "outputfile": outputfile,
                "level": level,
                "additionalargs": additional_args,
            },
        )

    def amass_scan(self, domain: str, mode: str = "enum", additional_args: str = ""):
        """Amass subdomain enumeration"""
        return self.api.post(
            "api/tools/amass",
            {"domain": domain, "mode": mode, "additionalargs": additional_args},
        )

    def subfinder_scan(
        self,
        domain: str,
        silent: bool = True,
        allsources: bool = False,
        additional_args: str = "",
    ):
        """Subfinder passive subdomain enumeration"""
        return self.api.post(
            "api/tools/subfinder",
            {
                "domain": domain,
                "silent": silent,
                "allsources": allsources,
                "additionalargs": additional_args,
            },
        )

    # ----- NETWORK / SMB / AD -----
    def netexec_scan(
        self,
        target: str,
        protocol: str = "smb",
        username: str = "",
        password: str = "",
        hashvalue: str = "",
        module: str = "",
        additional_args: str = "",
    ):
        """NetExec (CrackMapExec) network enumeration"""
        return self.api.post(
            "api/tools/netexec",
            {
                "target": target,
                "protocol": protocol,
                "username": username,
                "password": password,
                "hash": hashvalue,
                "module": module,
                "additionalargs": additional_args,
            },
        )

    def smbmap_scan(
        self,
        target: str,
        username: str = "",
        password: str = "",
        domain: str = "",
        additional_args: str = "",
    ):
        """SMBMap share enumeration"""
        return self.api.post(
            "api/tools/smbmap",
            {
                "target": target,
                "username": username,
                "password": password,
                "domain": domain,
                "additionalargs": additional_args,
            },
        )

    def enum4linux_ng_advanced(
        self,
        target: str,
        username: str = "",
        password: str = "",
        domain: str = "",
        shares: bool = True,
        users: bool = True,
        groups: bool = True,
        policy: bool = True,
        additional_args: str = "",
    ):
        """Enum4linux-ng advanced SMB enumeration"""
        return self.api.post(
            "api/tools/enum4linux-ng",
            {
                "target": target,
                "username": username,
                "password": password,
                "domain": domain,
                "shares": shares,
                "users": users,
                "groups": groups,
                "policy": policy,
                "additionalargs": additional_args,
            },
        )

    def rpcclient_enumeration(
        self,
        target: str,
        username: str = "",
        password: str = "",
        domain: str = "",
        commands: str = "enumdomusers;enumdomgroups;querydominfo",
        additional_args: str = "",
    ):
        """rpcclient RPC enumeration"""
        return self.api.post(
            "api/tools/rpcclient",
            {
                "target": target,
                "username": username,
                "password": password,
                "domain": domain,
                "commands": commands,
                "additionalargs": additional_args,
            },
        )

    def nbtscan_netbios(
        self,
        target: str,
        verbose: bool = False,
        timeout: int = 2,
        additional_args: str = "",
    ):
        """nbtscan NetBIOS name scan"""
        return self.api.post(
            "api/tools/nbtscan",
            {
                "target": target,
                "verbose": verbose,
                "timeout": timeout,
                "additionalargs": additional_args,
            },
        )

    def arp_scan_discovery(
        self,
        target: str = "",
        interface: str = "",
        localnetwork: bool = False,
        timeout: int = 500,
        retry: int = 3,
        additional_args: str = "",
    ):
        """arp-scan network discovery"""
        return self.api.post(
            "api/tools/arp-scan",
            {
                "target": target,
                "interface": interface,
                "localnetwork": localnetwork,
                "timeout": timeout,
                "retry": retry,
                "additionalargs": additional_args,
            },
        )

    def responder_credential_harvest(
        self,
        interface: str = "eth0",
        analyze: bool = False,
        wpad: bool = True,
        forcewpadauth: bool = False,
        fingerprint: bool = False,
        duration: int = 300,
        additional_args: str = "",
    ):
        """Responder credential harvesting"""
        return self.api.post(
            "api/tools/responder",
            {
                "interface": interface,
                "analyze": analyze,
                "wpad": wpad,
                "forcewpadauth": forcewpadauth,
                "fingerprint": fingerprint,
                "duration": duration,
                "additionalargs": additional_args,
            },
        )

    # ----- HIGH-SPEED / ADVANCED SCANS -----
    def rustscan_fast_scan(
        self,
        target: str,
        ports: str = "",
        ulimit: int = 5000,
        batchsize: int = 4500,
        timeout: int = 1500,
        scripts: bool = False,
        additional_args: str = "",
    ):
        """Rustscan ultra-fast port scan"""
        return self.api.post(
            "api/tools/rustscan",
            {
                "target": target,
                "ports": ports,
                "ulimit": ulimit,
                "batchsize": batchsize,
                "timeout": timeout,
                "scripts": scripts,
                "additionalargs": additional_args,
            },
        )

    def masscan_highspeed(
        self,
        target: str,
        ports: str = "1-65535",
        rate: int = 1000,
        interface: str = "",
        routermac: str = "",
        sourceip: str = "",
        banners: bool = False,
        additional_args: str = "",
    ):
        """Masscan high-speed port scan"""
        return self.api.post(
            "api/tools/masscan",
            {
                "target": target,
                "ports": ports,
                "rate": rate,
                "interface": interface,
                "routermac": routermac,
                "sourceip": sourceip,
                "banners": banners,
                "additionalargs": additional_args,
            },
        )

    def nmap_advanced_scan(
        self,
        target: str,
        scan_type: str = "-sS",
        ports: str = "",
        timing: str = "T4",
        nse_scripts: str = "",
        os_detection: bool = False,
        version_detection: bool = False,
        aggressive: bool = False,
        stealth: bool = False,
        additional_args: str = "",
    ):
        """Advanced Nmap with NSE scripts and tuning"""
        return self.api.post(
            "api/tools/nmap-advanced",
            {
                "target": target,
                "scantype": scan_type,
                "ports": ports,
                "timing": timing,
                "nsescripts": nse_scripts,
                "osdetection": os_detection,
                "versiondetection": version_detection,
                "aggressive": aggressive,
                "stealth": stealth,
                "additionalargs": additional_args,
            },
        )

    def autorecon_comprehensive(
        self,
        target: str,
        outputdir: str = "/tmp/autorecon",
        portscans: str = "top-100-ports",
        servicescans: str = "default",
        heartbeat: int = 60,
        timeout: int = 300,
        additional_args: str = "",
    ):
        """AutoRecon comprehensive recon"""
        return self.api.post(
            "api/tools/autorecon",
            {
                "target": target,
                "outputdir": outputdir,
                "portscans": portscans,
                "servicescans": servicescans,
                "heartbeat": heartbeat,
                "timeout": timeout,
                "additionalargs": additional_args,
            },
        )

    # ----- CLOUD / CONTAINER / IaC -----
    def prowler_scan(
        self,
        provider: str = "aws",
        profile: str = "default",
        region: str = "",
        checks: str = "",
        outputdir: str = "/tmp/prowler-output",
        outputformat: str = "json",
        additional_args: str = "",
    ):
        """Prowler cloud security assessment"""
        return self.api.post(
            "api/tools/prowler",
            {
                "provider": provider,
                "profile": profile,
                "region": region,
                "checks": checks,
                "outputdir": outputdir,
                "outputformat": outputformat,
                "additionalargs": additional_args,
            },
        )

    def trivy_scan(
        self,
        scan_type: str = "image",
        target: str = "",
        outputformat: str = "json",
        severity: str = "",
        outputfile: str = "",
        additional_args: str = "",
    ):
        """Trivy container / FS / repo scan"""
        return self.api.post(
            "api/tools/trivy",
            {
                "scantype": scan_type,
                "target": target,
                "outputformat": outputformat,
                "severity": severity,
                "outputfile": outputfile,
                "additionalargs": additional_args,
            },
        )

    def scoutsuite_assessment(
        self,
        provider: str = "aws",
        profile: str = "default",
        reportdir: str = "/tmp/scout-suite",
        services: str = "",
        exceptions: str = "",
        additional_args: str = "",
    ):
        """Scout Suite multi-cloud assessment"""
        return self.api.post(
            "api/tools/scout-suite",
            {
                "provider": provider,
                "profile": profile,
                "reportdir": reportdir,
                "services": services,
                "exceptions": exceptions,
                "additionalargs": additional_args,
            },
        )

    def cloudmapper_analysis(
        self,
        action: str = "collect",
        account: str = "",
        config: str = "config.json",
        additional_args: str = "",
    ):
        """CloudMapper AWS network viz / analysis"""
        return self.api.post(
            "api/tools/cloudmapper",
            {
                "action": action,
                "account": account,
                "config": config,
                "additionalargs": additional_args,
            },
        )

    def pacu_exploitation(
        self,
        sessionname: str = "hexstrike-session",
        modules: str = "",
        dataservices: str = "",
        regions: str = "",
        additional_args: str = "",
    ):
        """Pacu AWS exploitation framework"""
        return self.api.post(
            "api/tools/pacu",
            {
                "sessionname": sessionname,
                "modules": modules,
                "dataservices": dataservices,
                "regions": regions,
                "additionalargs": additional_args,
            },
        )

    def kube_hunter_scan(
        self,
        target: str = "",
        remote: str = "",
        cidr: str = "",
        interface: str = "",
        active: bool = False,
        report: str = "json",
        additional_args: str = "",
    ):
        """kube-hunter Kubernetes pentest"""
        return self.api.post(
            "api/tools/kube-hunter",
            {
                "target": target,
                "remote": remote,
                "cidr": cidr,
                "interface": interface,
                "active": active,
                "report": report,
                "additionalargs": additional_args,
            },
        )

    def kube_bench_cis(
        self,
        targets: str = "",
        version: str = "",
        configdir: str = "",
        outputformat: str = "json",
        additional_args: str = "",
    ):
        """kube-bench CIS benchmark"""
        return self.api.post(
            "api/tools/kube-bench",
            {
                "targets": targets,
                "version": version,
                "configdir": configdir,
                "outputformat": outputformat,
                "additionalargs": additional_args,
            },
        )

    def docker_bench_security_scan(
        self,
        checks: str = "",
        exclude: str = "",
        outputfile: str = "/tmp/docker-bench-results.json",
        additional_args: str = "",
    ):
        """Docker Bench for Security"""
        return self.api.post(
            "api/tools/docker-bench-security",
            {
                "checks": checks,
                "exclude": exclude,
                "outputfile": outputfile,
                "additionalargs": additional_args,
            },
        )

    def clair_vulnerability_scan(
        self,
        image: str,
        config: str = "/etc/clair/config.yaml",
        outputformat: str = "json",
        additional_args: str = "",
    ):
        """Clair container vuln scan"""
        return self.api.post(
            "api/tools/clair",
            {
                "image": image,
                "config": config,
                "outputformat": outputformat,
                "additionalargs": additional_args,
            },
        )

    def falco_runtime_monitoring(
        self,
        configfile: str = "/etc/falco/falco.yaml",
        rulesfile: str = "",
        outputformat: str = "json",
        duration: int = 60,
        additional_args: str = "",
    ):
        """Falco runtime security monitoring"""
        return self.api.post(
            "api/tools/falco",
            {
                "configfile": configfile,
                "rulesfile": rulesfile,
                "outputformat": outputformat,
                "duration": duration,
                "additionalargs": additional_args,
            },
        )

    def checkov_iac_scan(
        self,
        directory: str = ".",
        framework: str = "",
        check: str = "",
        skipcheck: str = "",
        outputformat: str = "json",
        additional_args: str = "",
    ):
        """Checkov IaC security scan"""
        return self.api.post(
            "api/tools/checkov",
            {
                "directory": directory,
                "framework": framework,
                "check": check,
                "skipcheck": skipcheck,
                "outputformat": outputformat,
                "additionalargs": additional_args,
            },
        )

    def terrascan_iac_scan(
        self,
        scantype: str = "all",
        iacdir: str = ".",
        policytype: str = "",
        outputformat: str = "json",
        severity: str = "",
        additional_args: str = "",
    ):
        """Terrascan IaC security scan"""
        return self.api.post(
            "api/tools/terrascan",
            {
                "scantype": scantype,
                "iacdir": iacdir,
                "policytype": policytype,
                "outputformat": outputformat,
                "severity": severity,
                "additionalargs": additional_args,
            },
        )

    # ----- PAYLOADS / FILES / PYTHON -----
    def generate_payload(
        self,
        payloadtype: str = "buffer",
        size: int = 1024,
        pattern: str = "A",
        filename: str = "",
    ):
        """Generate large payloads (buffer/cyclic/random)"""
        data: Dict[str, Any] = {"type": payloadtype, "size": size, "pattern": pattern}
        if filename:
            data["filename"] = filename
        return self.api.post("api/payloads/generate", data)

    def create_file(self, filename: str, content: str, binary: bool = False):
        """Create file on HexStrike server"""
        return self.api.post(
            "api/files/create",
            {"filename": filename, "content": content, "binary": binary},
        )

    def modify_file(self, filename: str, content: str, append: bool = False):
        """Modify file on HexStrike server"""
        return self.api.post(
            "api/files/modify",
            {"filename": filename, "content": content, "append": append},
        )

    def delete_file(self, filename: str):
        """Delete file/directory on HexStrike server"""
        return self.api.post("api/files/delete", {"filename": filename})

    def list_files(self, directory: str = "."):
        """List files in directory on HexStrike server"""
        # hier GET mit Query-Param
        return self.api.get(f"api/files/list?directory={directory}")

    def install_python_package(self, package: str, envname: str = "default"):
        """Install Python package in venv on HexStrike server"""
        return self.api.post(
            "api/python/install",
            {"package": package, "envname": envname},
        )

    def execute_python_script(
        self, script: str, envname: str = "default", filename: str = ""
    ):
        """Execute Python script in venv on HexStrike server"""
        data: Dict[str, Any] = {"script": script, "envname": envname}
        if filename:
            data["filename"] = filename
        return self.api.post("api/python/execute", data)

    # ----- AI-INTELLIGENCE & DASHBOARDS -----
    def analyze_target_intelligence(self, target: str):
        """AI-powered target profile"""
        return self.api.post("api/intelligence/analyze-target", {"target": target})

    def select_optimal_tools_ai(self, target: str, objective: str = "comprehensive"):
        """AI tool selection for target"""
        return self.api.post(
            "api/intelligence/select-tools",
            {"target": target, "objective": objective},
        )

    def intelligent_smart_scan(
        self, target: str, objective: str = "comprehensive", maxtools: int = 5
    ):
        """AI-optimized smart scan"""
        return self.api.post(
            "api/intelligence/smart-scan",
            {"target": target, "objective": objective, "maxtools": maxtools},
        )

    def detect_technologies_ai(self, target: str):
        """AI technology detection & recommendations"""
        return self.api.post(
            "api/intelligence/technology-detection", {"target": target}
        )

    def ai_reconnaissance_workflow(self, target: str, depth: str = "standard"):
        """AI-driven recon workflow"""
        return self.api.post(
            "api/intelligence/ai-recon-workflow",
            {"target": target, "depth": depth},
        )

    def ai_vulnerability_assessment(self, target: str, focus_areas: str = "all"):
        """AI-driven vulnerability assessment"""
        return self.api.post(
            "api/intelligence/ai-vuln-assessment",
            {"target": target, "focusareas": focus_areas},
        )

    def vulnerability_intelligence_dashboard(self):
        """Vulnerability intelligence dashboard"""
        return self.api.get("api/vuln-intel/dashboard")

    def get_live_dashboard(self):
        """Live process/system dashboard"""
        return self.api.get("api/processes/dashboard")

    def display_system_metrics(self):
        """System metrics dashboard"""
        return self.api.get("api/system/metrics")

    # ----- REPORTING & VISUALS -----
    def create_vulnerability_report(
        self,
        vulnerabilities_json: str,
        target: str = "",
        scan_type: str = "comprehensive",
    ):
        """Create formatted vulnerability report"""
        return self.api.post(
            "api/visual/vulnerability-report",
            {
                "vulnerabilities": vulnerabilities_json,
                "target": target,
                "scantype": scan_type,
            },
        )

    def create_scan_summary(
        self,
        target: str,
        tools_used: str,
        vulnerabilities_found: int = 0,
        execution_time: float = 0.0,
        findings: str = "",
    ):
        """Create visual scan summary report"""
        return self.api.post(
            "api/visual/summary-report",
            {
                "target": target,
                "toolsused": tools_used,
                "vulnerabilitiesfound": vulnerabilities_found,
                "executiontime": execution_time,
                "findings": findings,
            },
        )

    def format_tool_output_visual(
        self, tool_name: str, output: str, success: bool = True
    ):
        """Visual formatting for tool output"""
        return self.api.post(
            "api/visual/tool-output",
            {"tool": tool_name, "output": output, "success": success},
        )

    # ----- BUG BOUNTY WORKFLOWS -----
    def bugbounty_recon_workflow(
        self,
        domain: str,
        scope: str = "",
        out_of_scope: str = "",
        program_type: str = "web",
    ):
        """Bug bounty recon workflow"""
        return self.api.post(
            "api/bugbounty/reconnaissance-workflow",
            {
                "domain": domain,
                "scope": scope.split(",") if scope else [],
                "outofscope": out_of_scope.split(",") if out_of_scope else [],
                "programtype": program_type,
            },
        )

    def bugbounty_vuln_hunting(
        self,
        domain: str,
        priority_vulns: str = "rce,sqli,xss,idor,ssrf",
        bounty_range: str = "unknown",
    ):
        """Bug bounty vulnerability hunting workflow"""
        return self.api.post(
            "api/bugbounty/vulnerability-hunting-workflow",
            {
                "domain": domain,
                "priorityvulns": priority_vulns.split(",") if priority_vulns else [],
                "bountyrange": bounty_range,
            },
        )

    def bugbounty_osint_gathering(self, domain: str):
        """Bug bounty OSINT workflow"""
        return self.api.post(
            "api/bugbounty/osint-workflow",
            {"domain": domain},
        )

    def bugbounty_file_upload_testing(self, target_url: str):
        """Bug bounty file upload testing workflow"""
        return self.api.post(
            "api/bugbounty/file-upload-testing",
            {"targeturl": target_url},
        )

    def bugbounty_business_logic_testing(self, domain: str, program_type: str = "web"):
        """Bug bounty business logic testing workflow"""
        return self.api.post(
            "api/bugbounty/business-logic-workflow",
            {"domain": domain, "programtype": program_type},
        )

    def bugbounty_auth_bypass_testing(
        self,
        target_url: str,
        auth_type: str = "form",
    ):
        """Bug bounty authentication bypass testing workflow"""
        return self.api.post(
            "api/bugbounty/authentication-bypass-workflow",
            {"targeturl": target_url, "authtype": auth_type},
        )

    def bugbounty_comprehensive_assessment(
        self,
        domain: str,
        scope: str = "",
        priority_vulns: str = "rce,sqli,xss,idor,ssrf",
        include_osint: bool = True,
        include_business_logic: bool = True,
    ):
        """Comprehensive bug bounty assessment (all workflows combined)"""
        return self.api.post(
            "api/bugbounty/comprehensive-assessment",
            {
                "domain": domain,
                "scope": scope.split(",") if scope else [],
                "priorityvulns": priority_vulns.split(",") if priority_vulns else [],
                "includeosint": include_osint,
                "includebusinesslogic": include_business_logic,
            },
        )

    # ============================================================
    # ===============  PRESET / WORKFLOW HELPERS  ================
    # ============================================================

    def recon_host_workflow(
        self,
        target: str,
        rustscan_ports: str = "",
        nuclei_severity: str = "",
        ffuf_wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    ):
        """
        Opinionated recon preset for a single host:
        1. Rustscan fast port scan
        2. Nmap advanced scan on discovered/selected ports
        3. Nuclei vuln scan
        4. FFuf directory fuzzing (if HTTP(S))
        """
        results: Dict[str, Any] = {"target": target, "steps": {}}

        # 1) Rustscan
        rs = self.rustscan_fast_scan(target=target, ports=rustscan_ports)
        results["steps"]["rustscan"] = rs

        # 2) Advanced Nmap (hier ggf. Ports aus Rustscan-Ergebnis parsen)
        nm = self.nmap_advanced_scan(target=target, ports=rustscan_ports)
        results["steps"]["nmap_advanced"] = nm

        # 3) Nuclei (typisch HTTP/S-Target)
        nuclei = self.nuclei_scan(target=target, severity=nuclei_severity)
        results["steps"]["nuclei"] = nuclei

        # 4) FFuf (falls target als URL genutzt wird, sonst lässt du es einfach so)
        ffuf = self.ffuf_scan(url=f"http://{target}", wordlist=ffuf_wordlist)
        results["steps"]["ffuf"] = ffuf

        return results
