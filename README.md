# ⚠️ IMPORTANT DISCLAIMER
AUTHORIZED USE ONLY: This tool is designed for authorized security testing only. 
You must have explicit written authorization to test any systems, networks, or applications. Unauthorized access to computer systems is illegal.

USE AT YOUR OWN RISK: 
This software is provided "AS IS" without warranty. 
The authors are not liable for any damages or legal consequences resulting from use or misuse of this software.


# HexStrike OpenWebUI Tool Wrapper  
> A lightweight Python wrapper that exposes the **HexStrike** API as a set of OpenWebUI tools.  
> After cloning the repo, simply edit the `HEXSTRIKE_API` constant to point to your HexStrike MCP instance and add the tool to OpenWebUI.

---

## Table of Contents
- [What is this?](#what-is-this)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Adding the Tool to OpenWebUI](#adding-the-tool-to-openwebui)
- [Available Methods](#available-methods)
- [License](#license)

---

## What is this?
`hexstrike_openwebui.py` is a thin Python client that talks to the **HexStrike** micro‑service controller (MCP).  
The class `Tools` implements dozens of methods that map directly to the HexStrike API endpoints (e.g. Nmap, SQLMap, Metasploit, etc.).  
When integrated into **OpenWebUI** you can call any of these methods from the chat interface as if they were built‑in tools.

---

## Prerequisites
| Item | Notes |
|-------|-------|
| HexStrike MCP | Must be reachable from the machine running OpenWebUI. |
| OpenWebUI  | The official OpenWebUI repo or a fork that supports custom tools. |

---

## Installation
1. Open `hexstrike_openwebui.py`.  
2. Locate the line:

```python
default="http://YOUR-HEX-STRIKE-MCP:8888",
```

3. Replace the URL with the address of your HexStrike MCP, e.g.:

```python
default="http://192.168.1.XX:8888",
```

> **Important:** The IP/hostname and port must be reachable from the host running OpenWebUI.

---

## Adding the Tool to OpenWebUI
1. Start OpenWebUI.  
2. Navigate to **Workspace → Tools**.  
3. Click **Add Tool**.  
4. Fill in the form:  
   * **Name** – `HexStrike` (or any friendly name).  
   * **Description** – “Wrapper for HexStrike MCP – run scans, exploits, etc.”  
   * **Parameters** – leave blank (the wrapper exposes all methods).  
5. Click **Save**.  

Now you can invoke any method directly from the chat, e.g.:

```
nmap_scan target=example.com
```


---

## Available Methods

The wrapper contains **over 200** methods. Below is a grouped summary.

| Category | Example Method | Purpose |
|----------|----------------|---------|
| **System** | `server_health`, `execute_command` | Health checks & arbitrary shell execution |
| **Recon** | `nmap_scan`, `gobuster_scan`, `httpx_probe`, `paramspider_discovery` | Network, web & API reconnaissance |
| **Exploit** | `sqlmap_scan`, `metasploit_run`, `hydra_attack` | Automated exploitation & credential attacks |
| **API** | `api_fuzzer`, `graphql_scanner`, `jwt_analyzer` | Advanced API & GraphQL security testing |
| **DFIR** | `volatility3_analyze`, `foremost_carve`, `steghide_action` | Memory & file forensics |
| **Cloud** | `prowler_scan`, `trivy_scan`, `cloudmapper_analysis` | Cloud & container security |
| **AI** | `select_optimal_tools_ai`, `ai_reconnaissance_workflow`, `ai_vulnerability_assessment` | AI‑driven tool selection & assessments |
| **Reporting** | `create_vulnerability_report`, `create_scan_summary` | Generate visual reports |
| **Bug Bounty** | `bugbounty_recon_workflow`, `bugbounty_vuln_hunting` | End‑to‑end bug‑bounty workflows |

---

## License
MIT © 2026

---

### Want to contribute?  
Feel free to open issues or pull requests. Contributions that add new tools, improve documentation, or fix bugs are welcome!

Happy hacking! 🚀
