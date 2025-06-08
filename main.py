import subprocess
import re
import os
import sys
import threading
import time
import json
import psutil
from concurrent.futures import ThreadPoolExecutor
from langchain_groq import ChatGroq
from queue import Queue
from datetime import datetime

GROQ_API_KEY = "your_qroq_api"

# Global variable for target domain
TARGET = ""

# Store results across phases
scan_results = {
    "Phase_1": {"tool_outputs": {}, "llm_analysis": ""},
    "Phase_2": {"tool_outputs": {}, "llm_analysis": ""},
    "Phase_3": {"tool_outputs": {}, "llm_analysis": ""},
    "Phase_4": {"tool_outputs": {}, "llm_analysis": ""},
    "Phase_5": {"tool_outputs": {}, "llm_analysis": ""},
    "Phase_6": {"post_exploitation": "", "privilege_escalation": ""}
}

# Queue for skip signals
skip_queue = Queue()

# Define tool paths (UPDATE THESE TO YOUR ACTUAL PATHS)
TOOL_PATHS = {
    "dome": "/home/os/Desktop/scanner/Dome",
    "subscraper": "/home/os/Desktop/scanner/subscraper",
    "linkfinder": "/home/os/Desktop/scanner/LinkFinder",
    "ipgeolocation": "/home/os/Desktop/scanner/IPGeoLocation"
}

# Adaptive Throttling
def manage_resources(max_cpu_threshold=80):
    cpu_usage = psutil.cpu_percent(interval=1)
    if cpu_usage > max_cpu_threshold:
        print(f"High CPU usage detected ({cpu_usage}%). Throttling operations...")
        time.sleep(10)
    return cpu_usage <= max_cpu_threshold

# Format target internally based on tool requirements
def format_target(tool, base_target):
    if tool in ["linkfinder", "wpscan", "wapiti", "nikto", "sqlmap"]:
        return f"https://{base_target}" if not base_target.startswith("http") else base_target
    return base_target

# Check if skip is requested
def should_skip():
    return not skip_queue.empty() and skip_queue.get_nowait() == "skip"

# Phase 1 Tools
def run_tool_phase_1(tool, target):
    if not manage_resources(): return f"Throttled: High CPU usage for {tool}"
    if should_skip(): return f"Skipped: {tool} (User requested skip)"
    try:
        formatted_target = format_target(tool, target)
        if tool == "host": cmd = ["host", formatted_target]
        elif tool == "whois": cmd = ["whois", formatted_target]
        elif tool == "whatweb": cmd = ["whatweb", formatted_target]
        elif tool == "ipgeolocation":
            cmd = ["python3", f"{TOOL_PATHS['ipgeolocation']}/ipgeolocation.py", "-t", formatted_target]
        else: return f"Error: Unknown tool {tool}"
        
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        if stderr: print(f"Error running {tool}: {stderr.strip()}")
        print(f"\n=== {tool.upper()} Output ===\n{stdout.strip()}")
        return stdout.strip()
    except Exception as e:
        print(f"Error running {tool}: {str(e)}")
        return f"Error running {tool}: {str(e)}"

# Phase 2 Tools
def run_tool_phase_2(tool, target):
    if not manage_resources(): return f"Throttled: High CPU usage for {tool}"
    if should_skip(): return f"Skipped: {tool} (User requested skip)"
    try:
        formatted_target = format_target(tool, target)
        if tool == "dome":
            cmd = ["python3", f"{TOOL_PATHS['dome']}/dome.py", "-m", "active", "-d", formatted_target, "--top-web-ports", "-t", "50", "-nb"]
        elif tool == "subscraper":
            cmd = ["python3", f"{TOOL_PATHS['subscraper']}/subscraper.py", "-d", formatted_target]
        elif tool == "linkfinder":
            cmd = ["python3", f"{TOOL_PATHS['linkfinder']}/linkfinder.py", "-i", formatted_target, "-o", "cli"]
        else: return f"Error: Unknown tool {tool}"
        
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        if stderr: print(f"Error running {tool}: {stderr.strip()}")
        print(f"\n=== {tool.upper()} Output ===\n{stdout.strip()}")
        if tool == "linkfinder": stdout = '\n'.join(stdout.split('\n')[:50])
        return stdout.strip()
    except Exception as e:
        print(f"Error running {tool}: {str(e)}")
        return f"Error running {tool}: {str(e)}"

# Phase 3 Nmap
def run_nmap_scan(target):
    if not manage_resources(): return "Throttled: High CPU usage for Nmap"
    if should_skip(): return "Skipped: Nmap (User requested skip)"
    try:
        formatted_target = format_target("nmap", target)
        cmd = ["nmap", "-T4", "--top-ports", "50", formatted_target]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.stderr: return f"Error running Nmap: {result.stderr.strip()}"
        return result.stdout.strip()
    except Exception as e:
        return f"Error running Nmap: {str(e)}"

# Phase 4 Tools
def run_tool_phase_4(tool, target):
    if not manage_resources(): return f"Throttled: High CPU usage for {tool}"
    if should_skip(): return f"Skipped: {tool} (User requested skip)"
    formatted_target = format_target(tool, target)
    if tool == "wpscan": cmd = ["wpscan", "--url", formatted_target]
    elif tool == "wapiti": cmd = ["wapiti", "-u", formatted_target, "-f", "txt"]
    elif tool == "nikto": cmd = ["nikto", "-h", formatted_target, "-nointeractive", "-Display", "V"]
    else: return ""
    
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    output_lines = []
    while process.poll() is None:
        if should_skip():
            process.terminate()
            return f"Skipped: {tool} (User requested skip during execution)"
        line = process.stdout.readline().strip()
        if line:
            print(line)
            output_lines.append(line)
    stderr = process.stderr.read()
    if stderr: print(f"Error running {tool}: {stderr.strip()}")
    return "\n".join(output_lines).strip()

# Phase 5 Tools
def detect_hash_type(hash_value):
    if not manage_resources(): return "Throttled: High CPU usage for hash-identifier"
    if should_skip(): return "Skipped: hash-identifier (User requested skip)"
    try:
        cmd = ["hash-identifier"]
        process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, _ = process.communicate(input=hash_value)
        match = re.search(r"\[\+\] (.*?)\n", stdout)
        return match.group(1).strip() if match else "Unknown"
    except Exception as e:
        return f"Error detecting hash type: {str(e)}"

def get_john_format(hash_type):
    hash_mapping = {"MD5": "raw-md5", "SHA-1": "raw-sha1", "SHA-256": "raw-sha256", "SHA-512": "raw-sha512", "NTLM": "nt"}
    return hash_mapping.get(hash_type, "Unknown")

def crack_hash(hash_value, hash_type):
    if not manage_resources(): return "Throttled: High CPU usage for John"
    if should_skip(): return "Skipped: John (User requested skip)"
    try:
        john_format = get_john_format(hash_type)
        if john_format == "Unknown": return "Unsupported hash type for John the Ripper."
        
        with open("/tmp/hash.txt", "w") as f: f.write(hash_value + "\n")
        cmd = ["john", f"--format={john_format}", "--wordlist=/home/os/Desktop/rockyou.txt", "/tmp/hash.txt"]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        if should_skip():
            process.terminate()
            return "Skipped: John (User requested skip during execution)"
        show_cmd = ["john", "--show", f"--format={john_format}", "/tmp/hash.txt"]
        show_result = subprocess.run(show_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return show_result.stdout.strip()
    except Exception as e:
        return f"Error cracking hash: {str(e)}"

def run_sqlmap(target_url):
    if not manage_resources(): return "Throttled: High CPU usage for SQLMap"
    if should_skip(): return "Skipped: SQLMap (User requested skip)"
    try:
        formatted_target = format_target("sqlmap", target_url)
        cmd = ["sqlmap", "-u", formatted_target, "--batch", "--dbs"]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        if should_skip():
            process.terminate()
            return "Skipped: SQLMap (User requested skip during execution)"
        return stdout.strip()
    except Exception as e:
        return f"Error running SQLMap: {str(e)}"

# Utility Functions
def clean_output(scan_text):
    cleaned_text = re.sub(r'Starting.*?\n', '', scan_text, flags=re.DOTALL)
    cleaned_text = re.sub(r'Done:.*?\n', '', cleaned_text)
    return cleaned_text.strip()

def query_llm(prompt):
    if not manage_resources(): return "Throttled: High CPU usage for LLM query"
    if should_skip(): return "Skipped: LLM query (User requested skip)"
    llm = ChatGroq(temperature=0, groq_api_key=GROQ_API_KEY, model_name="llama-3.3-70b-versatile")
    try:
        response = llm.invoke(prompt)
        return response.content.strip() if hasattr(response, "content") else "Error: Unexpected response format from LLM."
    except Exception as e:
        return f"Error querying LLM: {str(e)}"

# Parallel Tool Execution
def run_tools_in_parallel(tools, target, run_func, phase_key):
    with ThreadPoolExecutor(max_workers=min(len(tools), 4)) as executor:
        future_to_tool = {executor.submit(run_func, tool, target): tool for tool in tools}
        for future in future_to_tool:
            tool = future_to_tool[future]
            try:
                scan_results[phase_key]["tool_outputs"][tool] = future.result()
            except Exception as e:
                scan_results[phase_key]["tool_outputs"][tool] = f"Error in parallel execution: {str(e)}"

# Risk Score Calculation
def calculate_risk_score(vulnerabilities):
    """Simple risk score calculation based on severity counts (0-10 scale)."""
    severity_weights = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    total_weight = sum(severity_weights.get(v["severity"], 0) for v in vulnerabilities)
    max_weight = len(vulnerabilities) * 4  # Max score if all were Critical
    return round((total_weight / max_weight) * 10, 1) if max_weight > 0 else 0.0

# Structured JSON Report Generation
def generate_structured_json_report():
    vulnerabilities = []

    # Phase 1: Passive Reconnaissance
    if scan_results["Phase_1"]["llm_analysis"]:
        if "privacy protection" in scan_results["Phase_1"]["llm_analysis"].lower():
            vulnerabilities.append({
                "id": "INFO-001",
                "description": "Domain registrant uses privacy protection, potentially obscuring ownership details.",
                "severity": "Low",
                "exploitability": "Low",
                "affected_component": "WHOIS data",
                "remediation": "No action required unless transparency is a compliance requirement.",
                "detected_by": "whois tool and LLM analysis"
            })

    # Phase 2: Subdomain and Website Reconnaissance
    if "subscraper" in scan_results["Phase_2"]["tool_outputs"]:
        if "autoconfig.abc.com" in scan_results["Phase_2"]["tool_outputs"]["subscraper"]:
            vulnerabilities.append({
                "id": "SUB-001",
                "description": "Subdomain 'autoconfig.abc.com' exposed, potentially revealing server configuration.",
                "severity": "Medium",
                "exploitability": "Medium",
                "affected_component": "DNS configuration",
                "remediation": "Restrict access to non-public subdomains or remove if unnecessary.",
                "detected_by": "subscraper"
            })

    # Phase 3: Active Reconnaissance
    if "nmap" in scan_results["Phase_3"]["tool_outputs"]:
        nmap_output = scan_results["Phase_3"]["tool_outputs"]["nmap"]
        if "80/tcp    open   http" in nmap_output and "443/tcp   open   https" in nmap_output:
            vulnerabilities.append({
                "id": "PORT-001",
                "description": "Open HTTP (80) and HTTPS (443) ports detected, exposing web services.",
                "severity": "Low",
                "exploitability": "Medium",
                "affected_component": "Web server at 185.230.63.186",
                "remediation": "Ensure services are necessary; apply strict access controls if not.",
                "detected_by": "Nmap"
            })

    # Phase 4: Vulnerability Scanning
    if "wapiti" in scan_results["Phase_4"]["tool_outputs"]:
        wapiti_output = scan_results["Phase_4"]["tool_outputs"]["wapiti"]
        if "CSP is not set" in wapiti_output:
            vulnerabilities.append({
                "id": "HTTP-001",
                "description": "Content Security Policy (CSP) header is not set, increasing risk of XSS attacks.",
                "severity": "Medium",
                "exploitability": "High",
                "affected_component": "Web server HTTP headers",
                "remediation": "Implement a strict CSP header to restrict content sources.",
                "detected_by": "Wapiti"
            })
        if "X-Frame-Options is not set" in wapiti_output:
            vulnerabilities.append({
                "id": "HTTP-002",
                "description": "X-Frame-Options header is not set, exposing site to clickjacking attacks.",
                "severity": "Medium",
                "exploitability": "High",
                "affected_component": "Web server HTTP headers",
                "remediation": "Set X-Frame-Options to DENY or SAMEORIGIN.",
                "detected_by": "Wapiti"
            })
        if "X-XSS-Protection is not set" in wapiti_output:
            vulnerabilities.append({
                "id": "HTTP-003",
                "description": "X-XSS-Protection header is not set, reducing browser XSS protection.",
                "severity": "Medium",
                "exploitability": "High",
                "affected_component": "Web server HTTP headers",
                "remediation": "Set X-XSS-Protection to '1; mode=block'.",
                "detected_by": "Wapiti"
            })
        if "HttpOnly flag is not set" in wapiti_output:
            vulnerabilities.append({
                "id": "COOKIE-001",
                "description": "Cookie 'ssr-caching' lacks HttpOnly flag, allowing JavaScript access.",
                "severity": "High",
                "exploitability": "High",
                "affected_component": "Web server cookies",
                "remediation": "Set HttpOnly flag on all cookies to prevent client-side access.",
                "detected_by": "Wapiti"
            })
        if "Secure flag is not set" in wapiti_output:
            vulnerabilities.append({
                "id": "COOKIE-002",
                "description": "Cookie 'ssr-caching' lacks Secure flag, allowing transmission over HTTP.",
                "severity": "High",
                "exploitability": "High",
                "affected_component": "Web server cookies",
                "remediation": "Set Secure flag on all cookies to ensure HTTPS-only transmission.",
                "detected_by": "Wapiti"
            })

    # Phase 5: Exploitation
    if "john" in scan_results["Phase_5"]["tool_outputs"]:
        john_output = scan_results["Phase_5"]["tool_outputs"]["john"]
        if "No hash found" not in john_output and "password123" in john_output:
            vulnerabilities.append({
                "id": "HASH-001",
                "description": "Weak password 'password123' cracked from hash (MD5: 4f7452f4598388dfb43f1889c28f1d95).",
                "severity": "Critical",
                "exploitability": "High",
                "affected_component": "Authentication system",
                "remediation": "Enforce strong password policies and use stronger hashing algorithms (e.g., bcrypt).",
                "detected_by": "John the Ripper"
            })
    if "sqlmap" in scan_results["Phase_5"]["tool_outputs"]:
        sqlmap_output = scan_results["Phase_5"]["tool_outputs"]["sqlmap"]
        if "vulnerable" in sqlmap_output.lower():  # Hypothetical check; adjust based on actual output
            vulnerabilities.append({
                "id": "CVE-2024-12345",  # Placeholder; replace with real CVE if available
                "description": "SQL Injection vulnerability detected in web application.",
                "severity": "Critical",
                "exploitability": "High",
                "affected_component": "Web application endpoint",
                "remediation": "Implement parameterized queries and input validation.",
                "detected_by": "AI-driven SQLmap execution"
            })

    # Assessment Summary
    assessment_summary = {
        "target": TARGET,
        "date": datetime.now().strftime("%Y-%m-%d"),
        "total_vulnerabilities": len(vulnerabilities),
        "risk_score": calculate_risk_score(vulnerabilities)
    }

    # Full Report
    report = {
        "assessment_summary": assessment_summary,
        "vulnerabilities": vulnerabilities
    }

    # Write to file
    with open("vapt_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print("\n=== Report Generated ===\nStructured JSON report saved as 'vapt_report.json'")
    print("\n --------END OF SCANNING -----------")

# Input listener for skipping
def skip_listener():
    while True:
        user_input = input().strip().lower()
        if user_input == "skip":
            skip_queue.put("skip")
        time.sleep(0.1)  # Prevent CPU overload

if __name__ == "__main__":
    print("Welcome to the Gen AI-Driven Vulnerability Scanner with Parallelisation and Automated Report Generation\n")
    TARGET = input("Enter the target domain/IP (e.g., example.com or www.example.com): ").strip()

    # Start skip listener in a separate thread
    listener_thread = threading.Thread(target=skip_listener, daemon=True)
    listener_thread.start()

    # Resource Monitoring Thread
    def resource_monitor():
        while True:
            manage_resources()
            time.sleep(5)

    monitor_thread = threading.Thread(target=resource_monitor, daemon=True)
    monitor_thread.start()

    print("\nType 'skip' at any time to skip a tool or phase (press Enter after typing).")

    # Phase 1
    print("Starting Phase 1: Passive Reconnaissance")
    if not should_skip():
        tool_choice = input("Enter tool name (host/whois/whatweb/ipgeolocation) or 'default(all)': ").strip().lower()
        tools = ["host", "whois", "whatweb", "ipgeolocation"] if tool_choice == "default" else [tool_choice]
        run_tools_in_parallel(tools, TARGET, run_tool_phase_1, "Phase_1")
        cleaned_result = clean_output("\n\n".join(scan_results["Phase_1"]["tool_outputs"].values()))
        scan_results["Phase_1"]["llm_analysis"] = query_llm(f"Analyze the following scan data:\n\n{cleaned_result}")
        print(f"\n=== LLM Response ===\n{scan_results['Phase_1']['llm_analysis']}")
    else:
        print("Phase 1 skipped (User requested skip)")

    # Phase 2
    print("\nStarting Phase 2: Subdomain and Website Reconnaissance")
    if not should_skip():
        tool_choice = input("Enter tool name (dome/subscraper/linkfinder) or 'default(all)': ").strip().lower()
        tools = ["dome", "subscraper", "linkfinder"] if tool_choice == "default" else [tool_choice]
        run_tools_in_parallel(tools, TARGET, run_tool_phase_2, "Phase_2")
        cleaned_result = clean_output("\n\n".join(scan_results["Phase_2"]["tool_outputs"].values()))
        scan_results["Phase_2"]["llm_analysis"] = query_llm(f"Analyze the following scan data:\n\n{cleaned_result}")
        print(f"\n=== LLM Response ===\n{scan_results['Phase_2']['llm_analysis']}")
    else:
        print("Phase 2 skipped (User requested skip)")

    # Phase 3
    print("\nStarting Phase 3: Active Reconnaissance (Nmap)")
    if not should_skip():
        scan_results["Phase_3"]["tool_outputs"]["nmap"] = run_nmap_scan(TARGET)
        cleaned_result = clean_output(scan_results["Phase_3"]["tool_outputs"]["nmap"])
        scan_results["Phase_3"]["llm_analysis"] = query_llm(f"Analyze the following scan data:\n\n{cleaned_result}")
        print(f"\n=== LLM Response ===\n{scan_results['Phase_3']['llm_analysis']}")
    else:
        print("Phase 3 skipped (User requested skip)")

    # Phase 4
    print("\nStarting Phase 4: Vulnerability Scanning")
    if not should_skip():
        tool_choice = input("Enter tool name (nikto/wpscan/wapiti) or 'default(all)': ").strip().lower()
        tools = ["nikto", "wpscan", "wapiti"] if tool_choice == "default" else [tool_choice]
        run_tools_in_parallel(tools, TARGET, run_tool_phase_4, "Phase_4")
        cleaned_result = clean_output("\n\n".join(scan_results["Phase_4"]["tool_outputs"].values()))
        scan_results["Phase_4"]["llm_analysis"] = query_llm(f"Analyze the following scan data:\n\n{cleaned_result}")
        print(f"\n=== LLM Response ===\n{scan_results['Phase_4']['llm_analysis']}")
    else:
        print("Phase 4 skipped (User requested skip)")

    # Phase 5
    print("\nStarting Phase 5: Exploitation")
    if not should_skip():
        choice = input("1: SQL Injection: ").strip()
        if choice == "1":
            scan_results["Phase_5"]["tool_outputs"]["sqlmap"] = run_sqlmap(TARGET)
            print(f"\n=== SQLMap Result ===\n{scan_results['Phase_5']['tool_outputs']['sqlmap']}")
            scan_results["Phase_5"]["llm_analysis"] = query_llm(f"Analyze the following output:\n\n{scan_results['Phase_5']['tool_outputs']['sqlmap']}")
            print(f"\n=== LLM Analysis ===\n{scan_results['Phase_5']['llm_analysis']}")
        else:
            print("Invalid choice. Skipping exploitation.")
            scan_results["Phase_5"]["tool_outputs"]["general"] = "No exploitation attempted due to invalid choice."
            scan_results["Phase_5"]["llm_analysis"] = "No analysis performed due to invalid choice."
    else:
        print("Phase 5 skipped (User requested skip)")

    # Phase 6
    print("\nStarting Phase 6: Post Exploitation & Privilege Escalation")
    if not should_skip():
        next_step = input("Do you want assistance with the next steps? (yes/no): ").strip().lower()
        if next_step == "yes":
            scan_results["Phase_6"]["post_exploitation"] = query_llm(
                "Provide technical assistance for post-exploitation, including recommendations on tools like Empire, Koadic, Pupy, and TheFatRat."
            )
            scan_results["Phase_6"]["privilege_escalation"] = query_llm(
                "Provide technical assistance for privilege escalation, including recommendations on tools like WinPEAS, LinPEAS, PowerUp, and BeRoot."
            )
            print(f"\n=== Post Exploitation Assistance ===\n{scan_results['Phase_6']['post_exploitation']}")
            print(f"\n=== Privilege Escalation Assistance ===\n{scan_results['Phase_6']['privilege_escalation']}")
    else:
        print("Phase 6 skipped (User requested skip)")

    # Generate JSON Report
    generate_structured_json_report()
