import subprocess
import os

def run_tool(tool_name, command, target):
    tool_file = f"{tool_name}.txt"
    
    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        output = result.stdout + result.stderr
        with open(tool_file, "a") as file:
            file.write(f"\n{'='*20} {target} {'='*20}\n")
            file.write(output + "\n")
            
        print(f"Output stored in {tool_file}")
    except Exception as e:
        print(f"Error running {tool_name}: {e}")

if __name__ == "__main__":
    while True:
        tool_name = input("Enter the tool to run (or 'exit' to quit): ")
        if tool_name.lower() == 'exit':
            break
        
        target = input("Enter the target URL or IP: ")
        
        tools = {
            "Nikto": f"nikto -h {target}",
            "wpscan": f"wpscan --url {target}",
            "nuclei": f"nuclei -u {target}",
            "w3af": f"w3af_console -s {target}",
            "Wapiti": f"wapiti -u {target}",
            "DVCS Ripper": f"dvcs-ripper {target}",
            "Rapidscan": f"rapidscan {target}",
            "whatweb": f"whatweb {target}",
            "xsstrike": f"xsstrike -u {target}"
        }
        
        if tool_name in tools:
            print(f"Running {tool_name} on {target}...")
            run_tool(tool_name, tools[tool_name], target)
        else:
            print("Invalid tool name. Please try again.")
