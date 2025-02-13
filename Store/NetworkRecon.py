import subprocess
import os
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(filename='tool_logs.txt', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def run_tool(tool_name, command, target):
    """
    Runs the specified tool with the given command and stores output in a dedicated file.
    """
    tool_file = f"{tool_name}.txt"
    
    try:
        start_time = datetime.now()
        logging.info(f"Started running {tool_name} on {target}")
        
        # Run the tool and capture the output
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        output = result.stdout + result.stderr
        
        end_time = datetime.now()
        duration = end_time - start_time
        logging.info(f"Finished running {tool_name} on {target} in {duration}")
        
        # Write output to the respective file
        with open(tool_file, "a") as file:
            file.write(f"\n{'='*20} {target} {'='*20}\n")
            file.write(output + "\n")
            
        print(f"Output stored in {tool_file}")
    except Exception as e:
        logging.error(f"Error running {tool_name} on {target}: {e}")
        print(f"Error running {tool_name}: {e}")

if __name__ == "__main__":
    while True:
        tool_name = input("Enter the tool to run (or 'exit' to quit): ")
        if tool_name.lower() == 'exit':
            break
        
        target = input("Enter the IP/URL to test: ")
        
        tools = {
            "Nmap": f"nmap {target} -T4 -n",
            "Masscan": f"masscan {target} --ports 0-65535",
            "Arp-Scan": f"arp-scan {target}",
            "ZMap": f"zmap -p * {target}"
        }
        
        if tool_name in tools:
            print(f"Running {tool_name} on {target}...")
            run_tool(tool_name, tools[tool_name], target)
        else:
            print("Invalid tool name. Please try again.")
