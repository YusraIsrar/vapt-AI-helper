import subprocess
import os
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(filename='tool_logs.txt', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def run_tool(tool_name, command, domain):
    """
    Runs the specified tool with the given command and stores output in a dedicated file.
    """
    tool_file = f"{tool_name}.txt"
    
    try:
        start_time = datetime.now()
        logging.info(f"Started running {tool_name} on {domain}")
        
        # Run the tool and capture the output
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        output = result.stdout + result.stderr
        
        end_time = datetime.now()
        duration = end_time - start_time
        logging.info(f"Finished running {tool_name} on {domain} in {duration}")
        
        # Write output to the respective file
        with open(tool_file, "a") as file:
            file.write(f"\n{'='*20} {domain} {'='*20}\n")
            file.write(output + "\n")
            
        print(f"Output stored in {tool_file}")
    except Exception as e:
        logging.error(f"Error running {tool_name} on {domain}: {e}")
        print(f"Error running {tool_name}: {e}")

if __name__ == "__main__":
    while True:
        tool_name = input("Enter the tool to run (or 'exit' to quit): ")
        if tool_name.lower() == 'exit':
            break
        
        domain = input("Enter the domain to test: ")
        
        tools = {
            "recon-ng": f"recon-ng -r {domain}",
            "pasv-agrsv": f"pasv-agrsv {domain}",
            "asn_lookup": f"python asnlookup.py -n=\"--top-ports 65535\" -o {domain}",
            "h8mail": f"h8mail -t {domain}",
            "prebellico": f"prebellico {domain}",
            "magicrecon": f"magicrecon -d {domain}"
        }
        
        if tool_name in tools:
            print(f"Running {tool_name} on {domain}...")
            run_tool(tool_name, tools[tool_name], domain)
        else:
            print("Invalid tool name. Please try again.")
