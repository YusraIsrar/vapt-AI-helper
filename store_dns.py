import subprocess
import os

def run_tool(tool_name, command, target):
    """
    Runs the specified tool with the given command and stores output in a dedicated file.
    """
    tool_file = f"{tool_name}.txt"
    
    try:
        # Run the tool and capture the output
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        output = result.stdout + result.stderr
        
        # Write output to the respective file
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
        
        target = input("Enter the domain to test: ")
        
        tools = {
            "DNSenum": f"dnsenum {target}",
            "DNSrecon": f"dnsrecon -d {target}",
            "Fierce": f"fierce --domain {target}",
            "dnstwist": f"dnstwist {target}"
        }
        
        if tool_name in tools:
            print(f"Running {tool_name} on {target}...")
            run_tool(tool_name, tools[tool_name], target)
        else:
            print("Invalid tool name. Please try again.")

