from mcp.server.fastmcp import FastMCP
import subprocess
import os
import signal
from dotenv import load_dotenv
from typing import List, Optional
import re

# Load environment variables
load_dotenv()

app = FastMCP("wireshark-mcp-server")

# Global dictionary to store running capture processes
capture_processes = {}

@app.tool()
async def get_interfaces() -> List[str]:
    """Get list of available network interfaces for packet capture."""
    try:
        result = subprocess.run(
            ["tshark", "-D"],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode != 0:
            return [f"Error: {result.stderr}"]
        
        # Parse interfaces from output
        interfaces = []
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                # Extract interface name (format: "1. eth0")
                match = re.match(r'\d+\.\s+(\S+)', line)
                if match:
                    interfaces.append(match.group(1))
        return interfaces
    except subprocess.TimeoutExpired:
        return ["Error: Timeout while getting interfaces"]
    except Exception as e:
        return [f"Error: {str(e)}"]

@app.tool()
async def start_packet_capture(interface: str, filename: str, filter: Optional[str] = None) -> str:
    """Start packet capture on specified interface and save to file."""
    try:
        # Check if interface exists
        interfaces = await get_interfaces()
        if interface not in interfaces:
            return f"Error: Interface '{interface}' not found. Available: {', '.join(interfaces)}"
        
        # Build command
        cmd = ["tshark", "-i", interface, "-w", filename]
        if filter:
            cmd.extend(["-f", filter])
        
        # Start subprocess in background
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process_id = process.pid
        capture_processes[process_id] = process
        
        return f"Packet capture started on interface '{interface}', PID: {process_id}, saving to '{filename}'"
    except Exception as e:
        return f"Error starting capture: {str(e)}"

@app.tool()
async def stop_packet_capture(process_id: int) -> str:
    """Stop packet capture by process ID."""
    try:
        if process_id not in capture_processes:
            return f"Error: No capture process found with PID {process_id}"
        
        process = capture_processes[process_id]
        process.terminate()
        
        # Wait for process to terminate
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()  # Force kill if terminate doesn't work
        
        del capture_processes[process_id]
        return f"Packet capture stopped for PID {process_id}"
    except Exception as e:
        return f"Error stopping capture: {str(e)}"

@app.tool()
async def analyze_packets(filename: str, filter: Optional[str] = None) -> str:
    """Analyze captured packets from file with optional filter."""
    try:
        if not os.path.exists(filename):
            return f"Error: File '{filename}' does not exist"
        
        # Build command for analysis
        cmd = ["tshark", "-r", filename]
        if filter:
            cmd.extend(["-Y", filter])
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        output = result.stdout
        if result.stderr:
            output += f"\nErrors: {result.stderr}"
        
        return output
    except subprocess.TimeoutExpired:
        return "Error: Timeout during packet analysis"
    except Exception as e:
        return f"Error analyzing packets: {str(e)}"

if __name__ == "__main__":
    app.run()