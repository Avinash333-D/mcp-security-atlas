import os
from mcp.server.fastmcp import FastMCP
from dotenv import load_dotenv
import requests
import json

# Load environment variables
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))

app = FastMCP("hackerone-mcp-server")

# Configuration
API_TOKEN = os.getenv("HACKERONE_API_TOKEN")
BASE_URL = "https://api.hackerone.com/v1"

def get_headers():
    return {
        "Authorization": f"Bearer {API_TOKEN}",
        "Accept": "application/json"
    }

@app.tool()
async def get_user_programs() -> str:
    """Get the list of programs the authenticated user has access to."""
    if not API_TOKEN:
        return "Error: HACKERONE_API_TOKEN not set in .env"

    try:
        response = requests.get(f"{BASE_URL}/me/programs", headers=get_headers())
        if response.status_code == 200:
            data = response.json()
            programs = data.get("data", [])
            result = "Your HackerOne Programs:\n"
            for program in programs:
                attributes = program.get("attributes", {})
                handle = attributes.get("handle")
                name = attributes.get("name")
                result += f"- {name} ({handle})\n"
            return result
        else:
            return f"Error: {response.status_code} - {response.text}"
    except Exception as e:
        return f"Error fetching user programs: {str(e)}"

@app.tool()
async def get_program_scope(program_handle: str) -> str:
    """Get the in-scope and out-of-scope assets for a specific program."""
    if not API_TOKEN:
        return "Error: HACKERONE_API_TOKEN not set in .env"

    try:
        response = requests.get(f"{BASE_URL}/programs/{program_handle}", headers=get_headers())
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            relationships = data.get("data", {}).get("relationships", {})

            result = f"Program: {attributes.get('name')} ({program_handle})\n\n"

            # In-scope
            in_scope = []
            if "structured_scopes" in relationships:
                scopes_url = relationships["structured_scopes"]["links"]["related"]
                scopes_response = requests.get(scopes_url, headers=get_headers())
                if scopes_response.status_code == 200:
                    scopes_data = scopes_response.json()
                    for scope in scopes_data.get("data", []):
                        scope_attr = scope.get("attributes", {})
                        if scope_attr.get("eligible_for_bounty"):
                            in_scope.append(scope_attr.get("asset_identifier"))
            if in_scope:
                result += "In Scope:\n" + "\n".join(f"- {asset}" for asset in in_scope) + "\n\n"
            else:
                result += "In Scope: None found\n\n"

            # Out-of-scope
            out_of_scope = []
            if "structured_scopes" in relationships:
                for scope in scopes_data.get("data", []):
                    scope_attr = scope.get("attributes", {})
                    if not scope_attr.get("eligible_for_bounty"):
                        out_of_scope.append(scope_attr.get("asset_identifier"))
            if out_of_scope:
                result += "Out of Scope:\n" + "\n".join(f"- {asset}" for asset in out_of_scope) + "\n\n"
            else:
                result += "Out of Scope: None found\n\n"

            return result
        else:
            return f"Error: {response.status_code} - {response.text}"
    except Exception as e:
        return f"Error fetching program scope: {str(e)}"

@app.tool()
async def update_active_scope(program_handle: str) -> str:
    """Fetch the scope for a program and update active_scope.txt in the workspace."""
    scope_data = await get_program_scope(program_handle)
    if scope_data.startswith("Error"):
        return scope_data

    try:
        # Parse the scope data
        lines = scope_data.split("\n")
        in_scope = []
        out_of_scope = []
        current_section = None
        for line in lines:
            if line.startswith("In Scope:"):
                current_section = "in"
            elif line.startswith("Out of Scope:"):
                current_section = "out"
            elif line.strip().startswith("- ") and current_section:
                asset = line.strip()[2:]
                if current_section == "in":
                    in_scope.append(asset)
                elif current_section == "out":
                    out_of_scope.append(asset)

        # Write to active_scope.txt
        with open("../../active_scope.txt", "w") as f:
            f.write(f"Program: {program_handle}\n")
            f.write("In Scope:\n")
            for asset in in_scope:
                f.write(f"{asset}\n")
            f.write("\nOut of Scope:\n")
            for asset in out_of_scope:
                f.write(f"{asset}\n")

        return f"Updated active_scope.txt with scope for {program_handle}"
    except Exception as e:
        return f"Error updating active_scope.txt: {str(e)}"

@app.tool()
async def get_public_programs(limit: int = 10) -> str:
    """Get a list of public programs from HackerOne directory."""
    try:
        response = requests.get(f"{BASE_URL}/programs", params={"filter[public]": "true", "page[size]": limit})
        if response.status_code == 200:
            data = response.json()
            programs = data.get("data", [])
            result = "Public Programs:\n"
            for program in programs:
                attributes = program.get("attributes", {})
                handle = attributes.get("handle")
                name = attributes.get("name")
                result += f"- {name} ({handle})\n"
            return result
        else:
            return f"Error: {response.status_code} - {response.text}"
    except Exception as e:
        return f"Error fetching public programs: {str(e)}"

if __name__ == "__main__":
    app.run()