import os
from dotenv import load_dotenv
try:
    from pymetasploit3 import msfrpc  # type: ignore
except ImportError as e:
    print(f"Failed to import pymetasploit3: {e}. Please install it with 'pip install pymetasploit3'")
    exit(1)
import json
import self_delete
from pydantic import BaseModel
from fastapi import FastAPI, HTTPException
from typing import Optional

# Load environment variables
load_dotenv()

app = FastAPI(title="metasploit-mcp-server")

# Metasploit Configuration
MSF_RPC_HOST = os.getenv("MSF_RPC_HOST", "localhost")
MSF_RPC_PORT = int(os.getenv("MSF_RPC_PORT", "55553"))
MSF_RPC_USER = os.getenv("MSF_RPC_USER", "msf")
MSF_RPC_PASS = os.getenv("MSF_RPC_PASS", "msf123")

# Global client
msf_client = None

def get_msf_client():
    global msf_client
    if msf_client is None:
        try:
            msf_client = msfrpc.MsfRpcClient(MSF_RPC_PASS, user=MSF_RPC_USER, server=MSF_RPC_HOST, port=MSF_RPC_PORT, ssl=False)
        except Exception as e:
            return None
    return msf_client

# Models
class ExploitRequest(BaseModel):
    module: str
    options: dict = {}

class PayloadRequest(BaseModel):
    payload: str
    options: dict = {}

class SessionRequest(BaseModel):
    session_id: int

class AuxiliaryRequest(BaseModel):
    module: str
    options: dict = {}

class PostRequest(BaseModel):
    module: str
    session_id: int
    options: dict = {}

class PayloadGenerateRequest(BaseModel):
    payload: str
    options: dict = {}
    encoder: Optional[str] = None
    format: str = "raw"

class PayloadEncodeRequest(BaseModel):
    payload_data: str
    encoder: str
    options: dict = {}

class SessionCommandRequest(BaseModel):
    session_id: int
    command: str

@app.get("/")
async def root():
    return {"message": "Metasploit MCP Server is running"}

@app.get("/connect")
async def connect():
    try:
        client = get_msf_client()
        version = client.call('core.version')
        return {"message": f"Connected, version: {version}"}
    except Exception as e:
        return {"error": f"Connection failed: {str(e)}"}

@app.get("/modules/exploits")
async def list_exploits():
    try:
        client = get_msf_client()
        exploits = client.call('module.exploits')
        return {"exploits": list(exploits.keys())}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/modules/payloads")
async def list_payloads():
    try:
        client = get_msf_client()
        payloads = client.call('module.payloads')
        return {"payloads": list(payloads.keys())}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/modules/auxiliary")
async def list_auxiliary():
    try:
        client = get_msf_client()
        auxiliary = client.call('module.auxiliary')
        return {"auxiliary": list(auxiliary.keys())}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/modules/post")
async def list_post():
    try:
        client = get_msf_client()
        post = client.call('module.post')
        return {"post": list(post.keys())}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/modules/encoders")
async def list_encoders():
    try:
        client = get_msf_client()
        encoders = client.call('module.encoders')
        return {"encoders": list(encoders.keys())}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/module/info/{module_type}/{module_name}")
async def module_info(module_type: str, module_name: str):
    try:
        client = get_msf_client()
        info = client.call('module.info', module_type, module_name)
        return info
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/exploit/run")
async def run_exploit(request: ExploitRequest):
    try:
        client = get_msf_client()

        # Use the exploit
        result = client.call('module.use', 'exploit', request.module)

        # Set options
        for key, value in request.options.items():
            client.call('module.set_option', request.module, key, value)

        # Execute
        job_id = client.call('module.execute')

        return {"job_id": job_id, "status": "running"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/auxiliary/run")
async def run_auxiliary(request: AuxiliaryRequest):
    try:
        client = get_msf_client()

        # Use the auxiliary
        result = client.call('module.use', 'auxiliary', request.module)

        # Set options
        for key, value in request.options.items():
            client.call('module.set_option', request.module, key, value)

        # Execute
        job_id = client.call('module.execute')

        return {"job_id": job_id, "status": "running"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/post/run")
async def run_post(request: PostRequest):
    try:
        client = get_msf_client()

        # Use the post
        result = client.call('module.use', 'post', request.module)

        # Set options
        for key, value in request.options.items():
            client.call('module.set_option', request.module, key, value)

        # Set session
        client.call('module.set_option', request.module, 'SESSION', request.session_id)

        # Execute
        job_id = client.call('module.execute')

        return {"job_id": job_id, "status": "running"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/payload/generate")
async def generate_payload(request: PayloadGenerateRequest):
    try:
        client = get_msf_client()

        # Use the payload
        result = client.call('module.use', 'payload', request.payload)

        # Set options
        for key, value in request.options.items():
            client.call('module.set_option', request.payload, key, value)

        # Generate
        payload_data = client.call('payload.generate')

        # If encoder, encode
        if request.encoder:
            # Use encoder
            client.call('module.use', 'encoder', request.encoder)
            # Encode
            encoded = client.call('encoder.encode', payload_data)
            payload_data = encoded

        return {"payload": payload_data, "format": request.format}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/payload/encode")
async def encode_payload(request: PayloadEncodeRequest):
    try:
        client = get_msf_client()

        # Use encoder
        client.call('module.use', 'encoder', request.encoder)

        # Set options
        for key, value in request.options.items():
            client.call('module.set_option', request.encoder, key, value)

        # Encode
        encoded = client.call('encoder.encode', request.payload_data)

        return {"encoded_payload": encoded}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/jobs")
async def list_jobs():
    try:
        client = get_msf_client()
        jobs = client.call('job.list')
        return {"jobs": jobs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/sessions")
async def list_sessions():
    try:
        client = get_msf_client()
        sessions = client.call('session.list')
        return {"sessions": sessions}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/session/info/{session_id}")
async def session_info(session_id: int):
    try:
        client = get_msf_client()
        info = client.call('session.info', session_id)
        return info
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/session/interact")
async def session_interact(request: SessionRequest):
    try:
        client = get_msf_client()
        # Read from session
        output = client.call('session.read', request.session_id)
        return {"output": output}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/session/write")
async def session_write(request: SessionCommandRequest):
    try:
        client = get_msf_client()
        # Write to session
        result = client.call('session.write', request.session_id, request.command + "\n")
        return {"result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/session/command")
async def session_command(request: SessionCommandRequest):
    try:
        client = get_msf_client()
        # Write command
        client.call('session.write', request.session_id, request.command + "\n")
        # Read output
        output = client.call('session.read', request.session_id)
        return {"output": output}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("MCP_SERVER_PORT", "8005")))