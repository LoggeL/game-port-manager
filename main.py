from fastapi import FastAPI, Request, Form, HTTPException, Depends, status, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import bcrypt
from jose import JWTError, jwt
from datetime import datetime, timedelta
import subprocess
import sqlite3
import socket
import os
import httpx
from typing import Optional

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-key-change-it")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 1 day
DB_PATH = "/data/users.db"
NPM_URL = os.getenv("NPM_URL", "http://nginx-proxy:81")

# Database initialization
def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS custom_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL UNIQUE,
            proxy_host_id INTEGER NOT NULL,
            proxy_host_name TEXT,
            added_by TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

init_db()

# --- Settings Helpers ---

def get_setting(key: str) -> Optional[str]:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

def set_setting(key: str, value: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()

# --- Auth Helpers ---

def verify_password(plain_password: str, hashed_password: str):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user(username: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT username, password_hash FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return {"username": user[0], "password_hash": user[1]}
    return None

async def get_current_user(request: Request) -> Optional[str]:
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: Optional[str] = payload.get("sub")
        return username
    except JWTError:
        return None

# --- NPM API Helpers ---

async def npm_get_token() -> Optional[str]:
    """Get JWT token from NPM API"""
    email = get_setting("npm_email")
    password = get_setting("npm_password")
    if not email or not password:
        return None
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{NPM_URL}/api/tokens",
                json={"identity": email, "secret": password}
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("token")
    except Exception as e:
        print(f"NPM login error: {e}")
    return None

async def npm_list_proxy_hosts() -> list:
    """List all proxy hosts from NPM"""
    token = await npm_get_token()
    if not token:
        return []
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{NPM_URL}/api/nginx/proxy-hosts",
                headers={"Authorization": f"Bearer {token}"}
            )
            if resp.status_code == 200:
                return resp.json()
    except Exception as e:
        print(f"NPM list error: {e}")
    return []

async def npm_get_proxy_host(host_id: int) -> Optional[dict]:
    """Get a specific proxy host"""
    token = await npm_get_token()
    if not token:
        return None
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{NPM_URL}/api/nginx/proxy-hosts/{host_id}",
                headers={"Authorization": f"Bearer {token}"}
            )
            if resp.status_code == 200:
                return resp.json()
    except Exception as e:
        print(f"NPM get host error: {e}")
    return None

async def npm_update_proxy_host_domains(host_id: int, domains: list) -> bool:
    """Update the domain names for a proxy host"""
    token = await npm_get_token()
    if not token:
        return False
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.put(
                f"{NPM_URL}/api/nginx/proxy-hosts/{host_id}",
                headers={"Authorization": f"Bearer {token}"},
                json={"domain_names": domains}
            )
            return resp.status_code == 200
    except Exception as e:
        print(f"NPM update error: {e}")
    return False

# --- Custom Domains DB Helpers ---

def get_custom_domains() -> list:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, domain, proxy_host_id, proxy_host_name, added_by, created_at FROM custom_domains ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "domain": r[1], "proxy_host_id": r[2], "proxy_host_name": r[3], "added_by": r[4], "created_at": r[5]} for r in rows]

def add_custom_domain(domain: str, proxy_host_id: int, proxy_host_name: str, added_by: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO custom_domains (domain, proxy_host_id, proxy_host_name, added_by) VALUES (?, ?, ?, ?)",
        (domain, proxy_host_id, proxy_host_name, added_by)
    )
    conn.commit()
    conn.close()

def remove_custom_domain(domain_id: int) -> Optional[dict]:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT domain, proxy_host_id FROM custom_domains WHERE id = ?", (domain_id,))
    row = cursor.fetchone()
    if row:
        cursor.execute("DELETE FROM custom_domains WHERE id = ?", (domain_id,))
        conn.commit()
        conn.close()
        return {"domain": row[0], "proxy_host_id": row[1]}
    conn.close()
    return None

# --- Firewall Helpers ---

def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error executing {cmd}: {e.stderr}")
        return None

def get_forwarding_rules():
    output = run_cmd("firewall-cmd --zone=public --list-forward-ports")
    rules = []
    if output:
        raw_rules = output.split()
        for rule_str in raw_rules:
            parts = {}
            for part in rule_str.split(':'):
                if '=' in part:
                    key, val = part.split('=', 1)
                    parts[key] = val
            if parts:
                rules.append(parts)
    return rules

# --- Routes ---

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: Optional[str] = None):
    return templates.TemplateResponse("login.html", {"request": request, "error": error})

@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    user = get_user(username)
    if not user or not verify_password(password, user["password_hash"]):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid username or password"})
    
    access_token = create_access_token(data={"sub": username})
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key="access_token", 
        value=access_token, 
        httponly=True, 
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax"
    )
    return response

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/login")
    response.delete_cookie("access_token")
    return response

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    username = await get_current_user(request)
    if not username:
        return RedirectResponse(url="/login")
    
    rules = get_forwarding_rules()
    proxy_hosts = await npm_list_proxy_hosts()
    custom_domains = get_custom_domains()
    npm_configured = bool(get_setting("npm_email") and get_setting("npm_password"))
    
    return templates.TemplateResponse("index.html", {
        "request": request,
        "rules": rules,
        "user": username,
        "proxy_hosts": proxy_hosts,
        "custom_domains": custom_domains,
        "npm_configured": npm_configured
    })

@app.post("/add")
async def add_rule(
    request: Request,
    port: str = Form(...),
    protocol: str = Form(...),
    toport: Optional[str] = Form(None),
    toaddr: str = Form(...)
):
    username = await get_current_user(request)
    if not username:
        raise HTTPException(status_code=401)

    if not toport:
        toport = port
    
    protos = [protocol]
    if protocol == "both":
        protos = ["tcp", "udp"]
    
    for proto in protos:
        cmd = f"firewall-cmd --zone=public --add-forward-port=port={port}:proto={proto}:toport={toport}:toaddr={toaddr} --permanent"
        run_cmd(cmd)
    
    run_cmd("firewall-cmd --reload")
    return RedirectResponse(url="/", status_code=303)

@app.post("/delete")
async def delete_rule(
    request: Request,
    port: str = Form(...),
    proto: str = Form(...),
    toport: str = Form(...),
    toaddr: str = Form(...)
):
    username = await get_current_user(request)
    if not username:
        raise HTTPException(status_code=401)

    cmd = f"firewall-cmd --zone=public --remove-forward-port=port={port}:proto={proto}:toport={toport}:toaddr={toaddr} --permanent"
    run_cmd(cmd)
    run_cmd("firewall-cmd --reload")
    return RedirectResponse(url="/", status_code=303)

# --- NPM Config Routes ---

@app.post("/npm/config")
async def save_npm_config(
    request: Request,
    npm_email: str = Form(...),
    npm_password: str = Form(...)
):
    username = await get_current_user(request)
    if not username:
        raise HTTPException(status_code=401)
    
    set_setting("npm_email", npm_email)
    set_setting("npm_password", npm_password)
    return RedirectResponse(url="/", status_code=303)

# --- Domain Routes ---

@app.post("/domains/add")
async def add_domain(
    request: Request,
    domain: str = Form(...),
    proxy_host_id: int = Form(...)
):
    username = await get_current_user(request)
    if not username:
        raise HTTPException(status_code=401)
    
    # Clean domain
    domain = domain.lower().strip()
    
    # Get current proxy host
    host = await npm_get_proxy_host(proxy_host_id)
    if not host:
        raise HTTPException(status_code=400, detail="Proxy host not found")
    
    # Add domain to the list
    current_domains = host.get("domain_names", [])
    if domain in current_domains:
        raise HTTPException(status_code=400, detail="Domain already exists on this host")
    
    new_domains = current_domains + [domain]
    
    # Update NPM
    success = await npm_update_proxy_host_domains(proxy_host_id, new_domains)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to update proxy host")
    
    # Save to local DB for tracking
    proxy_host_name = current_domains[0] if current_domains else f"Host #{proxy_host_id}"
    add_custom_domain(domain, proxy_host_id, proxy_host_name, username)
    
    return RedirectResponse(url="/", status_code=303)

@app.post("/domains/delete")
async def delete_domain(
    request: Request,
    domain_id: int = Form(...)
):
    username = await get_current_user(request)
    if not username:
        raise HTTPException(status_code=401)
    
    # Get domain info
    domain_info = remove_custom_domain(domain_id)
    if not domain_info:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    # Get current proxy host
    host = await npm_get_proxy_host(domain_info["proxy_host_id"])
    if host:
        current_domains = host.get("domain_names", [])
        new_domains = [d for d in current_domains if d != domain_info["domain"]]
        
        # Only update if there are remaining domains
        if new_domains:
            await npm_update_proxy_host_domains(domain_info["proxy_host_id"], new_domains)
    
    return RedirectResponse(url="/", status_code=303)

# --- Test Routes ---

@app.get("/api/test/domain/{domain}")
async def test_domain(request: Request, domain: str):
    """Test if a domain resolves and points to this server"""
    username = await get_current_user(request)
    if not username:
        raise HTTPException(status_code=401)
    
    domain = domain.lower().strip()
    results = {
        "domain": domain,
        "dns_resolves": False,
        "dns_ip": None,
        "points_to_server": False,
        "http_reachable": False,
        "https_reachable": False,
        "errors": []
    }
    
    # Get our server's public IP
    server_ip = None
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get("https://api.ipify.org")
            if resp.status_code == 200:
                server_ip = resp.text.strip()
    except Exception:
        pass
    
    # Test DNS resolution
    try:
        ip = socket.gethostbyname(domain)
        results["dns_resolves"] = True
        results["dns_ip"] = ip
        
        if server_ip and ip == server_ip:
            results["points_to_server"] = True
    except socket.gaierror as e:
        results["errors"].append(f"DNS lookup failed: {str(e)}")
    
    # Test HTTP connectivity (if DNS resolves)
    if results["dns_resolves"]:
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                resp = await client.get(f"http://{domain}", headers={"Host": domain})
                results["http_reachable"] = resp.status_code < 500
        except Exception as e:
            results["errors"].append(f"HTTP check failed: {str(e)}")
        
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
                resp = await client.get(f"https://{domain}", headers={"Host": domain})
                results["https_reachable"] = resp.status_code < 500
        except Exception as e:
            results["errors"].append(f"HTTPS check failed: {str(e)}")
    
    return JSONResponse(results)

@app.get("/api/test/npm")
async def test_npm_connection(request: Request):
    """Test NPM API connection"""
    username = await get_current_user(request)
    if not username:
        raise HTTPException(status_code=401)
    
    results = {
        "configured": False,
        "connected": False,
        "proxy_hosts_count": 0,
        "error": None
    }
    
    email = get_setting("npm_email")
    password = get_setting("npm_password")
    
    if not email or not password:
        results["error"] = "NPM credentials not configured"
        return JSONResponse(results)
    
    results["configured"] = True
    
    token = await npm_get_token()
    if not token:
        results["error"] = "Failed to authenticate with NPM"
        return JSONResponse(results)
    
    results["connected"] = True
    
    hosts = await npm_list_proxy_hosts()
    results["proxy_hosts_count"] = len(hosts)
    
    return JSONResponse(results)
