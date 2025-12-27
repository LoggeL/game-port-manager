from fastapi import FastAPI, Request, Form, HTTPException, Depends, status, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import bcrypt
from jose import JWTError, jwt
from datetime import datetime, timedelta
import subprocess
import sqlite3
import os
from typing import Optional

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-key-change-it")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 1 day
DB_PATH = "/data/users.db"

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
    conn.commit()
    conn.close()

init_db()

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
    return templates.TemplateResponse("index.html", {"request": request, "rules": rules, "user": username})

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
