#!/usr/bin/env python3
"""
Secure Hospital Management System  (Python Project)
====================================================
Single-file app: Python (Flask + SQLite) backend with an embedded HTML/CSS/JS front end.

Run:
    pip install flask
    python hospital_system.py
    -> open http://127.0.0.1:5001

Security measures (from the project slides)
  * Login required before any private record is shown (session cookie, HttpOnly, SameSite)
  * Role-based access: each user gets only the permissions they need
  * Input validation + error handling on every endpoint (parameterised SQL, output escaping)
  * Passwords stored as salted hashes (never plain text); lock-out after repeated failures
  * CSRF token on every state-changing request, security headers on every response
  * Activity (audit) log of logins, views, changes
  * One-click database backup (admin only)

NOTE: This is a student demo, not ready for real hospital use.
"""
import os, re, secrets, shutil, sqlite3, time
from datetime import date, datetime
from functools import wraps

from flask import Flask, g, jsonify, request, send_file, session
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "hospital.db")
BACKUP_DIR = os.path.join(BASE, "backups")

app = Flask(__name__)
app.secret_key = os.environ.get("HMS_SECRET") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")

MAX_FAILS, LOCK_SECONDS = 5, 120

# ---------------------------------------------------------------- roles
PERMS = {
    "admin":        {"patients.read", "patients.write", "patients.delete", "medical.read", "doctors.read",
                     "doctors.write", "appts.read", "appts.write", "bills.read", "bills.write",
                     "audit.read", "backup", "stats"},
    "doctor":       {"patients.read", "medical.read", "medical.write", "doctors.read", "appts.read",
                     "appts.write", "stats"},
    "receptionist": {"patients.read", "patients.write", "doctors.read", "appts.read", "appts.write", "stats"},
    "billing":      {"patients.read", "doctors.read", "appts.read", "bills.read", "bills.write", "stats"},
}
DEMO_USERS = [  # username, password, role, full name
    ("admin", "Admin@123", "admin", "System Administrator"),
    ("drmeena", "Doctor@123", "doctor", "Dr. Meena Raj"),
    ("reception", "Desk@123", "receptionist", "Front Desk"),
    ("billing", "Bill@123", "billing", "Billing Officer"),
]

# ---------------------------------------------------------------- database
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(_):
    c = g.pop("db", None)
    if c: c.close()

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, pw TEXT, role TEXT, full_name TEXT,
    fails INTEGER DEFAULT 0, locked_until REAL DEFAULT 0);
CREATE TABLE IF NOT EXISTS patients(id INTEGER PRIMARY KEY, name TEXT, age INTEGER, gender TEXT, phone TEXT,
    address TEXT, blood TEXT, diagnosis TEXT DEFAULT '', created TEXT);
CREATE TABLE IF NOT EXISTS doctors(id INTEGER PRIMARY KEY, name TEXT, speciality TEXT, phone TEXT, fee INTEGER);
CREATE TABLE IF NOT EXISTS appointments(id INTEGER PRIMARY KEY, patient_id INTEGER REFERENCES patients(id) ON DELETE CASCADE,
    doctor_id INTEGER REFERENCES doctors(id), day TEXT, slot TEXT, reason TEXT, status TEXT DEFAULT 'Booked');
CREATE TABLE IF NOT EXISTS bills(id INTEGER PRIMARY KEY, patient_id INTEGER REFERENCES patients(id) ON DELETE CASCADE,
    description TEXT, amount REAL, status TEXT DEFAULT 'Pending', created TEXT);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts TEXT, user TEXT, action TEXT, detail TEXT);
"""

def init_db():
    c = sqlite3.connect(DB_PATH)
    c.executescript(SCHEMA)
    if not c.execute("SELECT 1 FROM users").fetchone():
        for u, p, r, n in DEMO_USERS:
            c.execute("INSERT INTO users(username,pw,role,full_name) VALUES(?,?,?,?)", (u, generate_password_hash(p), r, n))
        c.executemany("INSERT INTO doctors(name,speciality,phone,fee) VALUES(?,?,?,?)", [
            ("Dr. Meena Raj", "General Medicine", "9840011111", 400),
            ("Dr. Arun Kumar", "Cardiology", "9840022222", 800),
            ("Dr. Priya Nair", "Paediatrics", "9840033333", 500),
            ("Dr. Vikram Singh", "Orthopaedics", "9840044444", 700)])
        today = date.today().isoformat()
        c.executemany("INSERT INTO patients(name,age,gender,phone,address,blood,diagnosis,created) VALUES(?,?,?,?,?,?,?,?)", [
            ("Ravi Shankar", 45, "Male", "9876543210", "12 Anna Nagar, Chennai", "B+", "Hypertension", today),
            ("Lakshmi Devi", 62, "Female", "9123456780", "5 Gandhi Road, Madurai", "O+", "Type 2 diabetes", today),
            ("Karthik S", 8, "Male", "9988776655", "78 Lake View, Coimbatore", "A+", "Seasonal fever", today)])
    c.commit(); c.close()

def log(action, detail=""):
    db().execute("INSERT INTO audit(ts,user,action,detail) VALUES(?,?,?,?)",
                 (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), session.get("user", "-"), action, detail[:200]))
    db().commit()

# ---------------------------------------------------------------- security helpers
class Bad(Exception):
    def __init__(self, msg, code=400): self.msg, self.code = msg, code

@app.errorhandler(Bad)
def _bad(e): return jsonify(error=e.msg), e.code

@app.errorhandler(Exception)
def _err(e):  # never leak stack traces to the client
    if hasattr(e, "code") and isinstance(e.code, int): return jsonify(error=getattr(e, "name", "Error")), e.code
    app.logger.exception(e)
    return jsonify(error="Something went wrong"), 500

@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "no-referrer"
    r.headers["Cache-Control"] = "no-store"
    r.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    return r

def need(perm=None):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            if "user" not in session: raise Bad("Please log in", 401)
            if request.method not in ("GET", "HEAD"):
                if not secrets.compare_digest(request.headers.get("X-CSRF-Token", ""), session.get("csrf", "x")):
                    raise Bad("Bad CSRF token", 403)
            if perm and perm not in PERMS[session["role"]]:
                log("DENIED", f"{perm} {request.path}")
                raise Bad("You do not have permission for this action", 403)
            return f(*a, **k)
        return w
    return deco

def body():
    d = request.get_json(silent=True)
    if not isinstance(d, dict): raise Bad("Invalid request body")
    return d

def text(d, key, lo=1, hi=100, label=None, required=True):
    v = str(d.get(key, "") or "").strip()
    label = label or key
    if not v and not required: return ""
    if not (lo <= len(v) <= hi): raise Bad(f"{label} must be {lo}-{hi} characters")
    return v

def phone(d):
    v = re.sub(r"[\s-]", "", str(d.get("phone", "")))
    if not re.fullmatch(r"[6-9]\d{9}", v): raise Bad("Phone must be a valid 10-digit mobile number")
    return v

def intval(d, key, lo, hi, label):
    try: v = int(d.get(key))
    except (TypeError, ValueError): raise Bad(f"{label} must be a number")
    if not lo <= v <= hi: raise Bad(f"{label} must be between {lo} and {hi}")
    return v

def row(cur): return [dict(r) for r in cur.fetchall()]

# ---------------------------------------------------------------- auth routes
@app.post("/api/login")
def login():
    d = body()
    u = db().execute("SELECT * FROM users WHERE username=?", (str(d.get("username", "")).strip().lower(),)).fetchone()
    if u and u["locked_until"] > time.time():
        raise Bad(f"Account locked. Try again in {int(u['locked_until'] - time.time())}s", 429)
    if not u or not check_password_hash(u["pw"], str(d.get("password", ""))):
        if u:
            fails = u["fails"] + 1
            lock = time.time() + LOCK_SECONDS if fails >= MAX_FAILS else 0
            db().execute("UPDATE users SET fails=?, locked_until=? WHERE id=?", (0 if lock else fails, lock, u["id"]))
            db().commit()
        session["user"] = str(d.get("username", ""))[:30]; log("LOGIN_FAILED"); session.clear()
        raise Bad("Invalid username or password", 401)
    db().execute("UPDATE users SET fails=0, locked_until=0 WHERE id=?", (u["id"],)); db().commit()
    session.clear()
    session.update(user=u["username"], role=u["role"], name=u["full_name"], csrf=secrets.token_hex(16))
    log("LOGIN")
    return me()

@app.post("/api/logout")
@need()
def logout():
    log("LOGOUT"); session.clear(); return jsonify(ok=True)

@app.get("/api/me")
def me():
    if "user" not in session: return jsonify(user=None)
    return jsonify(user=session["user"], name=session["name"], role=session["role"],
                   perms=sorted(PERMS[session["role"]]), csrf=session["csrf"])

# ---------------------------------------------------------------- patients
@app.get("/api/patients")
@need("patients.read")
def patients():
    q = f"%{request.args.get('q', '').strip()[:40]}%"
    rows = row(db().execute("SELECT * FROM patients WHERE name LIKE ? OR phone LIKE ? OR CAST(id AS TEXT) LIKE ? ORDER BY id DESC", (q, q, q)))
    if "medical.read" not in PERMS[session["role"]]:
        for r in rows: r.pop("diagnosis", None)  # least privilege: hide clinical data
    log("VIEW_PATIENTS", request.args.get("q", ""))
    return jsonify(rows)

def patient_fields(d):
    gender = d.get("gender")
    if gender not in ("Male", "Female", "Other"): raise Bad("Choose a gender")
    blood = d.get("blood")
    if blood not in ("A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"): raise Bad("Choose a blood group")
    return (text(d, "name", 2, 60, "Name"), intval(d, "age", 0, 120, "Age"), gender, phone(d),
            text(d, "address", 3, 120, "Address"), blood)

@app.post("/api/patients")
@need("patients.write")
def add_patient():
    d = body(); f = patient_fields(d)
    cur = db().execute("INSERT INTO patients(name,age,gender,phone,address,blood,created) VALUES(?,?,?,?,?,?,?)",
                       (*f, date.today().isoformat()))
    db().commit(); log("ADD_PATIENT", f"id={cur.lastrowid}")
    return jsonify(id=cur.lastrowid), 201

@app.put("/api/patients/<int:pid>")
@need("patients.write")
def edit_patient(pid):
    d = body(); f = patient_fields(d)
    if not db().execute("SELECT 1 FROM patients WHERE id=?", (pid,)).fetchone(): raise Bad("Patient not found", 404)
    db().execute("UPDATE patients SET name=?,age=?,gender=?,phone=?,address=?,blood=? WHERE id=?", (*f, pid))
    if "medical.write" in PERMS[session["role"]] and "diagnosis" in d:
        db().execute("UPDATE patients SET diagnosis=? WHERE id=?", (text(d, "diagnosis", 0, 200, "Diagnosis", False), pid))
    db().commit(); log("EDIT_PATIENT", f"id={pid}")
    return jsonify(ok=True)

@app.put("/api/patients/<int:pid>/diagnosis")
@need("medical.write")
def diagnosis(pid):
    d = body()
    db().execute("UPDATE patients SET diagnosis=? WHERE id=?", (text(d, "diagnosis", 0, 200, "Diagnosis", False), pid))
    db().commit(); log("EDIT_DIAGNOSIS", f"id={pid}")
    return jsonify(ok=True)

@app.delete("/api/patients/<int:pid>")
@need("patients.delete")
def del_patient(pid):
    db().execute("DELETE FROM patients WHERE id=?", (pid,)); db().commit(); log("DELETE_PATIENT", f"id={pid}")
    return jsonify(ok=True)

# ---------------------------------------------------------------- doctors
@app.get("/api/doctors")
@need("doctors.read")
def doctors(): return jsonify(row(db().execute("SELECT * FROM doctors ORDER BY name")))

@app.post("/api/doctors")
@need("doctors.write")
def add_doctor():
    d = body()
    cur = db().execute("INSERT INTO doctors(name,speciality,phone,fee) VALUES(?,?,?,?)",
        (text(d, "name", 3, 60, "Name"), text(d, "speciality", 2, 50, "Speciality"), phone(d), intval(d, "fee", 0, 100000, "Fee")))
    db().commit(); log("ADD_DOCTOR", f"id={cur.lastrowid}")
    return jsonify(id=cur.lastrowid), 201

# ---------------------------------------------------------------- appointments
SLOTS = [f"{h:02d}:{m:02d}" for h in range(9, 17) for m in (0, 30)]

@app.get("/api/appointments")
@need("appts.read")
def appointments():
    return jsonify(row(db().execute("""SELECT a.*, p.name AS patient, d.name AS doctor, d.speciality FROM appointments a
        JOIN patients p ON p.id=a.patient_id JOIN doctors d ON d.id=a.doctor_id ORDER BY day DESC, slot""")))

@app.post("/api/appointments")
@need("appts.write")
def book():
    d = body()
    pid, did = intval(d, "patient_id", 1, 10**9, "Patient"), intval(d, "doctor_id", 1, 10**9, "Doctor")
    try: day = date.fromisoformat(str(d.get("day")))
    except ValueError: raise Bad("Enter a valid date")
    if day < date.today(): raise Bad("Appointment date cannot be in the past")
    slot = d.get("slot")
    if slot not in SLOTS: raise Bad("Choose a valid time slot (09:00-16:30)")
    if not db().execute("SELECT 1 FROM patients WHERE id=?", (pid,)).fetchone(): raise Bad("Patient not found", 404)
    if not db().execute("SELECT 1 FROM doctors WHERE id=?", (did,)).fetchone(): raise Bad("Doctor not found", 404)
    if db().execute("SELECT 1 FROM appointments WHERE doctor_id=? AND day=? AND slot=? AND status!='Cancelled'",
                    (did, day.isoformat(), slot)).fetchone():
        raise Bad("That doctor already has an appointment in this slot", 409)
    cur = db().execute("INSERT INTO appointments(patient_id,doctor_id,day,slot,reason) VALUES(?,?,?,?,?)",
                       (pid, did, day.isoformat(), slot, text(d, "reason", 0, 120, "Reason", False)))
    db().commit(); log("BOOK_APPT", f"id={cur.lastrowid}")
    return jsonify(id=cur.lastrowid), 201

@app.patch("/api/appointments/<int:aid>")
@need("appts.write")
def appt_status(aid):
    st = body().get("status")
    if st not in ("Booked", "Completed", "Cancelled"): raise Bad("Invalid status")
    db().execute("UPDATE appointments SET status=? WHERE id=?", (st, aid)); db().commit(); log("APPT_STATUS", f"id={aid} {st}")
    return jsonify(ok=True)

# ---------------------------------------------------------------- billing
@app.get("/api/bills")
@need("bills.read")
def bills():
    return jsonify(row(db().execute("SELECT b.*, p.name AS patient FROM bills b JOIN patients p ON p.id=b.patient_id ORDER BY b.id DESC")))

@app.post("/api/bills")
@need("bills.write")
def add_bill():
    d = body()
    pid = intval(d, "patient_id", 1, 10**9, "Patient")
    if not db().execute("SELECT 1 FROM patients WHERE id=?", (pid,)).fetchone(): raise Bad("Patient not found", 404)
    try: amt = round(float(d.get("amount")), 2)
    except (TypeError, ValueError): raise Bad("Amount must be a number")
    if not 0 < amt <= 1_000_000: raise Bad("Amount must be between 1 and 10,00,000")
    cur = db().execute("INSERT INTO bills(patient_id,description,amount,created) VALUES(?,?,?,?)",
                       (pid, text(d, "description", 2, 120, "Description"), amt, date.today().isoformat()))
    db().commit(); log("ADD_BILL", f"id={cur.lastrowid} amt={amt}")
    return jsonify(id=cur.lastrowid), 201

@app.patch("/api/bills/<int:bid>")
@need("bills.write")
def pay_bill(bid):
    db().execute("UPDATE bills SET status='Paid' WHERE id=?", (bid,)); db().commit(); log("PAY_BILL", f"id={bid}")
    return jsonify(ok=True)

# ---------------------------------------------------------------- dashboard / audit / backup
@app.get("/api/stats")
@need("stats")
def stats():
    q = lambda s, *a: db().execute(s, a).fetchone()[0]
    out = dict(patients=q("SELECT COUNT(*) FROM patients"), doctors=q("SELECT COUNT(*) FROM doctors"),
               today=q("SELECT COUNT(*) FROM appointments WHERE day=? AND status='Booked'", date.today().isoformat()))
    if "bills.read" in PERMS[session["role"]]:
        out["pending"] = q("SELECT COALESCE(SUM(amount),0) FROM bills WHERE status='Pending'")
        out["collected"] = q("SELECT COALESCE(SUM(amount),0) FROM bills WHERE status='Paid'")
    return jsonify(out)

@app.get("/api/audit")
@need("audit.read")
def audit(): return jsonify(row(db().execute("SELECT * FROM audit ORDER BY id DESC LIMIT 150")))

@app.post("/api/backup")
@need("backup")
def backup():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    path = os.path.join(BACKUP_DIR, f"hospital_{datetime.now():%Y%m%d_%H%M%S}.db")
    src = sqlite3.connect(DB_PATH); dst = sqlite3.connect(path); src.backup(dst); dst.close(); src.close()
    log("BACKUP", os.path.basename(path))
    return send_file(path, as_attachment=True, download_name=os.path.basename(path))

@app.get("/")
def index():
    demo = "".join(f'<code data-u="{u}" data-p="{p}">{u}</code> {r}<br>' for u, p, r, _ in DEMO_USERS)
    return PAGE.replace("%%DEMO%%", demo)  # plain replace: the page's CSS/JS contain braces Jinja would misread

# ---------------------------------------------------------------- front end
PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Secure Hospital Management System</title>
<style>
:root{--bg:#f2f7f8;--card:#fff;--ink:#12303a;--mut:#5f7b85;--line:#d9e6ea;--pri:#0f7f8f;--pri-d:#0b6471;--dang:#c92a2a;--ok:#2b8a3e;--warn:#e67700;--side:#0d3b45}
@media(prefers-color-scheme:dark){:root{--bg:#0c1a1f;--card:#14272e;--ink:#e6f3f6;--mut:#8fb0ba;--line:#244049;--pri:#2bb5c8;--pri-d:#4fd0e2;--side:#091418}}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 "Segoe UI",system-ui,sans-serif;background:var(--bg);color:var(--ink)}
.hide{display:none!important}
button{font:inherit;cursor:pointer}
.btn{background:var(--pri);color:#fff;border:0;padding:9px 16px;border-radius:9px;font-weight:600}.btn:hover{background:var(--pri-d)}
.btn.sm{padding:4px 10px;font-size:.82rem}.btn.alt{background:transparent;color:var(--pri);border:1px solid var(--pri)}.btn.red{background:var(--dang)}.btn.grn{background:var(--ok)}
input,select,textarea{width:100%;font:inherit;padding:9px 11px;border:1px solid var(--line);border-radius:9px;background:var(--bg);color:var(--ink)}
label{display:block;font-size:.78rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--mut);margin:12px 0 4px}
/* login */
#login{min-height:100vh;display:grid;place-items:center;padding:16px;background:linear-gradient(135deg,#0d3b45,#0f7f8f)}
.lbox{background:var(--card);padding:30px;border-radius:20px;width:100%;max-width:400px;box-shadow:0 20px 60px rgba(0,0,0,.3)}
.lbox h1{margin:0 0 2px;font-size:1.4rem}.lbox p{margin:0;color:var(--mut)}
.demo{margin-top:18px;font-size:.8rem;color:var(--mut);border-top:1px dashed var(--line);padding-top:12px}
.demo code{background:var(--bg);padding:1px 6px;border-radius:5px;cursor:pointer}
.err{color:var(--dang);font-size:.88rem;min-height:1.3em;margin-top:8px}
/* app */
#app{display:grid;grid-template-columns:230px 1fr;min-height:100vh}
@media(max-width:780px){#app{grid-template-columns:1fr}aside{flex-direction:row!important;flex-wrap:wrap;align-items:center}}
aside{background:var(--side);color:#cfe7ec;padding:18px 12px;display:flex;flex-direction:column;gap:4px}
aside h2{margin:0 8px 14px;font-size:1.05rem;color:#fff}
aside button{background:none;border:0;color:inherit;text-align:left;padding:10px 12px;border-radius:9px}
aside button.on,aside button:hover{background:rgba(255,255,255,.12);color:#fff}
.who{margin-top:auto;font-size:.82rem;padding:10px 12px;border-top:1px solid rgba(255,255,255,.15)}
.role{display:inline-block;background:var(--pri);color:#fff;padding:1px 9px;border-radius:99px;font-size:.72rem;font-weight:700;text-transform:uppercase}
main{padding:22px;max-width:1100px;width:100%}
.head{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:14px}.head h2{margin:0}
.tools{display:flex;gap:8px}.tools input{width:240px}
.panel{background:var(--card);border:1px solid var(--line);border-radius:14px;overflow:auto}
table{width:100%;border-collapse:collapse;font-size:.9rem}th,td{padding:10px 12px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap}
th{font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;color:var(--mut)}tr:last-child td{border:0}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-bottom:18px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px}.stat b{display:block;font-size:1.7rem}.stat span{color:var(--mut);font-size:.85rem}
.tag{padding:2px 10px;border-radius:99px;font-size:.75rem;font-weight:700;background:var(--bg)}
.Booked,.Pending{color:var(--warn)}.Completed,.Paid{color:var(--ok)}.Cancelled{color:var(--dang)}
.note{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--warn);border-radius:10px;padding:10px 14px;font-size:.85rem;color:var(--mut);margin-top:16px}
/* modal */
#modal{position:fixed;inset:0;background:rgba(0,0,0,.5);display:grid;place-items:center;padding:16px;z-index:9}
.mbox{background:var(--card);border-radius:16px;padding:22px;width:100%;max-width:460px;max-height:92vh;overflow:auto}
.mbox h3{margin:0 0 4px}.g2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
#toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#12303a;color:#fff;padding:10px 18px;border-radius:10px;z-index:20;box-shadow:0 8px 24px rgba(0,0,0,.3)}
#toast.bad{background:var(--dang)}
</style></head><body>

<section id="login">
 <form class="lbox" id="lf" autocomplete="off">
  <h1>🏥 Secure Hospital System</h1><p>Please log in to access patient records.</p>
  <label for="lu">Username</label><input id="lu" required autofocus>
  <label for="lp">Password</label><input id="lp" type="password" required>
  <div class="err" id="lerr" role="alert"></div>
  <button class="btn" style="width:100%;margin-top:6px">Log in</button>
  <div class="demo"><b>Demo accounts</b> (click to fill):<br>
   %%DEMO%%</div>
 </form>
</section>

<div id="app" class="hide">
 <aside><h2>🏥 HMS</h2><div id="nav" style="display:contents"></div>
  <div class="who"><div id="whoName"></div><span class="role" id="whoRole"></span><br><button id="out" style="padding:6px 0;margin-top:6px;color:#ffb3b3">Log out</button></div></aside>
 <main><div id="view"></div></main>
</div>

<div id="modal" class="hide"><div class="mbox" id="mbox"></div></div>
<div id="toast" class="hide"></div>

<script>
const $=s=>document.querySelector(s);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let U=null, page='dash', idle;

async function api(path,method='GET',data){
  const r=await fetch('/api/'+path,{method,headers:{'Content-Type':'application/json','X-CSRF-Token':U?.csrf||''},body:data?JSON.stringify(data):undefined});
  if(r.status===401&&U){U=null;showLogin('Session expired. Please log in again.');throw new Error('expired')}
  if(r.headers.get('content-disposition')) return r;
  const j=await r.json(); if(!r.ok) throw new Error(j.error||'Error'); return j;
}
function toast(m,bad){const t=$('#toast');t.textContent=m;t.className=bad?'bad':'';clearTimeout(t.h);t.h=setTimeout(()=>t.className='hide',3200)}
const can=p=>U.perms.includes(p);
const guard=f=>async(...a)=>{try{return await f(...a)}catch(e){if(e.message!=='expired')toast(e.message,true)}};

// ---------- login / session
function showLogin(msg){$('#app').classList.add('hide');$('#login').classList.remove('hide');$('#lerr').textContent=msg||'';$('#lp').value=''}
document.querySelectorAll('.demo code').forEach(c=>c.onclick=()=>{$('#lu').value=c.dataset.u;$('#lp').value=c.dataset.p});
$('#lf').onsubmit=async e=>{e.preventDefault();try{U=await api('login','POST',{username:$('#lu').value,password:$('#lp').value});start()}catch(x){$('#lerr').textContent=x.message}};
$('#out').onclick=async()=>{await api('logout','POST');U=null;showLogin('You have been logged out.')};
function resetIdle(){clearTimeout(idle);if(U)idle=setTimeout(()=>{if(U){api('logout','POST').catch(()=>{});U=null;showLogin('Logged out after 10 minutes of inactivity.')}},600000)}
['click','keydown'].forEach(ev=>document.addEventListener(ev,resetIdle));

const MENU=[['dash','📊 Dashboard',0],['patients','🧑 Patients','patients.read'],['doctors','🩺 Doctors','doctors.read'],
 ['appts','📅 Appointments','appts.read'],['bills','💳 Billing','bills.read'],['audit','🛡️ Activity log','audit.read']];
function start(){
  $('#login').classList.add('hide');$('#app').classList.remove('hide');
  $('#whoName').textContent=U.name;$('#whoRole').textContent=U.role;
  $('#nav').innerHTML=MENU.filter(m=>!m[2]||can(m[2])).map(m=>`<button data-p="${m[0]}">${m[1]}</button>`).join('');
  document.querySelectorAll('#nav button').forEach(b=>b.onclick=()=>go(b.dataset.p));
  resetIdle();go('dash');
}
const go=guard(async p=>{page=p;document.querySelectorAll('#nav button').forEach(b=>b.classList.toggle('on',b.dataset.p===p));await VIEWS[p]()});

// ---------- modal
function modal(html){$('#mbox').innerHTML=html;$('#modal').classList.remove('hide')}
function closeM(){$('#modal').classList.add('hide')}
$('#modal').onclick=e=>{if(e.target.id==='modal')closeM()};
const val=id=>$('#'+id).value;
const opts=(arr,v,l)=>arr.map(x=>`<option value="${esc(x[v])}">${esc(typeof l==='function'?l(x):x[l])}</option>`).join('');

const VIEWS={
 async dash(){
  const s=await api('stats');
  $('#view').innerHTML=`<div class="head"><h2>Welcome, ${esc(U.name)}</h2></div><div class="stats">
   <div class="stat"><b>${s.patients}</b><span>Registered patients</span></div>
   <div class="stat"><b>${s.doctors}</b><span>Doctors</span></div>
   <div class="stat"><b>${s.today}</b><span>Booked today</span></div>
   ${s.pending!==undefined?`<div class="stat"><b>₹${s.pending.toLocaleString('en-IN')}</b><span>Pending bills</span></div><div class="stat"><b>₹${s.collected.toLocaleString('en-IN')}</b><span>Collected</span></div>`:''}</div>
   <div class="panel" style="padding:16px"><b>Your access (${esc(U.role)})</b><p style="color:var(--mut);margin:6px 0 0">${U.perms.map(p=>`<span class="tag">${esc(p)}</span>`).join(' ')}</p></div>
   <div class="note">⚠️ Student demo — not ready for real hospital use. Real systems need HTTPS, encrypted storage, tested backups and compliance with privacy law.</div>`;
 },
 async patients(q=''){
  const rows=await api('patients?q='+encodeURIComponent(q)); const med=can('medical.read');
  $('#view').innerHTML=`<div class="head"><h2>Patients</h2><div class="tools"><input id="pq" placeholder="Search name, phone or ID" value="${esc(q)}">
   ${can('patients.write')?'<button class="btn" id="addP">+ Register</button>':''}</div></div>
   <div class="panel"><table><tr><th>ID</th><th>Name</th><th>Age</th><th>Gender</th><th>Phone</th><th>Blood</th>${med?'<th>Diagnosis</th>':''}<th></th></tr>
   ${rows.map(p=>`<tr><td>${p.id}</td><td>${esc(p.name)}</td><td>${p.age}</td><td>${esc(p.gender)}</td><td>${esc(p.phone)}</td><td>${esc(p.blood)}</td>${med?`<td>${esc(p.diagnosis)}</td>`:''}
   <td>${can('patients.write')||can('medical.write')?`<button class="btn sm alt" data-e="${p.id}">Edit</button> `:''}${can('patients.delete')?`<button class="btn sm red" data-d="${p.id}">Delete</button>`:''}</td></tr>`).join('')||'<tr><td colspan=8>No patients found.</td></tr>'}</table></div>
   ${med?'':'<div class="note">Diagnosis details are hidden for your role (least-privilege access).</div>'}`;
  let t;$('#pq').oninput=e=>{clearTimeout(t);t=setTimeout(guard(()=>VIEWS.patients(e.target.value)),300);};
  const f=$('#pq');f.focus();f.setSelectionRange(99,99);
  $('#addP')&&($('#addP').onclick=()=>patientForm());
  document.querySelectorAll('[data-e]').forEach(b=>b.onclick=()=>patientForm(rows.find(r=>r.id==b.dataset.e)));
  document.querySelectorAll('[data-d]').forEach(b=>b.onclick=guard(async()=>{if(confirm('Delete this patient and all their appointments and bills?')){await api('patients/'+b.dataset.d,'DELETE');toast('Patient deleted');VIEWS.patients()}}));
 },
 async doctors(){
  const rows=await api('doctors');
  $('#view').innerHTML=`<div class="head"><h2>Doctors</h2>${can('doctors.write')?'<button class="btn" id="addD">+ Add doctor</button>':''}</div>
  <div class="panel"><table><tr><th>Name</th><th>Speciality</th><th>Phone</th><th>Fee</th></tr>${rows.map(d=>`<tr><td>${esc(d.name)}</td><td>${esc(d.speciality)}</td><td>${esc(d.phone)}</td><td>₹${d.fee}</td></tr>`).join('')}</table></div>`;
  $('#addD')&&($('#addD').onclick=()=>modal(`<h3>Add doctor</h3><label>Name</label><input id="dn"><label>Speciality</label><input id="ds">
   <div class="g2"><div><label>Phone</label><input id="dp" inputmode="numeric"></div><div><label>Fee (₹)</label><input id="df" type="number" min="0"></div></div>
   <p style="margin-top:16px"><button class="btn" id="sv">Save</button> <button class="btn alt" onclick="closeM()">Cancel</button></p>`)||($('#sv').onclick=guard(async()=>{
   await api('doctors','POST',{name:val('dn'),speciality:val('ds'),phone:val('dp'),fee:val('df')});closeM();toast('Doctor added');VIEWS.doctors()})));
 },
 async appts(){
  const rows=await api('appointments');
  $('#view').innerHTML=`<div class="head"><h2>Appointments</h2>${can('appts.write')?'<button class="btn" id="addA">+ Book</button>':''}</div>
  <div class="panel"><table><tr><th>Date</th><th>Time</th><th>Patient</th><th>Doctor</th><th>Reason</th><th>Status</th><th></th></tr>
  ${rows.map(a=>`<tr><td>${a.day}</td><td>${a.slot}</td><td>${esc(a.patient)}</td><td>${esc(a.doctor)}<br><small style="color:var(--mut)">${esc(a.speciality)}</small></td><td>${esc(a.reason)}</td><td><span class="tag ${a.status}">${a.status}</span></td>
  <td>${can('appts.write')&&a.status==='Booked'?`<button class="btn sm grn" data-c="${a.id}">Complete</button> <button class="btn sm red" data-x="${a.id}">Cancel</button>`:''}</td></tr>`).join('')||'<tr><td colspan=7>No appointments yet.</td></tr>'}</table></div>`;
  const st=(id,s)=>guard(async()=>{await api('appointments/'+id,'PATCH',{status:s});VIEWS.appts()});
  document.querySelectorAll('[data-c]').forEach(b=>b.onclick=st(b.dataset.c,'Completed'));
  document.querySelectorAll('[data-x]').forEach(b=>b.onclick=st(b.dataset.x,'Cancelled'));
  $('#addA')&&($('#addA').onclick=guard(async()=>{
   const [ps,ds]=await Promise.all([api('patients'),api('doctors')]);const slots=[];for(let h=9;h<17;h++)for(const m of['00','30'])slots.push(String(h).padStart(2,'0')+':'+m);
   const today=new Date().toISOString().slice(0,10);
   modal(`<h3>Book appointment</h3><label>Patient</label><select id="ap">${opts(ps,'id',p=>p.id+' · '+p.name)}</select>
   <label>Doctor</label><select id="ad">${opts(ds,'id',d=>d.name+' — '+d.speciality)}</select>
   <div class="g2"><div><label>Date</label><input id="adt" type="date" min="${today}" value="${today}"></div><div><label>Time slot</label><select id="asl">${slots.map(s=>`<option>${s}</option>`).join('')}</select></div></div>
   <label>Reason</label><input id="ar" maxlength="120"><p style="margin-top:16px"><button class="btn" id="sv">Book</button> <button class="btn alt" onclick="closeM()">Cancel</button></p>`);
   $('#sv').onclick=guard(async()=>{await api('appointments','POST',{patient_id:val('ap'),doctor_id:val('ad'),day:val('adt'),slot:val('asl'),reason:val('ar')});closeM();toast('Appointment booked');VIEWS.appts()});}));
 },
 async bills(){
  const rows=await api('bills');
  $('#view').innerHTML=`<div class="head"><h2>Billing</h2>${can('bills.write')?'<button class="btn" id="addB">+ New bill</button>':''}</div>
  <div class="panel"><table><tr><th>Bill #</th><th>Date</th><th>Patient</th><th>Description</th><th>Amount</th><th>Status</th><th></th></tr>
  ${rows.map(b=>`<tr><td>${b.id}</td><td>${b.created}</td><td>${esc(b.patient)}</td><td>${esc(b.description)}</td><td>₹${b.amount.toLocaleString('en-IN')}</td><td><span class="tag ${b.status}">${b.status}</span></td>
  <td>${can('bills.write')&&b.status==='Pending'?`<button class="btn sm grn" data-p="${b.id}">Mark paid</button>`:''}</td></tr>`).join('')||'<tr><td colspan=7>No bills yet.</td></tr>'}</table></div>`;
  document.querySelectorAll('[data-p]').forEach(b=>b.onclick=guard(async()=>{await api('bills/'+b.dataset.p,'PATCH');VIEWS.bills()}));
  $('#addB')&&($('#addB').onclick=guard(async()=>{const ps=await api('patients');
   modal(`<h3>New bill</h3><label>Patient</label><select id="bp">${opts(ps,'id',p=>p.id+' · '+p.name)}</select><label>Description</label><input id="bd" placeholder="Consultation, lab test…">
   <label>Amount (₹)</label><input id="ba" type="number" min="1" step="0.01"><p style="margin-top:16px"><button class="btn" id="sv">Create</button> <button class="btn alt" onclick="closeM()">Cancel</button></p>`);
   $('#sv').onclick=guard(async()=>{await api('bills','POST',{patient_id:val('bp'),description:val('bd'),amount:val('ba')});closeM();toast('Bill created');VIEWS.bills()})}));
 },
 async audit(){
  const rows=await api('audit');
  $('#view').innerHTML=`<div class="head"><h2>Activity log</h2>${can('backup')?'<button class="btn" id="bk">⬇ Backup database</button>':''}</div>
  <div class="panel"><table><tr><th>Time</th><th>User</th><th>Action</th><th>Detail</th></tr>${rows.map(a=>`<tr><td>${a.ts}</td><td>${esc(a.user)}</td><td><span class="tag ${/FAILED|DENIED/.test(a.action)?'Cancelled':''}">${esc(a.action)}</span></td><td>${esc(a.detail)}</td></tr>`).join('')}</table></div>`;
  $('#bk')&&($('#bk').onclick=guard(async()=>{const r=await api('backup','POST');const b=await r.blob();const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='hospital_backup.db';a.click();toast('Backup saved');}));
 }
};

function patientForm(p){
  const e=!!p;p=p||{};const bg=['A+','A-','B+','B-','AB+','AB-','O+','O-'];
  const sel=(a,v)=>a.map(x=>`<option ${x===v?'selected':''}>${x}</option>`).join('');
  modal(`<h3>${e?'Edit patient':'Register patient'}</h3><label>Full name</label><input id="pn" value="${esc(p.name)}" maxlength="60">
  <div class="g2"><div><label>Age</label><input id="pa" type="number" min="0" max="120" value="${esc(p.age)}"></div><div><label>Gender</label><select id="pg">${sel(['Male','Female','Other'],p.gender)}</select></div></div>
  <div class="g2"><div><label>Phone</label><input id="pp" inputmode="numeric" value="${esc(p.phone)}" maxlength="10"></div><div><label>Blood group</label><select id="pb">${sel(bg,p.blood)}</select></div></div>
  <label>Address</label><input id="pad" value="${esc(p.address)}" maxlength="120">
  ${can('medical.write')?`<label>Diagnosis</label><input id="pdx" value="${esc(p.diagnosis)}" maxlength="200">`:''}
  <p style="margin-top:16px"><button class="btn" id="sv">Save</button> <button class="btn alt" onclick="closeM()">Cancel</button></p>`);
  $('#sv').onclick=guard(async()=>{
    const d={name:val('pn'),age:val('pa'),gender:val('pg'),phone:val('pp'),blood:val('pb'),address:val('pad')};
    if($('#pdx'))d.diagnosis=val('pdx');
    if(e){if(can('patients.write'))await api('patients/'+p.id,'PUT',d);else await api('patients/'+p.id+'/diagnosis','PUT',{diagnosis:d.diagnosis})}
    else await api('patients','POST',d);
    closeM();toast('Saved');VIEWS.patients()});
}

(async()=>{try{const m=await api('me');if(m.user){U=m;start()}}catch(e){}})();
</script></body></html>
"""

if __name__ == "__main__":
    init_db()
    print("Secure Hospital Management System -> http://127.0.0.1:5001")
    app.run(port=5001, debug=False)
