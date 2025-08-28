# app.py (refactored: templates split into templates/*.html)
import os, math, re, signal, time, subprocess, sys
from datetime import datetime, timezone
from functools import lru_cache, wraps
from urllib.parse import urlencode

from celery.result import AsyncResult
from worker.celery_app import celery
from worker.tasks import run_fetch_and_reco, run_fetch_user_rss_once

import requests
from flask import (
    Flask, request, redirect, url_for, render_template,
    render_template_string,  # still used for a couple of tiny pages
    make_response, abort, session, flash, jsonify
)
from pymongo import MongoClient
from dateutil import parser as dateparser
from bson import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash

# Optional content extraction
try:
    from readability import Document
except Exception:
    Document = None
try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None

# ----------------- Environment -----------------
MONGODB_URI = os.getenv(
    "MONGODB_URI",
    "mongodb+srv://yzhang850:a237342160@cluster0.cficuai.mongodb.net/?retryWrites=true&w=majority&authSource=admin"
)
DB_NAME = os.getenv("DB_NAME", "cti_platform")
COLL_NAME = os.getenv("COLL_NAME", "threats")
SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-key")
NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()

ROLES = ["public", "pro", "admin"]
ROLE_ORDER = {r: i for i, r in enumerate(ROLES)}

# Sources (removed "user")
ARTICLE_SOURCES = ["krebsonsecurity", "msrc_blog", "cisa_kev", "nvd", "exploitdb"]

# Minimum role per built-in source
SOURCE_ROLE = {
    "krebsonsecurity": "public",
    "msrc_blog": "public",
    "cisa_kev": "pro",
    "nvd": "admin",
    "exploitdb": "admin",
}

SOURCE_STYLE = {
    "krebsonsecurity": {"name": "KrebsOnSecurity", "badge": "success", "icon": "🕵️"},
    "msrc_blog":       {"name": "MSRC Blog",       "badge": "primary", "icon": "🛡"},
    "cisa_kev":        {"name": "CISA KEV",        "badge": "warning", "icon": "⚠️"},
    "nvd":             {"name": "NVD (CVE)",       "badge": "danger",  "icon": "📊"},
    "exploitdb":       {"name": "Exploit-DB",      "badge": "dark",    "icon": "💥"},
}

# ----------------- Flask & Mongo -----------------
app = Flask(__name__)
app.secret_key = SECRET_KEY
mongo = MongoClient(MONGODB_URI)
coll = mongo[DB_NAME][COLL_NAME]
sources_coll = mongo[DB_NAME]["custom_sources"]
users_coll = mongo[DB_NAME]["users"]
# New isolated collections for per-user RSS
user_rss_sources_coll = mongo[DB_NAME]["user_rss_sources"]
user_rss_items_coll   = mongo[DB_NAME]["user_rss_items"]

# ----------------- Utilities -----------------
def parse_dt(s):
    if not s: return None
    try: return dateparser.parse(s)
    except Exception: return None

def role_allows(current_role: str, min_role: str) -> bool:
    return ROLE_ORDER.get(current_role, 0) >= ROLE_ORDER.get(min_role, 0)

def fmt_ts(ts, fmt="%Y-%m-%d %H:%M:%S"):
    if not ts: return ""
    if isinstance(ts, datetime): return ts.strftime(fmt)
    if isinstance(ts, str):
        try:
            dt = dateparser.parse(ts); return dt.strftime(fmt) if dt else ""
        except Exception: return ts
    return ""

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
def extract_cves_from_text(txt: str):
    if not txt: return []
    return sorted(set(m.upper() for m in CVE_RE.findall(txt)))

def brief_for_public(text: str, length=200):
    if not text: return ""
    t = re.sub(r"<[^>]+>", " ", text)
    t = re.sub(r"\s+", " ", t).strip()
    return t[:length] + ("…" if len(t) > length else "")

def threat_points_for_pro(text: str):
    if not text: return ""
    body = re.sub(r"<[^>]+>", " ", text)
    body = re.sub(r"\s+", " ", body)
    sentences = re.split(r"(?<=[。.!?])\s+", body)
    SIGNALS = ("critical", "remote execution", "RCE", "exploit", "zero-day",
               "in the wild", "privilege escalation", "bypass", "vulnerability", "attack")
    picked = [s for s in sentences if any(k.lower() in s.lower() for k in SIGNALS)]
    if not picked and sentences: picked = sentences[:2]
    return " ".join(picked[:2])

def extract_main_content(html: str):
    title = ""; text = ""
    if Document:
        try:
            doc = Document(html)
            title = (doc.short_title() or "").strip()
            summary_html = doc.summary()
            text = re.sub(r"<[^>]+>", " ", summary_html or "")
        except Exception:
            pass
    if not text and BeautifulSoup:
        try:
            soup = BeautifulSoup(html, "html.parser")
            article = soup.find("article") or soup
            paras = [p.get_text(" ", strip=True) for p in article.find_all("p")]
            text = " ".join(paras).strip()
            if not title and soup.title and soup.title.string:
                title = soup.title.string.strip()
        except Exception:
            pass
    if not text:
        text = re.sub(r"<[^>]+>", " ", html or "")
    text = re.sub(r"\s+", " ", text).strip()
    return title, text

# ----------------- Current user / auth helpers -----------------
def get_current_user():
    uid = session.get("uid")
    if not uid:
        return None
    try:
        return users_coll.find_one({"_id": ObjectId(uid)})
    except Exception:
        return None

def current_user_id():
    u = get_current_user()
    return u["_id"] if u else None

def current_username():
    u = get_current_user()
    return u["username"] if u else None

def current_role() -> str:
    u = get_current_user()
    return u["role"] if u and u.get("role") in ROLES else "public"

def login_required(view):
    @wraps(view)
    def _wrapped(*args, **kwargs):
        if not get_current_user():
            return redirect(url_for("auth_login_get", next=request.path))
        return view(*args, **kwargs)
    return _wrapped

@app.context_processor
def inject_helpers():
    return dict(
        SOURCE_STYLE=SOURCE_STYLE,
        extract_cves_from_text=extract_cves_from_text,
        brief_for_public=brief_for_public,
        threat_points_for_pro=threat_points_for_pro,
        fmt_ts=fmt_ts,
        current_user=get_current_user(),
        ROLES=ROLES
    )

# ----------------- NVD API (for /cve/<id>) -----------------
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
def _nvd_headers():
    h = {"User-Agent": "cti-portal/1.0"}
    if NVD_API_KEY: h["apiKey"] = NVD_API_KEY
    return h

@lru_cache(maxsize=256)
def nvd_get_cve_raw(cve_id: str):
    r = requests.get(NVD_API, params={"cveId": cve_id}, headers=_nvd_headers(), timeout=15)
    r.raise_for_status()
    return r.json()

def nvd_parse_summary(nvd_json: dict):
    vulns = (nvd_json or {}).get("vulnerabilities") or []
    if not vulns: return {}
    cve = vulns[0].get("cve") or {}
    descriptions = cve.get("descriptions") or []
    desc = ""
    for d in descriptions:
        if d.get("lang") == "en":
            desc = d.get("value","")
            break
    metrics = cve.get("metrics") or {}
    cvss = {}
    for key in ("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
        if metrics.get(key):
            m = metrics[key][0]; data = m.get("cvssData", {})
            cvss = {
                "version": data.get("version"),
                "baseScore": data.get("baseScore"),
                "baseSeverity": m.get("baseSeverity"),
                "vectorString": data.get("vectorString"),
                "exploitabilityScore": m.get("exploitabilityScore"),
                "impactScore": m.get("impactScore"),
            }
            break
    weaknesses = []
    for w in (cve.get("weaknesses") or []):
        for d in (w.get("description") or []):
            if d.get("value"): weaknesses.append(d["value"])
    weaknesses = sorted(set(weaknesses))
    refs = []
    for r in (cve.get("references") or []):
        refs.append({"url": r.get("url"), "tags": r.get("tags") or []})
    return {"id": cve.get("id"), "description": desc, "cvss": cvss, "weaknesses": weaknesses, "references": refs}

# ----------------- Auth: login / register / logout -----------------
@app.get("/auth/login")
def auth_login_get():
    return render_template("auth.html", mode="login", next=request.args.get("next") or "")

@app.post("/auth/login")
def auth_login_post():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    next_url = (request.form.get("next") or "").strip() or url_for("feed")
    u = users_coll.find_one({"username": username})
    if not u or not check_password_hash(u.get("password",""), password):
        flash("Invalid username or password", "danger")
        return render_template("auth.html", mode="login", next=next_url)
    session["uid"] = str(u["_id"])
    return redirect(next_url)

@app.get("/auth/register")
def auth_register_get():
    return render_template("auth.html", mode="register", next=request.args.get("next") or "")

@app.post("/auth/register")
def auth_register_post():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    role = (request.form.get("role") or "public").strip()
    next_url = (request.form.get("next") or "").strip() or url_for("feed")
    if role not in ROLES:
        role = "public"
    if not username or not password:
        flash("Please enter username and password", "warning")
        return render_template("auth.html", mode="register", next=next_url)
    if users_coll.find_one({"username": username}):
        flash("Username already exists", "warning")
        return render_template("auth.html", mode="register", next=next_url)

    u = {
        "username": username,
        "password": generate_password_hash(password),
        "role": role,
        "created_at": datetime.now(timezone.utc)
    }
    r = users_coll.insert_one(u)
    session["uid"] = str(r.inserted_id)
    return redirect(next_url)

@app.get("/auth/logout")
def auth_logout():
    session.pop("uid", None)
    return redirect(url_for("auth_login_get"))

# ----------------- Routes -----------------
@app.route("/")
def index():
    return redirect(url_for("feed"))

# Feed (login required) + RSS manager (username-bound)
@app.route("/feed")
@login_required
def feed():
    role = current_role()
    owner_name = current_username()
    q = (request.args.get("q") or "").strip()
    since = parse_dt(request.args.get("since"))
    until = parse_dt(request.args.get("until"))
    page = max(1, int(request.args.get("page", 1)))
    page_size = min(100, max(5, int(request.args.get("page_size", 20))))

    # NEW: unified filter bar (["rss"] + built-ins)
    all_filters = ["rss"] + ARTICLE_SOURCES
    sel_sources = request.args.getlist("source")
    if not sel_sources:
        # default: show built-in sources (no RSS)
        sel_sources = ARTICLE_SOURCES[:]

    rss_mode = ("rss" in sel_sources) and (set(sel_sources) == {"rss"})

    if rss_mode:
        filt = {"owner_username": owner_name}
        if q:
            filt["$or"] = [
                {"title": {"$regex": q, "$options": "i"}},
                {"content": {"$regex": q, "$options": "i"}},
            ]
        if since or until:
            rng = {}
            if since: rng["$gte"] = since
            if until: rng["$lte"] = until
            filt["timestamp"] = rng

        total = user_rss_items_coll.count_documents(filt)
        items = list(
            user_rss_items_coll.find(
                filt,
                {"title":1,"url":1,"content":1,"timestamp":1,"feed_url":1}
            )
            .sort([("timestamp", -1)])
            .skip((page - 1) * page_size)
            .limit(page_size)
        )
    else:
        # Only keep valid built-in sources and enforce role
        req_sources = [s for s in sel_sources if s in ARTICLE_SOURCES]
        allowed_sources = [s for s in req_sources if role_allows(role, SOURCE_ROLE.get(s, "public"))]

        items = []; total = 0
        if allowed_sources:
            branch = {"source": {"$in": allowed_sources}, "allowed_roles": role}
            if q:
                branch["$or"] = [
                    {"title": {"$regex": q, "$options": "i"}},
                    {"content": {"$regex": q, "$options": "i"}},
                ]
            if since or until:
                rng = {}
                if since: rng["$gte"] = since
                if until: rng["$lte"] = until
                branch["timestamp"] = rng

            filt = branch
            total = coll.count_documents(filt)
            items = list(
                coll.find(
                    filt,
                    {
                        "title":1,"url":1,"content":1,"timestamp":1,"source":1,"min_role":1,
                        "nvd_cvss":1,"nvd_cwes":1,"nvd_refs":1,
                        "edb_id":1,"edb_cves":1,
                        "recommendations.cybok": 1,
                    }
                )
                .sort([("timestamp", -1)])
                .skip((page - 1) * page_size)
                .limit(page_size)
            )

    pages = max(1, math.ceil(total / page_size))
    pager = {"total": total, "page": page, "pages": pages,
             "page_size": page_size, "has_prev": page > 1, "has_next": page < pages,
             "prev": page - 1, "next": page + 1}

    rss_list = list(
        user_rss_sources_coll.find({"owner_username": owner_name}).sort([("updated_at", -1)])
    )

    resp = make_response(render_template(
        "feed.html",
        items=items, pager=pager, q=q,
        sources=sel_sources,
        source_label={k: v["name"] for k, v in SOURCE_STYLE.items()},
        all_sources=ARTICLE_SOURCES,
        all_filters=all_filters,
        rss_list=rss_list,
        rss_mode=rss_mode
    ))
    return resp

# --- enqueue fetch -> reco ---
@app.post("/fetch_now")
@login_required
def fetch_now():
    ar = run_fetch_and_reco.delay()
    return jsonify({
        "task_id": ar.id,
        "state": ar.state
    })

# --- poll task status ---
@app.get("/task_status/<task_id>")
@login_required
def task_status(task_id):
    return jsonify(get_task_status(task_id))

def get_task_status(task_id: str) -> dict:
    ar = AsyncResult(task_id, app=celery)
    payload = {"task_id": task_id, "state": ar.state}

    if ar.state == "PENDING":
        payload["meta"] = None
    elif ar.state in {"RECEIVED", "STARTED", "PROGRESS"}:
        payload["meta"] = _safe_info(ar.info)
    elif ar.state == "FAILURE":
        payload["meta"] = _safe_info(ar.info)
        payload["traceback"] = ar.traceback
    elif ar.state == "SUCCESS":
        payload["result"] = _safe_info(ar.result)
    return payload

def _safe_info(val):
    if isinstance(val, Exception):
        return {"error": str(val)}
    if isinstance(val, (dict, list, str, int, float, bool)) or val is None:
        return val
    return {"repr": repr(val)}

# Item details
@app.get("/item/<id>")
@login_required
def item_detail(id):
    try:
        oid = ObjectId(id)
    except Exception:
        abort(404)
    doc = coll.find_one({"_id": oid})
    if not doc:
        abort(404)
    st = SOURCE_STYLE.get(doc.get("source"), {"name": doc.get("source","Other"), "badge":"secondary", "icon":"📰"})
    return render_template("item.html", it=doc, st=st)

# CVE details
@app.get("/cve/<cve_id>")
@login_required
def cve_detail(cve_id):
    role = current_role()
    data = {}
    try:
        data = nvd_parse_summary(nvd_get_cve_raw(cve_id))
    except Exception:
        data = {}
    return render_template("cve.html", cve_id=cve_id, data=data, role=role)

# CyBOK by sid (kept inline as very small pages)
@app.get("/cybok/<sid>")
@login_required
def cybok_view(sid):
    cybok_coll = coll.database["cybok_sections"]
    try:
        oid = ObjectId(sid)
    except Exception:
        return render_template_string("""
        <!doctype html><html><body>
        <div style="padding:24px;font-family:sans-serif">
          <h4>Invalid ID</h4>
          <div>The provided sid is not a valid ObjectId: {{ sid }}</div>
        </div></body></html>""", sid=sid), 400

    doc = cybok_coll.find_one({"_id": oid})
    if not doc:
        return render_template_string("""
        <!doctype html><html><body>
        <div style="padding:24px;font-family:sans-serif">
          <h4>Section Not Found</h4>
          <div>Version mismatch or data not imported.</div>
        </div></body></html>"""), 404

    import html as _h, re as _r
    title = _h.escape(doc.get("title") or "")
    section = _h.escape(doc.get("section") or "")
    content = doc.get("content") or ""
    paras = [f"<p>{_h.escape(p.strip())}</p>" for p in _r.split(r"\n{2,}", content) if p.strip()]
    body_html = "\n".join(paras) if paras else f"<pre class='text-secondary'>{_h.escape(content)}</pre>"

    return render_template_string(r"""
    <!doctype html>
    <html lang="en"><head>
      <meta charset="utf-8">
      <title>CyBOK · {{ section }} {{ title }}</title>
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
      <nav class="navbar navbar-expand-lg bg-white border-bottom">
        <div class="container-fluid">
          <a class="navbar-brand" href="{{ url_for('feed') }}">CTI Portal</a>
          <span class="ms-2 text-muted">CyBOK</span>
        </div>
      </nav>
      <div class="container py-4">
        <h4 class="mb-1">{{ section }} · {{ title }}</h4>
        <div class="card"><div class="card-body">{{ body|safe }}</div></div>
      </div>
    </body></html>
    """, section=section, title=title, body=body_html)

# CyBOK by title/section (kept inline)
@app.get("/cybok/byref>")
@login_required
def cybok_byref():
    title = (request.args.get("title") or "").strip()
    section = (request.args.get("section") or "").strip()
    version = (request.args.get("version") or "v1").strip()

    if not title and not section:
        return render_template_string("<div style='padding:24px'>Missing params: provide ?title or ?section</div>"), 400

    cybok_coll = coll.database["cybok_sections"]

    q = {"version": version}
    if title:   q["title"] = title
    if section: q["section"] = section
    doc = cybok_coll.find_one(q)

    if not doc:
        q2 = {"version": version}
        if title:
            q2["title"] = {"$regex": re.escape(title), "$options": "i"}
        if section:
            q2["section"] = {"$regex": f"^{re.escape(section)}", "$options": "i"}
        doc = cybok_coll.find_one(q2)

    if not doc:
        return render_template_string("<div style='padding:24px'>CyBOK section not found</div>"), 404

    import html as _h, re as _r
    safe_title = _h.escape(doc.get("title") or "")
    safe_section = _h.escape(doc.get("section") or "")
    content = doc.get("content") or ""
    paras = [f"<p>{_h.escape(p.strip())}</p>" for p in _r.split(r"\n{2,}", content) if p.strip()]
    body_html = "\n".join(paras) if paras else f"<pre class='text-secondary'>{_h.escape(content)}</pre>"

    return render_template_string(r"""
    <!doctype html>
    <html lang="en"><head>
      <meta charset="utf-8">
      <title>CyBOK · {{ section }} {{ title }}</title>
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
      <nav class="navbar navbar-expand-lg bg-white border-bottom">
        <div class="container-fluid">
          <a class="navbar-brand" href="{{ url_for('feed') }}">CTI Portal</a>
          <span class="ms-2 text-muted">CyBOK</span>
        </div>
      </nav>
      <div class="container py-4">
        <h4 class="mb-1">{{ section }} · {{ title }}</h4>
        <div class="card"><div class="card-body">{{ body|safe }}</div></div>
      </div>
    </body></html>
    """, section=safe_section, title=safe_title, body=body_html)



