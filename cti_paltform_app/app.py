# app.py
import os, math, re
from datetime import datetime, timezone
from functools import lru_cache, wraps
from urllib.parse import urlencode

import requests
from flask import (
    Flask, request, redirect, url_for, render_template_string,
    make_response, abort, session, flash
)
from pymongo import MongoClient
from dateutil import parser as dateparser
from bson import ObjectId

from werkzeug.security import generate_password_hash, check_password_hash

# Optional content extraction (app works without these)
try:
    from readability import Document  # pip install readability-lxml
except Exception:
    Document = None
try:
    from bs4 import BeautifulSoup     # pip install beautifulsoup4
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

# Sources (including user-provided links)
ARTICLE_SOURCES = ["krebsonsecurity", "msrc_blog", "cisa_kev", "nvd", "exploitdb", "user"]

# Minimum role required per built-in source
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
    "user":            {"name": "User Link",       "badge": "info",    "icon": "🔗"},
}

# ----------------- Flask & Mongo -----------------
app = Flask(__name__)
app.secret_key = SECRET_KEY
mongo = MongoClient(MONGODB_URI)
coll = mongo[DB_NAME][COLL_NAME]
sources_coll = mongo[DB_NAME]["custom_sources"]
users_coll = mongo[DB_NAME]["users"]

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
    """Try to extract article title & main text."""
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
    return render_template_string(TPL_AUTH, mode="login", next=request.args.get("next") or "")

@app.post("/auth/login")
def auth_login_post():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    next_url = (request.form.get("next") or "").strip() or url_for("feed")
    u = users_coll.find_one({"username": username})
    if not u or not check_password_hash(u.get("password",""), password):
        flash("Invalid username or password", "danger")
        return render_template_string(TPL_AUTH, mode="login", next=next_url)
    session["uid"] = str(u["_id"])
    return redirect(next_url)

@app.get("/auth/register")
def auth_register_get():
    return render_template_string(TPL_AUTH, mode="register", next=request.args.get("next") or "")

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
        return render_template_string(TPL_AUTH, mode="register", next=next_url)
    if users_coll.find_one({"username": username}):
        flash("Username already exists", "warning")
        return render_template_string(TPL_AUTH, mode="register", next=next_url)

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

# Feed (login required)
@app.route("/feed")
@login_required
def feed():
    role = current_role()
    q = (request.args.get("q") or "").strip()
    since = parse_dt(request.args.get("since"))
    until = parse_dt(request.args.get("until"))
    page = max(1, int(request.args.get("page", 1)))
    page_size = min(100, max(5, int(request.args.get("page_size", 20))))

    req_sources = request.args.getlist("source") or ARTICLE_SOURCES
    allowed_sources = [s for s in req_sources if role_allows(role, SOURCE_ROLE.get(s, "public"))]

    items = []; total = 0
    if allowed_sources:
        # If your documents have an "allowed_roles" array, you can switch to {"allowed_roles": {"$in": [role]}}
        filt = {"source": {"$in": allowed_sources}, "allowed_roles": role}
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

    resp = make_response(render_template_string(
        TPL_FEED,
        items=items, pager=pager, q=q,
        sources=req_sources,
        source_label={k: v["name"] for k, v in SOURCE_STYLE.items()},
        all_sources=ARTICLE_SOURCES
    ))
    return resp

# Item details (login required)
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
    return render_template_string(TPL_ITEM, it=doc, st=st)

# CVE details (login required)
@app.get("/cve/<cve_id>")
@login_required
def cve_detail(cve_id):
    role = current_role()
    data = {}
    try:
        data = nvd_parse_summary(nvd_get_cve_raw(cve_id))
    except Exception:
        data = {}
    return render_template_string(TPL_CVE, cve_id=cve_id, data=data, role=role)

# CyBOK by sid (login required)
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

# CyBOK by title/section (fallback when no sid)
@app.get("/cybok/byref")
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

# Add RSS source (login required)
@app.post("/add_rss")
@login_required
def add_rss():
    role = current_role()
    rss_url = (request.form.get("rss_url") or "").strip()
    role_sel = (request.form.get("rss_role") or "public").strip()
    if role_sel not in ROLES:
        role_sel = "public"
    if not rss_url or not re.match(r"^https?://", rss_url, re.I):
        return redirect(url_for("feed"))

    now = datetime.now(timezone.utc)
    sources_coll.update_one(
        {"url": rss_url},
        {"$set": {
            "url": rss_url,
            "mode": "rss",
            "min_role": role_sel,
            "allowed_roles": [r for r in ROLES if ROLE_ORDER[r] >= ROLE_ORDER[role_sel]],
            "enabled": True,
            "updated_at": now,
        }, "$setOnInsert": {
            "created_at": now,
            "last_crawled": None,
            "last_status": None,
        }},
        upsert=True
    )
    return redirect(url_for("feed"))

# ----------------- Templates -----------------
TPL_AUTH = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{{ 'Log in' if mode=='login' else 'Register' }} · CTI Portal</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container py-5" style="max-width:480px">
  <div class="card shadow-sm">
    <div class="card-body">
      <h4 class="mb-3">{{ 'Log in' if mode=='login' else 'Register' }}</h4>
      {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
          {% for cat, msg in messages %}
          <div class="alert alert-{{ cat }} py-2">{{ msg }}</div>
          {% endfor %}
        {% endif %}
      {% endwith %}

      {% if mode=='login' %}
      <form method="post" action="{{ url_for('auth_login_post') }}">
        <input type="hidden" name="next" value="{{ next or '' }}">
        <div class="mb-3">
          <label class="form-label">Username</label>
          <input class="form-control" name="username" required />
        </div>
        <div class="mb-3">
          <label class="form-label">Password</label>
          <input class="form-control" type="password" name="password" required />
        </div>
        <button class="btn btn-primary w-100">Log in</button>
      </form>
      <div class="mt-3 text-center">
        No account? <a href="{{ url_for('auth_register_get', next=next) }}">Register</a>
      </div>

      {% else %}
      <form method="post" action="{{ url_for('auth_register_post') }}">
        <input type="hidden" name="next" value="{{ next or '' }}">
        <div class="mb-3">
          <label class="form-label">Username</label>
          <input class="form-control" name="username" required />
        </div>
        <div class="mb-3">
          <label class="form-label">Password</label>
          <input class="form-control" type="password" name="password" required />
        </div>
        <div class="mb-3">
          <label class="form-label">Choose role</label>
          <select class="form-select" name="role">
            <option value="public">public</option>
            <option value="pro">pro</option>
            <option value="admin">admin</option>
          </select>
          <div class="form-text">Demo only: free choice of pro/admin. Restrict in production.</div>
        </div>
        <button class="btn btn-success w-100">Register & log in</button>
      </form>
      <div class="mt-3 text-center">
        Already have an account? <a href="{{ url_for('auth_login_get', next=next) }}">Log in</a>
      </div>
      {% endif %}
    </div>
  </div>
</div>
</body>
</html>
"""

TPL_FEED = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Threat Feed</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<nav class="navbar navbar-expand-lg bg-white border-bottom sticky-top">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{ url_for('feed') }}">CTI Portal</a>
    <div class="ms-auto d-flex align-items-center gap-2">
      {% if current_user %}
        <span class="badge text-bg-secondary">{{ current_user.username }}</span>
        <span class="badge text-bg-info text-uppercase">{{ current_user.role }}</span>
        <a class="btn btn-outline-danger btn-sm" href="{{ url_for('auth_logout') }}">Logout</a>
      {% endif %}
    </div>
  </div>
</nav>

<div class="container py-3">

  <form method="get" class="row g-2 mb-3">
    <div class="col-md-4">
      <input class="form-control" type="search" name="q" value="{{ q }}" placeholder="Search title/content…">
    </div>
    <div class="col-12">
      <div class="btn-group flex-wrap mt-2" role="group">
        {% for s in all_sources %}
        {% set checked = 'checked' if s in sources else '' %}
        <input type="checkbox" class="btn-check" id="src-{{ s }}" name="source" value="{{ s }}" {{ checked }}>
        <label class="btn btn-outline-secondary" for="src-{{ s }}">{{ source_label.get(s, s) }}</label>
        {% endfor %}
      </div>
    </div>
    <div class="col-12">
      <button class="btn btn-primary mt-2">Apply</button>
    </div>
  </form>

  <div class="row g-3">
    {% for it in items %}
    {% set item_link = url_for('item_detail', id=it._id|string) %}
    <div class="col-12">
      <div class="card shadow-sm">
        <div class="card-body">
          {% set st = SOURCE_STYLE.get(it.source, {"name": it.source, "badge":"secondary", "icon":"📰"}) %}
          <div class="d-flex justify-content-between align-items-center">
            <span class="badge bg-{{ st.badge }}">{{ st.icon }} {{ st.name }}</span>
            <small class="text-muted">{{ fmt_ts(it.timestamp) }}</small>
          </div>

          <h5 class="mt-2"><a class="link-dark text-decoration-none" href="{{ item_link }}">{{ it.title }}</a></h5>

          {% if it.source == 'msrc_blog' %}
            <p class="text-secondary">{{ brief_for_public(it.content or '') }}</p>
            <a class="btn btn-sm btn-outline-primary" href="{{ item_link }}">Read</a>

            {% if it.recommendations and it.recommendations.cybok %}
              <div class="mt-3 p-2 border rounded">
                <div class="small text-muted mb-1">CyBOK recommendations</div>
                <ul class="mb-0">
                  {% for r in it.recommendations.cybok[:5] %}
                    <li>
                      {% if r.sid %}
                        <a href="{{ url_for('cybok_view', sid=r.sid) }}" target="_self">
                          {{ r.title }}{% if r.section %} ({{ r.section }}){% endif %}
                        </a>
                      {% elif r.url and r.url|lower.startswith('/cybok/') %}
                        <a href="{{ r.url }}" target="_self">
                          {{ r.title }}{% if r.section %} ({{ r.section }}){% endif %}
                        </a>
                      {% elif r.title or r.section %}
                        <a href="{{ url_for('cybok_byref', title=r.title, section=r.section, version='v1') }}" target="_self">
                          {{ r.title }}{% if r.section %} ({{ r.section }}){% endif %}
                        </a>
                      {% else %}
                        <a href="{{ item_link }}" target="_self">
                          {{ r.title or 'CyBOK section' }}{% if r.section %} ({{ r.section }}){% endif %}
                        </a>
                      {% endif %}

                      {% if r.score is not none %}
                        <span class="text-muted ms-1">score {{ '%.2f'|format(r.score) }}</span>
                      {% endif %}
                    </li>
                  {% endfor %}
                </ul>
              </div>
            {% endif %}
          {% endif %}

          {% if it.source == 'krebsonsecurity' %}
            {% set cves = extract_cves_from_text((it.title or '') ~ ' ' ~ (it.content or '')) %}
            {% if cves %}
              <div class="mb-2"><strong>CVE(s):</strong>
                {% for c in cves %}
                  <a class="badge text-bg-dark me-1" href="{{ url_for('cve_detail', cve_id=c) }}">{{ c }}</a>
                {% endfor %}
              </div>
            {% endif %}
            <div class="mb-2">
              <span class="badge text-bg-success">Highlights</span>
              <div class="mt-1 text-secondary">{{ threat_points_for_pro(it.content or '') }}</div>
            </div>
            <a class="btn btn-sm btn-outline-primary" href="{{ item_link }}">Read</a>
          {% endif %}

          {% if it.source == 'cisa_kev' %}
            <p class="text-secondary">{{ brief_for_public(it.content or '', 260) }}</p>
            {% set cves = extract_cves_from_text((it.title or '') ~ ' ' ~ (it.content or '')) %}
            {% if cves %}
              <div class="mb-2"><strong>KEV includes:</strong>
                {% for c in cves %}
                  <a class="badge text-bg-warning me-1" href="{{ url_for('cve_detail', cve_id=c) }}">{{ c }}</a>
                {% endfor %}
              </div>
            {% endif %}
            <a class="btn btn-sm btn-outline-primary" href="{{ item_link }}">Read</a>
          {% endif %}

          {% if it.source == 'nvd' %}
            {% if it.nvd_cvss %}
              <div class="mb-2">
                <span class="badge text-bg-danger">CVSS {{ it.nvd_cvss.version or '' }}</span>
                <span class="ms-2">base: <strong>{{ it.nvd_cvss.baseScore or '—' }}</strong> ({{ it.nvd_cvss.baseSeverity or '—' }})</span>
                {% if it.nvd_cvss.vectorString %}
                  <div class="text-muted mt-1"><code>{{ it.nvd_cvss.vectorString }}</code></div>
                {% endif %}
              </div>
            {% endif %}
            {% if it.nvd_cwes %}
              <div class="mb-2"><strong>CWE:</strong>
                {% for w in it.nvd_cwes[:5] %}
                  <span class="badge text-bg-secondary me-1">{{ w }}</span>
                {% endfor %}
              </div>
            {% endif %}
            {% if it.nvd_refs %}
              <div class="mb-2"><strong>Refs:</strong>
                <ul class="mb-0">
                  {% for u in it.nvd_refs[:3] %}
                    <li><a href="{{ u }}" target="_blank" rel="noreferrer">{{ u }}</a></li>
                  {% endfor %}
                </ul>
              </div>
            {% endif %}
            <a class="btn btn-sm btn-outline-primary" href="{{ item_link }}">Read</a>
          {% endif %}

          {% if it.source == 'exploitdb' %}
            <div class="mb-2">
              <span class="badge text-bg-dark">Exploit available</span>
              {% if it.edb_id %}<span class="ms-2 text-muted">EDB-ID: {{ it.edb_id }}</span>{% endif %}
            </div>
            {% if it.edb_cves and it.edb_cves|length > 0 %}
              <div class="mb-2"><strong>Related CVEs:</strong>
                {% for c in it.edb_cves %}
                  <a class="badge text-bg-danger me-1" href="{{ url_for('cve_detail', cve_id=c) }}">{{ c }}</a>
                {% endfor %}
              </div>
            {% endif %}
            <p class="text-secondary">{{ brief_for_public(it.content or '', 240) }}</p>
            <a class="btn btn-sm btn-outline-primary" href="{{ item_link }}">Read</a>
          {% endif %}

          {% if it.source == 'user' %}
            <p class="text-secondary">{{ brief_for_public(it.content or '', 240) }}</p>
            <a class="btn btn-sm btn-outline-primary" href="{{ item_link }}">Read</a>
          {% endif %}

          {% if it.source not in ['msrc_blog','krebsonsecurity','cisa_kev','nvd','exploitdb','user'] %}
            <p class="text-secondary">{{ brief_for_public(it.content or '') }}</p>
            <a class="btn btn-sm btn-outline-primary" href="{{ item_link }}">Read</a>
          {% endif %}
        </div>
      </div>
    </div>
    {% endfor %}
  </div>

  <nav class="mt-3">
    <ul class="pagination">
      <li class="page-item {% if not pager.has_prev %}disabled{% endif %}">
        <a class="page-link" href="?page={{ pager.prev }}&q={{ q }}{% for s in sources %}&source={{ s }}{% endfor %}">Prev</a>
      </li>
      <li class="page-item disabled"><span class="page-link">Page {{ pager.page }} / {{ pager.pages }} ({{ pager.total }} items)</span></li>
      <li class="page-item {% if not pager.has_next %}disabled{% endif %}">
        <a class="page-link" href="?page={{ pager.next }}&q={{ q }}{% for s in sources %}&source={{ s }}{% endfor %}">Next</a>
      </li>
    </ul>
  </nav>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

TPL_CVE = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{{ cve_id }} · NVD</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<nav class="navbar navbar-expand-lg bg-white border-bottom">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{ url_for('feed') }}">CTI Portal</a>
  </div>
</nav>

<div class="container py-4">
  <h3 class="mb-3">{{ cve_id }}</h3>

  {% if not data %}
    <div class="alert alert-warning">Failed to fetch from NVD (network/quota/not found).</div>
  {% else %}
    <div class="card mb-3">
      <div class="card-body">
        <h5>Description</h5>
        <p class="text-secondary">{{ data.description or '—' }}</p>
      </div>
    </div>

    <div class="row g-3">
      <div class="col-md-6">
        <div class="card h-100">
          <div class="card-body">
            <h5>CVSS</h5>
            {% if data.cvss %}
              <ul class="mb-0">
                <li>Version: {{ data.cvss.version or '—' }}</li>
                <li>Base score: <strong>{{ data.cvss.baseScore or '—' }}</strong> ({{ data.cvss.baseSeverity or '—' }})</li>
                <li>Vector: <code>{{ data.cvss.vectorString or '—' }}</code></li>
              </ul>
            {% else %}
              <div class="text-muted">No CVSS available</div>
            {% endif %}
          </div>
        </div>
      </div>

      <div class="col-md-6">
        <div class="card h-100">
          <div class="card-body">
            <h5>CWE (Weaknesses)</h5>
            {% if data.weaknesses %}
              <ul class="mb-0">
                {% for w in data.weaknesses %}<li>{{ w }}</li>{% endfor %}
              </ul>
            {% else %}
              <div class="text-muted">No CWE info</div>
            {% endif %}
          </div>
        </div>
      </div>
    </div>

    <div class="card mt-3">
      <div class="card-body">
        <h5>References</h5>
        {% if data.references %}
          <ul class="mb-0">
            {% for r in data.references %}
              <li>
                <a href="{{ r.url }}" target="_blank" rel="noreferrer">{{ r.url }}</a>
                {% if r.tags %}
                  <span class="ms-2">
                    {% for t in r.tags %}
                      <span class="badge text-bg-secondary">{{ t }}</span>
                    {% endfor %}
                  </span>
                {% endif %}
              </li>
            {% endfor %}
          </ul>
        {% else %}
          <div class="text-muted">No references</div>
        {% endif %}
      </div>
    </div>
  {% endif %}
</div>
</body>
</html>
"""

TPL_ITEM = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{{ it.title }}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<nav class="navbar navbar-expand-lg bg-white border-bottom">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{ url_for('feed') }}">CTI Portal</a>
  </div>
</nav>

<div class="container py-4">
  <h3 class="mb-1">{{ it.title }}</h3>
  <div class="text-muted mb-3">{{ it.source }} · {{ fmt_ts(it.timestamp) }}</div>

  {% if it.content %}
    <article class="card">
      <div class="card-body" style="white-space:pre-wrap; line-height:1.7">{{ it.content }}</div>
    </article>
  {% else %}
    <div class="alert alert-secondary">No content captured yet.</div>
  {% endif %}

  {% if it.url %}
    <div class="mt-3">
      <a class="btn btn-sm btn-outline-secondary" href="{{ it.url }}" target="_blank" rel="noopener">Original</a>
    </div>
  {% endif %}
</div>
</body>
</html>
"""

# ----------------- Entry -----------------
if __name__ == "__main__":
    app.run(debug=True)
