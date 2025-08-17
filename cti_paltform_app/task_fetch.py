# task_fetch.py
import os, re, logging, hashlib, html
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

import requests
import feedparser
from pymongo import MongoClient, UpdateOne

# ---------- Configuration ----------
MONGODB_URI = os.getenv(
    "MONGODB_URI",
    "mongodb+srv://yzhang850:a237342160@cluster0.cficuai.mongodb.net/?retryWrites=true&w=majority&authSource=admin"
)
DB_NAME = os.getenv("DB_NAME", "cti_platform")
NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()

ROLES = ["public", "pro", "admin"]
ROLE_ORDER = {"public": 0, "pro": 1, "admin": 2}
def roles_at_or_above(min_role: str):
    """Return all roles whose level >= min_role."""
    i = ROLE_ORDER.get(min_role, 0)
    return [r for r in ROLES if ROLE_ORDER[r] >= i]

# ---------- MongoDB ----------
mongo = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=20000, connectTimeoutMS=20000)
db = mongo[DB_NAME]
coll = db["threats"]
sources_coll = db["custom_sources"]
try:
    coll.create_index("source_id", unique=True)
    coll.create_index([("timestamp", -1)])
    coll.create_index([("allowed_roles", 1), ("timestamp", -1)])
    sources_coll.create_index("url", unique=True)
except Exception:
    # Index creation is best-effort; ignore if already exists
    pass

# ---------- Utilities ----------
UA = {"User-Agent": "cti-crawler/1.0"}
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

def clean_text(s: str | None) -> str:
    """Decode HTML entities and collapse whitespace."""
    if not s:
        return ""
    s = html.unescape(s)
    return re.sub(r"\s+", " ", s).strip()

def extract_cves(s: str | None):
    """Extract unique CVE IDs from a string."""
    if not s:
        return []
    return sorted(set(m.upper() for m in CVE_RE.findall(s)))

# ====== Common: sentence splitting / denoising / summarization ======
_SENT_SPLIT = re.compile(r"(?<=[。！？!?\.])\s+")
_ONLY_PUNCT = re.compile(r"^\W+$")
_BRACE_NOISE = re.compile(r"[\{\}\(\)\[\]\|\/\\]{3,}")
_JS_SNIPPET  = re.compile(r"(?:^|[\s;])!?\s*function\s*\(", re.I)
_MULTI_SPACE = re.compile(r"\s{2,}")
_BRAND_TAIL  = re.compile(r"\s*\|\s*MSRC\s*Blog\s*\|\s*Microsoft\s*Security\s*Response\s*Center.*$", re.I)

def _strip_noise(text: str) -> str:
    if not text:
        return ""
    text = _BRACE_NOISE.sub(" ", text)
    text = _MULTI_SPACE.sub(" ", text)
    return text.strip()

def _is_human_line(t: str) -> bool:
    """Heuristics to drop nav/cookie/boilerplate lines."""
    if not t or len(t) < 6:
        return False
    if _ONLY_PUNCT.match(t):
        return False
    if _BRACE_NOISE.search(t):
        return False
    if _JS_SNIPPET.search(t):
        return False
    low = t.lower()
    for k in (
        "cookie", "privacy", "terms", "navigation", "skip to content",
        "microsoft security response center", "msrc blog", "rss", "search"
    ):
        if k in low:
            return False
    return True

def _brand_tail_cut(s: str) -> str:
    """Remove brand/site suffixes from titles."""
    return _BRAND_TAIL.sub("", s or "").strip()

def _first_good_sentences(text: str, max_sents: int = 3) -> str:
    """Pick the first few human-looking sentences."""
    sents = [s.strip() for s in _SENT_SPLIT.split(text) if s.strip()]
    good = [s for s in sents if _is_human_line(s)]
    return " ".join(good[:max_sents]) if good else (sents[0] if sents else "")

def make_summary(text: str, max_chars: int = 260, max_sents: int = 3) -> str:
    """Short extractive summary from denoised content."""
    text = _strip_noise(clean_text(text))
    if not text:
        return ""
    brief = _first_good_sentences(text, max_sents=max_sents) or text
    if len(brief) > max_chars:
        brief = brief[:max_chars].rstrip() + "..."
    return brief

# ====== Generic main-content extraction (includes MSRC .blog-post-content) ======
def extract_main_content(html_doc: str) -> tuple[str, str]:
    """
    Returns (title, text_without_scripts):
    - Use readability to get the main article area
    - Prefer paragraph/list text from common containers (incl. .blog-post-content)
    - Line-level denoising
    """
    title, text = "", ""
    try:
        from readability import Document
        from bs4 import BeautifulSoup

        doc = Document(html_doc)
        title = clean_text(doc.short_title() or "")
        summary_html = doc.summary(html_partial=True)
        soup = BeautifulSoup(summary_html, "html.parser")

        for tag in soup(["script", "style", "noscript", "template"]):
            tag.decompose()

        containers = []
        for sel in [
            "article", "main", ".entry-content", ".post-content",
            ".article-content", ".content", "#content", ".post-body",
            ".blog-post-content"  # MSRC
        ]:
            containers.extend(soup.select(sel))

        lines = []
        def push_lines(node):
            for p in node.select("p, li"):
                t = clean_text(p.get_text(" "))
                t = _brand_tail_cut(_strip_noise(t))
                if _is_human_line(t):
                    lines.append(t)

        if containers:
            for c in containers:
                push_lines(c)

        if not lines:
            all_text = clean_text(soup.get_text(" "))
            all_text = _brand_tail_cut(_strip_noise(all_text))
            primer = _first_good_sentences(all_text, max_sents=6)
            lines = [primer] if primer else []

        text = " ".join(lines)
        text = _strip_noise(text)

        if not title:
            soup2 = BeautifulSoup(html_doc, "html.parser")
            t = soup2.find("title")
            if t:
                title = clean_text(t.get_text())
        title = _brand_tail_cut(title)

    except Exception:
        title = ""
        text = clean_text(re.sub("<[^>]+>", " ", html_doc))
        text = _brand_tail_cut(_strip_noise(text))

    return title, text

# ====== MSRC-specific body extraction (no title) ======
def extract_msrc_body(html_doc: str) -> str:
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html_doc, "html.parser")

    box = soup.select_one("div.blog-post-content")
    paras = []
    if box:
        for p in box.select("p"):
            t = clean_text(p.get_text(" "))
            t = _brand_tail_cut(_strip_noise(t))
            if _is_human_line(t):
                paras.append(t)
    raw = " ".join(paras[:3]).strip()
    if not raw:
        # Fallback to generic extraction
        _, full = extract_main_content(html_doc)
        raw = full
    return raw

# ====== KrebsOnSecurity-specific body extraction (no title) ======
def extract_krebs_body(html_doc: str) -> str:
    """
    Pull a few paragraphs from #content.site-content (or #primary.site-content) article,
    dropping WordPress emoji init noise.
    """
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html_doc, "html.parser")

    container = soup.select_one("#content.site-content article") or \
                soup.select_one("#primary.site-content article")

    ban_substr = ("wpemojiSettings", "s.w.org/images/core/emoji", "SVGAnimated")
    paras = []
    if container:
        for p in container.select("p"):
            t = clean_text(p.get_text(" "))
            if any(b in t for b in ban_substr):
                continue
            t = _strip_noise(t)
            if _is_human_line(t):
                paras.append(t)

    raw = " ".join(paras[:3]).strip()
    if not raw:
        # Fallback to generic extraction
        _, full = extract_main_content(html_doc)
        raw = full
    return raw

# ====== MongoDB bulk upsert ======
def upsert_many(docs):
    """Bulk upsert by source_id. Returns (inserted_count, matched_count)."""
    if not docs:
        return (0, 0)
    ops = []
    for d in docs:
        ops.append(UpdateOne(
            {"source_id": d["source_id"]},
            {"$setOnInsert": {"source_id": d["source_id"], "source": d.get("source")},
             "$set": {k: v for k, v in d.items() if k not in ("source_id", "source")}},
            upsert=True
        ))
    try:
        res = coll.bulk_write(ops, ordered=False)
        ins = getattr(res, "upserted_count", 0)
        return ins, len(ops) - ins
    except Exception as e:
        logging.error("Mongo bulk_write error: %s", e)
        return (0, 0)

def _entry_datetime(e):
    """Build a timezone-aware datetime from feed entry, fallback to now."""
    try:
        if getattr(e, "published_parsed", None):
            return datetime(*e.published_parsed[:6], tzinfo=timezone.utc)
        if getattr(e, "updated_parsed", None):
            return datetime(*e.updated_parsed[:6], tzinfo=timezone.utc)
    except Exception:
        pass
    return datetime.now(timezone.utc)

def _iso8601_z(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")

# ---------- Site crawlers ----------

def crawl_cisa_kev(limit=2000):
    logging.info("[cisa_kev] min_role=pro limit=%d", limit)
    urls = [
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.csv.json",
    ]
    docs, now = [], datetime.now(timezone.utc)
    for url in urls:
        try:
            r = requests.get(url, timeout=30, headers=UA)
            r.raise_for_status()
            data = r.json()
            vulns = data.get("vulnerabilities") or []
            for v in vulns[:limit]:
                cve = v.get("cveID") or v.get("cve") or v.get("cveId")
                if not cve:
                    continue
                title = f"{cve} - {v.get('vendorProject','')}/{v.get('product','')}"
                desc = v.get("shortDescription") or v.get("description") or ""
                page_url = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                docs.append({
                    "source": "cisa_kev",
                    "source_id": f"cisa_kev:{cve}",
                    "title": clean_text(title),
                    "url": page_url,
                    "content": make_summary(desc, max_chars=240),
                    "timestamp": now,
                    "min_role": "pro",
                    "allowed_roles": roles_at_or_above("pro"),
                    "origin": "cisa.gov",
                })
            break
        except Exception as e:
            logging.warning("[cisa_kev] fetch fail from %s: %s", url, e)
            continue
    return docs

def crawl_krebsonsecurity(limit=40):
    logging.info("[krebsonsecurity] min_role=public limit=%d", limit)
    feed_url = "https://krebsonsecurity.com/feed/"
    docs = []
    try:
        feed = feedparser.parse(feed_url)
        for e in feed.entries[:limit]:
            link = (getattr(e, "link", "") or "").strip()
            if not link:
                continue
            try:
                r = requests.get(link, timeout=25, headers=UA)
                r.raise_for_status()
                # Krebs: summary from body paragraphs only (no title mixed in)
                raw = extract_krebs_body(r.text)
                title = clean_text(getattr(e, "title", "") or link)
                content = make_summary(raw, max_chars=260)
            except Exception:
                title = clean_text(getattr(e, "title", "") or link)
                raw = clean_text(getattr(e, "summary", "") or "")
                content = make_summary(raw, max_chars=260)
            docs.append({
                "source": "krebsonsecurity",
                "source_id": f"krebsonsecurity:{hashlib.sha1(link.encode()).hexdigest()}",
                "title": title or link,
                "url": link,
                "content": content,
                "timestamp": datetime.now(timezone.utc),
                "min_role": "public",
                "allowed_roles": roles_at_or_above("public"),
                "origin": urlparse(link).netloc,
            })
    except Exception as e:
        logging.error("[krebsonsecurity] error: %s", e)
    return docs

def crawl_msrc_blog(limit=40):
    logging.info("[msrc_blog] min_role=public limit=%d", limit)
    feed_url = "https://msrc.microsoft.com/blog/feed/"
    docs = []
    try:
        feed = feedparser.parse(feed_url)
        for e in feed.entries[:limit]:
            link = (getattr(e, "link", "") or "").strip()
            if not link:
                continue
            try:
                r = requests.get(link, timeout=25, headers=UA)
                r.raise_for_status()
                raw = extract_msrc_body(r.text)  # Only body text (no title)
                # Title from RSS or <title>, but do not prepend to summary
                title = clean_text(getattr(e, "title", "") or "") or _brand_tail_cut(clean_text(r.text))
                content = make_summary(raw, max_chars=260, max_sents=3)
                if not title:
                    title = link
            except Exception:
                title = clean_text(getattr(e, "title", "") or link)
                raw = clean_text(getattr(e, "summary", "") or getattr(e, "description", "") or "")
                content = make_summary(raw, max_chars=260, max_sents=3)

            docs.append({
                "source": "msrc_blog",
                "source_id": f"msrc_blog:{hashlib.sha1(link.encode()).hexdigest()}",
                "title": title or link,
                "url": link,
                "content": content,
                "timestamp": datetime.now(timezone.utc),
                "min_role": "public",
                "allowed_roles": roles_at_or_above("public"),
                "origin": urlparse(link).netloc,
            })
    except Exception as e:
        logging.error("[msrc_blog] error: %s", e)
    return docs

def crawl_threatfox(limit=60):
    logging.info("[threatfox] min_role=admin limit=%d", limit)
    feed_url = "https://threatfox.abuse.ch/feeds/rss/"
    docs = []
    try:
        feed = feedparser.parse(feed_url)
        if not getattr(feed, "entries", None):
            logging.info("[threatfox] no items.")
            return []
        for e in feed.entries[:limit]:
            link = (getattr(e, "link", "") or "").strip() or "https://threatfox.abuse.ch"
            title = clean_text(getattr(e, "title", "") or "ThreatFox item")
            raw = clean_text(getattr(e, "summary", "") or getattr(e, "description", "") or "")
            content = make_summary(raw, max_chars=260)
            docs.append({
                "source": "threatfox",
                "source_id": f"threatfox:{hashlib.sha1((link or title).encode()).hexdigest()}",
                "title": title,
                "url": link,
                "content": content,
                "timestamp": _entry_datetime(e),
                "min_role": "admin",
                "allowed_roles": roles_at_or_above("admin"),
                "origin": urlparse(link).netloc if link else "threatfox.abuse.ch",
            })
    except Exception as e:
        logging.error("[threatfox] error: %s", e)
    return docs

# ---------- NVD & Exploit-DB ----------
def crawl_nvd_recent(days=7, max_items=200):
    logging.info("[nvd] min_role=admin days=%d max=%d", days, max_items)
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    params = {
        "pubStartDate": _iso8601_z(start),
        "pubEndDate": _iso8601_z(end),
        "resultsPerPage": min(2000, max_items),
        "startIndex": 0,
    }
    headers = {"User-Agent": "cti-crawler/1.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    docs = []
    try:
        r = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params, headers=headers, timeout=30
        )
        r.raise_for_status()
        data = r.json()
        vulns = data.get("vulnerabilities") or []
        for v in vulns[:max_items]:
            cve = (v.get("cve") or {})
            cve_id = cve.get("id")
            if not cve_id:
                continue

            desc = ""
            for d in (cve.get("descriptions") or []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            metrics = cve.get("metrics") or {}
            cvss = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(key):
                    m = metrics[key][0]
                    data_cvss = m.get("cvssData", {})
                    cvss = {
                        "version": data_cvss.get("version"),
                        "baseScore": data_cvss.get("baseScore"),
                        "baseSeverity": m.get("baseSeverity"),
                        "vectorString": data_cvss.get("vectorString"),
                        "exploitabilityScore": m.get("exploitabilityScore"),
                        "impactScore": m.get("impactScore"),
                    }
                    break

            weaknesses = []
            for w in (cve.get("weaknesses") or []):
                for dsc in (w.get("description") or []):
                    val = dsc.get("value")
                    if val:
                        weaknesses.append(val)
            weaknesses = sorted(set(weaknesses))

            refs = []
            for rr in (cve.get("references") or []):
                url = rr.get("url")
                if url:
                    refs.append(url)

            ts_str = cve.get("published") or cve.get("lastModified")
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except Exception:
                ts = end

            docs.append({
                "source": "nvd",
                "source_id": f"nvd:{cve_id}",
                "title": f"{cve_id} - {clean_text(desc)[:120]}",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "content": make_summary(desc, max_chars=260),
                "timestamp": ts,
                "min_role": "admin",
                "allowed_roles": roles_at_or_above("admin"),
                "origin": "nvd.nist.gov",
                "nvd_cvss": cvss,
                "nvd_cwes": weaknesses,
                "nvd_refs": refs[:10],
            })
    except Exception as e:
        logging.error("[nvd] error: %s", e)
    return docs

def crawl_exploitdb(limit=60):
    logging.info("[exploitdb] min_role=admin limit=%d", limit)
    feed_url = "https://www.exploit-db.com/rss.xml"
    docs = []
    try:
        feed = feedparser.parse(feed_url)
        for e in feed.entries[:limit]:
            link = (getattr(e, "link", "") or "").strip()
            if not link:
                continue
            m = re.search(r"/exploits/(\d+)", link)
            edb_id = m.group(1) if m else None

            title = clean_text(getattr(e, "title", "") or link)
            summary = clean_text(getattr(e, "summary", "") or getattr(e, "description", "") or "")
            cves = extract_cves(title + " " + summary)

            docs.append({
                "source": "exploitdb",
                "source_id": f"exploitdb:{edb_id or hashlib.sha1(link.encode()).hexdigest()}",
                "title": title,
                "url": link,
                "content": make_summary(summary, max_chars=260),
                "timestamp": _entry_datetime(e),
                "min_role": "admin",
                "allowed_roles": roles_at_or_above("admin"),
                "origin": urlparse(link).netloc,
                "edb_id": edb_id,
                "edb_cves": cves,
            })
    except Exception as e:
        logging.error("[exploitdb] error: %s", e)
    return docs

# ---------- User-defined RSS ----------
def crawl_user_rss(limit_sources=200, max_items_per_feed=40, timeout=25):
    logging.info("[user_rss] crawling enabled RSS sources (deferred)")
    recs = list(sources_coll.find({"enabled": True, "mode": "rss"})
                .sort([("updated_at", -1)]).limit(limit_sources))
    docs, now = [], datetime.now(timezone.utc)

    for rcd in recs:
        feed_url = rcd.get("url")
        role = (rcd.get("min_role") or "public").lower()
        if role not in ROLES:
            role = "public"
        try:
            feed = feedparser.parse(feed_url)
            cnt = 0
            for e in feed.entries:
                if cnt >= max_items_per_feed:
                    break
                link = (getattr(e, "link", "") or "").strip()
                if not link or not link.startswith(("http://", "https://")):
                    continue

                try:
                    resp = requests.get(link, timeout=timeout, headers=UA)
                    resp.raise_for_status()
                    # Generic main-body -> summary (do not prepend the title)
                    _, full = extract_main_content(resp.text)
                    title = clean_text(getattr(e, "title", "") or link)
                    content = make_summary(full, max_chars=260)
                except Exception:
                    title = clean_text(getattr(e, "title", "") or link)
                    raw = clean_text(getattr(e, "summary", "") or getattr(e, "description", "") or "")
                    content = make_summary(raw, max_chars=260)

                ts = _entry_datetime(e)
                docs.append({
                    "source": "user",
                    "source_id": f"user:{hashlib.sha1(link.encode()).hexdigest()}",
                    "title": title or link,
                    "url": link,
                    "content": content,
                    "timestamp": ts,
                    "min_role": role,
                    "allowed_roles": roles_at_or_above(role),
                    "origin": urlparse(link).netloc,
                })
                cnt += 1

            sources_coll.update_one(
                {"_id": rcd["_id"]},
                {"$set": {"last_crawled": now, "last_status": f"ok:{cnt}"}}
            )
            logging.info("[user_rss] %s -> %d items", feed_url, cnt)
        except Exception as e:
            logging.warning("[user_rss] fail %s: %s", feed_url, e)
            sources_coll.update_one(
                {"_id": rcd["_id"]},
                {"$set": {"last_crawled": now, "last_status": f"error:{e.__class__.__name__}"}}
            )
    return docs

# ---------- Main entry ----------
def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    sites = [
        ("cisa_kev", crawl_cisa_kev, {"limit": 2000}),
        ("krebsonsecurity", crawl_krebsonsecurity, {"limit": 40}),
        ("msrc_blog", crawl_msrc_blog, {"limit": 40}),
        ("threatfox", crawl_threatfox, {"limit": 60}),
        ("nvd", crawl_nvd_recent, {"days": 7, "max_items": 200}),
        ("exploitdb", crawl_exploitdb, {"limit": 60}),
    ]
    logging.info("Sites to crawl: %s", [n for (n, _, _) in sites])

    for name, func, kwargs in sites:
        try:
            docs = func(**kwargs)
            ins, _ = upsert_many(docs)
            logging.info("[%s] saved: upserted=%d matched=%d", name, ins, len(docs) - ins)
        except Exception as e:
            logging.error("[%s] fatal: %s", name, e)

    try:
        docs = crawl_user_rss(limit_sources=200, max_items_per_feed=40)
        ins, _ = upsert_many(docs)
        logging.info("[user_rss] saved: upserted=%d total=%d", ins, len(docs))
    except Exception as e:
        logging.error("[user_rss] fatal: %s", e)

if __name__ == "__main__":
    main()
