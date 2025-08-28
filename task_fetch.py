# worker/task_fetch.py
# -*- coding: utf-8 -*-

import os
import re
import time
import html
import random
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import Tuple, Optional
from urllib.parse import urlparse, urlsplit, urlunsplit
import requests
from pymongo import MongoClient, UpdateOne
from pymongo.errors import (
    AutoReconnect,
    ConnectionFailure,
    NetworkTimeout,
    ExecutionTimeout,
    BulkWriteError,
)

# feedparser 作为可选依赖：若缺失，依赖它的函数会抛出更友好的错误
try:
    import feedparser
except Exception:
    feedparser = None

# readability / bs4 可选依赖：缺失时退化到简单 HTML 去标签
try:
    from readability import Document  # type: ignore
except Exception:
    Document = None  # type: ignore
try:
    from bs4 import BeautifulSoup  # type: ignore
except Exception:
    BeautifulSoup = None  # type: ignore

# ---------- Environment ----------
MONGODB_URI = os.getenv(
    "MONGODB_URI",
    "mongodb+srv://yzhang850:a237342160@cluster0.cficuai.mongodb.net/?retryWrites=true&w=majority&authSource=admin",
)
DB_NAME = os.getenv("DB_NAME", "cti_platform")
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "15"))
NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()

# Exponential backoff parameters
MAX_RETRIES = int(os.getenv("BACKOFF_MAX_RETRIES", "5"))        # number of retry attempts
BASE_DELAY = float(os.getenv("BACKOFF_BASE_SECONDS", "0.5"))     # initial delay in seconds
MAX_DELAY = float(os.getenv("BACKOFF_MAX_SECONDS", "20"))        # cap delay
JITTER_BOUND = float(os.getenv("BACKOFF_JITTER_SECONDS", "0.5")) # additional random jitter [0, JITTER_BOUND]

ROLES = ["public", "pro", "admin"]
ROLE_ORDER = {"public": 0, "pro": 1, "admin": 2}
def roles_at_or_above(min_role: str):
    """Return all roles whose level >= min_role."""
    i = ROLE_ORDER.get(min_role, 0)
    return [r for r in ROLES if ROLE_ORDER[r] >= i]

# ---------- MongoDB ----------
mongo = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=20000, connectTimeoutMS=20000)
db = mongo[DB_NAME]

# 来自“文件1”的集合（主威胁集合 + 自定义源集合）
coll = db["threats"]
sources_coll = db["custom_sources"]

# 来自“文件2”的用户级 RSS 集合
user_rss_sources = db["user_rss_sources"]
user_rss_items = db["user_rss_items"]

# 创建索引（尽力而为，已存在则忽略）
try:
    coll.create_index("source_id", unique=True)
    coll.create_index([("timestamp", -1)])
    coll.create_index([("allowed_roles", 1), ("timestamp", -1)])
    sources_coll.create_index("url", unique=True)
    user_rss_items.create_index([("owner_username", 1), ("url", 1)], unique=True)
    user_rss_sources.create_index([("owner_username", 1), ("url", 1)], unique=True)
except Exception:
    pass

# ---------- HTTP Sessions ----------
# “文件2”中的会话（用于 per-user RSS 抓取）
UA_RSS = "cti-portal/1.0 (+rss)"
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": UA_RSS})

# “文件1”中的会话 + UA 头（用于站点爬取 + 带退避的请求）
_session = requests.Session()
UA_HEADERS = {"User-Agent": "cti-crawler/1.0"}

# ---------- 通用小工具（两端共享） ----------
def clean_text(s: str | None) -> str:
    """Decode HTML entities and collapse whitespace."""
    if not s:
        return ""
    s = html.unescape(s)
    return re.sub(r"\s+", " ", s).strip()

# 来自“文件1”的 CVE 抽取
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
def extract_cves(s: str | None):
    """Extract unique CVE IDs from a string."""
    if not s:
        return []
    return sorted(set(m.upper() for m in CVE_RE.findall(s)))

# ====== Backoff helpers（来自“文件1”）======
def _retryable_http(resp: requests.Response | None, err: Exception | None) -> bool:
    """Decide if an HTTP operation is retryable (network errors, throttling, server errors)."""
    if err is not None:
        return True
    if resp is None:
        return True
    return resp.status_code in (408, 409, 425, 429, 500, 502, 503, 504)

def _sleep_backoff(attempt: int):
    """Exponential backoff with bounded jitter."""
    delay = min(MAX_DELAY, BASE_DELAY * (2 ** attempt))
    delay += random.uniform(0, JITTER_BOUND)
    time.sleep(delay)

def http_get(url: str, **kwargs) -> requests.Response:
    """GET with exponential backoff."""
    last_err = None
    for i in range(MAX_RETRIES):
        resp = None
        try:
            resp = _session.get(url, **kwargs)
            if not _retryable_http(resp, None):
                return resp
            logging.warning("HTTP GET %s -> %s; retry %d/%d", url, resp.status_code, i + 1, MAX_RETRIES)
        except Exception as e:
            last_err = e
            logging.warning("HTTP GET %s error: %s; retry %d/%d", url, e, i + 1, MAX_RETRIES)
        _sleep_backoff(i)
    if last_err:
        raise last_err
    raise RuntimeError(f"HTTP GET failed after {MAX_RETRIES} retries: {url}")

def http_post(url: str, **kwargs) -> requests.Response:
    """POST with exponential backoff."""
    last_err = None
    for i in range(MAX_RETRIES):
        resp = None
        try:
            resp = _session.post(url, **kwargs)
            if not _retryable_http(resp, None):
                return resp
            logging.warning("HTTP POST %s -> %s; retry %d/%d", url, resp.status_code, i + 1, MAX_RETRIES)
        except Exception as e:
            last_err = e
            logging.warning("HTTP POST %s error: %s; retry %d/%d", url, e, i + 1, MAX_RETRIES)
        _sleep_backoff(i)
    if last_err:
        raise last_err
    raise RuntimeError(f"HTTP POST failed after {MAX_RETRIES} retries: {url}")

def parse_feed_with_backoff(feed_url: str):
    """feedparser.parse with exponential backoff."""
    if feedparser is None:
        raise RuntimeError("feedparser is not installed")
    last_err = None
    for i in range(MAX_RETRIES):
        try:
            return feedparser.parse(feed_url)
        except Exception as e:
            last_err = e
            logging.warning("feedparser %s error: %s; retry %d/%d", feed_url, e, i + 1, MAX_RETRIES)
            _sleep_backoff(i)
    if last_err:
        raise last_err
    raise RuntimeError(f"feedparser failed after {MAX_RETRIES} retries: {feed_url}")

def bulk_write_with_backoff(ops):
    """Mongo bulk_write with exponential backoff on transient errors."""
    last_err = None
    for i in range(MAX_RETRIES):
        try:
            return coll.bulk_write(ops, ordered=False)
        except (AutoReconnect, ConnectionFailure, NetworkTimeout, ExecutionTimeout, BulkWriteError) as e:
            last_err = e
            logging.warning("Mongo bulk_write transient error: %s; retry %d/%d", e, i + 1, MAX_RETRIES)
            _sleep_backoff(i)
        except Exception:
            raise
    if last_err:
        raise last_err

# ====== 摘要与内容抽取（来自“文件1”）======
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

def extract_main_content(html_doc: str) -> tuple[str, str]:
    """
    Returns (title, text_without_scripts):
    - Use readability to get the main article area
    - Prefer paragraph/list text from common containers (incl. .blog-post-content)
    - Line-level denoising
    """
    title, text = "", ""
    try:
        # 动态导入，避免全局硬依赖
        from readability import Document as _Doc  # type: ignore
        from bs4 import BeautifulSoup as _BS     # type: ignore

        doc = _Doc(html_doc)
        title = clean_text(doc.short_title() or "")
        summary_html = doc.summary(html_partial=True)
        soup = _BS(summary_html, "html.parser")

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
            soup2 = _BS(html_doc, "html.parser")
            t = soup2.find("title")
            if t:
                title = clean_text(t.get_text())
        title = _brand_tail_cut(title)

    except Exception:
        title = ""
        text = clean_text(re.sub("<[^>]+>", " ", html_doc))
        text = _brand_tail_cut(_strip_noise(text))

    return title, text

def extract_msrc_body(html_doc: str) -> str:
    # MSRC 特化
    try:
        from bs4 import BeautifulSoup as _BS  # type: ignore
        soup = _BS(html_doc, "html.parser")

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
            _, full = extract_main_content(html_doc)
            raw = full
        return raw
    except Exception:
        _, full = extract_main_content(html_doc)
        return full

def extract_krebs_body(html_doc: str) -> str:
    """
    Pull a few paragraphs from #content.site-content (or #primary.site-content) article,
    dropping WordPress emoji init noise.
    """
    try:
        from bs4 import BeautifulSoup as _BS  # type: ignore
        soup = _BS(html_doc, "html.parser")

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
            _, full = extract_main_content(html_doc)
            raw = full
        return raw
    except Exception:
        _, full = extract_main_content(html_doc)
        return full

def upsert_many(docs):
    """Bulk upsert by source_id. Returns (inserted_count, matched_count)."""
    if not docs:
        return (0, 0)
    ops = []
    for d in docs:
        ops.append(UpdateOne(
            {"source_id": d["source_id"]},
            {
                "$setOnInsert": {"source_id": d["source_id"], "source": d.get("source")},
                "$set": {k: v for k, v in d.items() if k not in ("source_id", "source")},
            },
            upsert=True,
        ))
    try:
        res = bulk_write_with_backoff(ops)
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

# ---------- 站点爬虫（来自“文件1”）----------

def crawl_cisa_kev(limit=2000):
    logging.info("[cisa_kev] min_role=pro limit=%d", limit)
    urls = [
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.csv.json",
    ]
    docs, now = [], datetime.now(timezone.utc)
    for url in urls:
        try:
            r = http_get(url, timeout=30, headers=UA_HEADERS)
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
        feed = parse_feed_with_backoff(feed_url)
        for e in feed.entries[:limit]:
            link = (getattr(e, "link", "") or "").strip()
            if not link:
                continue
            try:
                r = http_get(link, timeout=25, headers=UA_HEADERS)
                r.raise_for_status()
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
        feed = parse_feed_with_backoff(feed_url)
        for e in feed.entries[:limit]:
            link = (getattr(e, "link", "") or "").strip()
            if not link:
                continue
            try:
                r = http_get(link, timeout=25, headers=UA_HEADERS)
                r.raise_for_status()
                raw = extract_msrc_body(r.text)  # Only body text (no title)
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
        r = http_get(
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
        feed = parse_feed_with_backoff(feed_url)
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

def crawl_user_rss(limit_sources=200, max_items_per_feed=40, timeout=25):
    """来自“文件1”的自定义源（custom_sources, mode=rss），写入 threats。"""
    logging.info("[user_rss] crawling enabled RSS sources (deferred)")
    recs = list(
        sources_coll.find({"enabled": True, "mode": "rss"}).sort([("updated_at", -1)]).limit(limit_sources)
    )
    docs, now = [], datetime.now(timezone.utc)

    for rcd in recs:
        feed_url = rcd.get("url")
        role = (rcd.get("min_role") or "public").lower()
        if role not in ROLES:
            role = "public"
        try:
            feed = parse_feed_with_backoff(feed_url)
            cnt = 0
            for e in feed.entries:
                if cnt >= max_items_per_feed:
                    break
                link = (getattr(e, "link", "") or "").strip()
                if not link or not link.startswith(("http://", "https://")):
                    continue

                try:
                    resp = http_get(link, timeout=timeout, headers=UA_HEADERS)
                    resp.raise_for_status()
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

# ---------- “文件2”的 per-user RSS 抓取到 user_rss_items ----------

def _strip_html(html_str: str) -> str:
    if not html_str:
        return ""
    txt = re.sub(r"<[^>]+>", " ", html_str)
    txt = re.sub(r"\s+", " ", txt).strip()
    return txt

def _extract_main_content_user(html_str: str) -> Tuple[str, str]:
    """
    “文件2”版本：返回 (title, text)，偏向于提炼 <article> 段落。
    与 extract_main_content 同时存在不冲突。
    """
    title, text = "", ""
    if html_str:
        if Document:
            try:
                doc = Document(html_str)  # type: ignore
                title = (doc.short_title() or "").strip()
                text = _strip_html(doc.summary() or "")
            except Exception:
                pass
        if not text and BeautifulSoup:
            try:
                soup = BeautifulSoup(html_str, "html.parser")  # type: ignore
                article = soup.find("article") or soup
                paras = [p.get_text(" ", strip=True) for p in article.find_all("p")]
                text = " ".join(paras).strip()
                if not title and soup.title and soup.title.string:
                    title = soup.title.string.strip()
            except Exception:
                pass
        if not text:
            text = _strip_html(html_str)
    return title, text

def _fetch_url(url: str) -> Optional[str]:
    try:
        r = SESSION.get(url, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.text
    except Exception:
        return None

def _entry_time(entry) -> datetime:
    # Prefer published, then updated, else now
    for key in ("published_parsed", "updated_parsed"):
        t = getattr(entry, key, None) or entry.get(key) if isinstance(entry, dict) else None
        if t:
            try:
                return datetime.fromtimestamp(time.mktime(t), tz=timezone.utc)
            except Exception:
                pass
    return datetime.now(timezone.utc)

def _normalize_link(entry) -> Optional[str]:
    """
    “文件2”版本：从 entry 中抽取 URL。修复了正则 flags 写法。
    """
    url = None
    try:
        # feedparser 的 entry 是对象也支持 dict-like 访问
        url = getattr(entry, "link", None) or getattr(entry, "id", None)
        if not url and isinstance(entry, dict):
            url = entry.get("link") or entry.get("id")
        if isinstance(url, list):
            url = url[0] if url else ""
        if isinstance(url, dict):
            url = url.get("href") or ""
    except Exception:
        url = None

    if not url:
        return None
    if not re.match(r"^https?://", str(url), re.I):
        return None
    return str(url).strip()

def _upsert_item(owner_username: str, feed_url: str, url: str, title: str, content: str, ts: datetime):
    # Deduplicate per owner+url
    existing = user_rss_items.find_one({"owner_username": owner_username, "url": url})
    if existing:
        user_rss_items.update_one(
            {"_id": existing["_id"]},
            {"$set": {
                "title": title or existing.get("title"),
                "content": content or existing.get("content"),
                "timestamp": ts or existing.get("timestamp"),
                "feed_url": feed_url,
                "updated_at": datetime.now(timezone.utc),
            }}
        )
        return False
    user_rss_items.insert_one({
        "owner_username": owner_username,
        "feed_url": feed_url,
        "url": url,
        "title": title or url,
        "content": content or "",
        "timestamp": ts,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    })
    return True

def fetch_user_rss_once(owner_username: str, rss_url: str, limit: int = 200) -> dict:
    """
    从指定 rss_url 抓取该用户的 RSS 项，存入 user_rss_items / user_rss_sources。
    函数名与行为保留与“文件2”一致。
    """
    if not feedparser:
        raise RuntimeError("feedparser is not installed")

    parsed = feedparser.parse(rss_url)
    status = getattr(parsed, "status", None) or (parsed.get("status") if isinstance(parsed, dict) else None)
    if status and int(status) >= 400:
        user_rss_sources.update_one(
            {"owner_username": owner_username, "url": rss_url},
            {"$set": {
                "last_status": f"http {status}",
                "last_crawled": datetime.now(timezone.utc)
            }},
            upsert=True
        )
        return {"ok": False, "new": 0, "total": 0, "status": status}

    entries = parsed.entries or []
    total = 0
    new_count = 0

    for entry in entries[:limit]:
        url = _normalize_link(entry)
        if not url:
            continue

        title = (getattr(entry, "title", "") or "").strip()
        if not title and isinstance(entry, dict):
            title = (entry.get("title") or "").strip()

        summary = _strip_html(
            getattr(entry, "summary", "") or getattr(entry, "description", "") or (
                entry.get("summary") if isinstance(entry, dict) else ""
            ) or ""
        )

        content_text = summary
        if not content_text:
            html_doc = _fetch_url(url)
            if html_doc:
                t2, txt2 = _extract_main_content_user(html_doc)
                if not title and t2:
                    title = t2
                content_text = txt2

        ts = _entry_time(entry)

        inserted = _upsert_item(
            owner_username=owner_username,
            feed_url=rss_url,
            url=url,
            title=title,
            content=content_text,
            ts=ts
        )
        total += 1
        if inserted:
            new_count += 1

    user_rss_sources.update_one(
        {"owner_username": owner_username, "url": rss_url},
        {"$set": {
            "last_crawled": datetime.now(timezone.utc),
            "last_status": f"ok: {new_count} new / {total} scanned"
        }},
        upsert=True
    )
    return {"ok": True, "new": new_count, "total": total, "status": "ok"}












# --- 放在 fetch_user_rss_once(...) 之后、main() 之前 ---

from pathlib import Path
from contextlib import contextmanager

def _normalize_url_for_dedup(u: str) -> str:
    """
    规范化 URL 以便去重：小写主机名、去掉 fragment、保留 path/query。
    """
    u = (u or "").strip()
    if not u:
        return ""
    parts = urlsplit(u)
    scheme = parts.scheme or "http"
    netloc = (parts.netloc or "").lower()
    path = parts.path or "/"
    query = parts.query
    return urlunsplit((scheme, netloc, path, query, ""))

# 抓取阶段的跨进程文件锁，避免并发导入/初始化导致的死锁
_LOCK_PATH = Path(os.getenv("CTI_FETCH_LOCK_FILE", os.path.join(os.getenv("TMP", os.getenv("TEMP", "/tmp")), "cti_fetch.lock")))

@contextmanager
def _fetch_lock():
    import time as _t
    while True:
        try:
            fd = os.open(str(_LOCK_PATH), os.O_CREAT | os.O_EXCL | os.O_RDWR)
            os.write(fd, str(os.getpid()).encode("utf-8"))
            os.close(fd)
            break
        except FileExistsError:
            _t.sleep(0.2)
    try:
        yield
    finally:
        try:
            os.remove(_LOCK_PATH)
        except FileNotFoundError:
            pass

def fetch_all_rss_dedup(limit: int = 200, owner_filter=None, sample: int | None = None) -> dict:
    """
    去重抓取仓库里所有 RSS URL：
      - 来源：MongoDB collection `user_rss_sources`
      - 去重：按规范化后的 URL 合并
      - 调用：对每个 URL，按它关联到的所有 owner 逐一调用 fetch_user_rss_once(owner, url, limit)

    参数:
      limit         每条 feed 抓取的最大条数（传给 fetch_user_rss_once）
      owner_filter  仅抓取某个 owner 或 owner 列表（None 表示全部）
      sample        仅处理去重后的前 N 个 URL（用于测试）

    返回:
      {
        "ok": True,
        "url_count": 去重后的 URL 数量,
        "invocations": 总调用次数（owner×url）,
        "by_url": {
          url: {"owners": [...], "calls": X, "new_sum": Y, "total_sum": Z}
        }
      }
    """
    if isinstance(owner_filter, str):
        owner_filter = [owner_filter]

    q = {}
    if owner_filter:
        q["owner_username"] = {"$in": owner_filter}

    # 从 user_rss_sources 读 (owner_username, url)
    cursor = user_rss_sources.find(q, {"owner_username": 1, "url": 1})

    url_to_owners: dict[str, set[str]] = {}
    for doc in cursor:
        owner = (doc.get("owner_username") or "").strip()
        url = _normalize_url_for_dedup(doc.get("url") or "")
        if not owner or not url:
            continue
        url_to_owners.setdefault(url, set()).add(owner)

    urls = sorted(url_to_owners.keys())
    if sample is not None:
        urls = urls[: int(sample)]

    summary = {
        "ok": True,
        "url_count": len(urls),
        "invocations": 0,
        "by_url": {}
    }

    # 串行“抓取阶段”，避免并发导入/初始化死锁（你之前遇到的 _DeadlockError）
    with _fetch_lock():
        for url in urls:
            owners = sorted(url_to_owners[url])
            by_url_entry = {"owners": owners, "calls": 0, "new_sum": 0, "total_sum": 0}
            for owner in owners:
                try:
                    res = fetch_user_rss_once(owner_username=owner, rss_url=url, limit=limit)
                except Exception as e:
                    res = {"ok": False, "error": str(e)}
                by_url_entry["calls"] += 1
                summary["invocations"] += 1
                if isinstance(res, dict):
                    by_url_entry["new_sum"] += int(res.get("new", 0) or 0)
                    by_url_entry["total_sum"] += int(res.get("total", 0) or 0)
            summary["by_url"][url] = by_url_entry

    return summary


# ---------- Main entry（融合主流程） ----------
def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    sites = [
        ("cisa_kev", crawl_cisa_kev, {"limit": 2000}),
        ("krebsonsecurity", crawl_krebsonsecurity, {"limit": 40}),
        ("msrc_blog", crawl_msrc_blog, {"limit": 40}),
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

    # 注意：per-user 拉取函数 fetch_user_rss_once 保持独立，由业务调用时传入 owner_username / rss_url。

if __name__ == "__main__":
    main()
