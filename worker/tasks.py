# worker/tasks.py
import os, sys, time, subprocess, shlex, logging
from pathlib import Path
from datetime import datetime, timezone
from celery.signals import worker_ready
import redis
from contextlib import contextmanager

from .celery_app import celery

BASE = Path(__file__).resolve().parents[1]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s"
)
logger = logging.getLogger(__name__)

# ---------- 子进程执行器 ----------
def _run(pyfile: str, args: list[str] | None = None):
    cmd = [sys.executable, str(BASE / pyfile), *(args or [])]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"[{pyfile}] failed({p.returncode}): {p.stderr.strip()}")
    return {
        "cmd": " ".join(shlex.quote(c) for c in cmd),
        "stdout": p.stdout.strip(),
    }

# ---------- 占位任务 ----------
@celery.task(name="worker.tasks.run_ingest_cybok_intro_pdf")
def run_ingest_cybok_intro_pdf():
    logger.info("run_ingest_cybok_intro_pdf placeholder executed")
    return _run("ingest_cybok_intro_pdf.py")

# ---------- 基础抓取 ----------
@celery.task(name="worker.tasks.run_fetch")
def run_fetch():
    try:
        return _run("task_fetch.py")
    except Exception as e:
        logger.exception("run_fetch failed: %s", e)
        return {"ok": False, "error": str(e)}

# ---------- 用户定向抓取 ----------
@celery.task(bind=True, name="worker.tasks.run_fetch_user_rss_once")
def run_fetch_user_rss_once(self, owner_username: str, rss_url: str, limit: int = 200):
    logger.info("run_fetch_user_rss_once owner=%s url=%s limit=%s", owner_username, rss_url, limit)
    try:
        from task_fetch import fetch_user_rss_once as _fetch_user_rss_once
    except ImportError:
        from worker.task_fetch import fetch_user_rss_once as _fetch_user_rss_once

    self.update_state(state="PROGRESS", meta={"step": "start"})
    try:
        self.update_state(state="PROGRESS", meta={"step": "fetch"})
        result = _fetch_user_rss_once(owner_username=owner_username, rss_url=rss_url, limit=limit)

        self.update_state(state="PROGRESS", meta={"step": "finalize"})
        return {
            "ok": bool(result.get("ok")),
            "owner_username": owner_username,
            "rss_url": rss_url,
            "new": int(result.get("new", 0)),
            "total": int(result.get("total", 0)),
            "status": result.get("status", "ok"),
            "finished_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.exception("run_fetch_user_rss_once failed")
        self.update_state(state="FAILURE", meta={"step": "error", "error": str(e)})
        raise

# ---------- 去重抓取所有 RSS ----------
@celery.task(name="worker.tasks.run_fetch_all_rss_dedup")
def run_fetch_all_rss_dedup(limit: int = 200, owner_filter=None, sample: int | None = None):
    try:
        from task_fetch import fetch_all_rss_dedup as _fetch_all
    except ImportError:
        from worker.task_fetch import fetch_all_rss_dedup as _fetch_all
    return _fetch_all(limit=limit, owner_filter=owner_filter, sample=sample)

# ---------- 抓取+推荐 ----------
@celery.task(bind=True, name="worker.tasks.run_fetch_and_reco")
def run_fetch_and_reco(self):
    try:
        logger.info("[Celery] run_fetch_and_reco: start")
        self.update_state(state="PROGRESS", meta={"step": "fetch"})

        res1 = _run("task_fetch.py")

        self.update_state(state="PROGRESS", meta={"step": "reco"})
        res2 = _run("task_cybok_reco_gridfs.py")

        logger.info("[Celery] run_fetch_and_reco: done")
        return {"fetch": res1, "reco": res2}
    except Exception as e:
        logger.exception("run_fetch_and_reco failed: %s", e)
        self.update_state(state="FAILURE", meta={"step": "error", "err": str(e)})
        raise

# ---------- 仅推荐 ----------
@celery.task(name="worker.tasks.run_cybok_reco_gridfs")
def run_cybok_reco_gridfs():
    return _run("task_cybok_reco_gridfs.py")


