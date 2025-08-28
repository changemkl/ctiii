# ingest_cybok_intro_pdf_gapabs.py (TOC-based)
# -*- coding: utf-8 -*-
"""
Ingest multiple CyBOK PDFs → split into sections using embedded TOC (bookmarks)
→ write sections to MongoDB → build a FAISS index and store it (and metadata) in GridFS.
"""
import os
import io
import re
import json
import logging
import requests
import gridfs
import tempfile
import numpy as np
from pymongo import MongoClient
from sentence_transformers import SentenceTransformer
import faiss
import fitz  # PyMuPDF

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# ===== Configuration =====
MONGODB_URI = os.getenv(
    "MONGODB_URI",
    "mongodb+srv://yzhang850:a237342160@cluster0.cficuai.mongodb.net/?retryWrites=true&w=majority&authSource=admin"
)
DB_NAME = os.getenv("DB_NAME", "cti_platform")
COLL_NAME = os.getenv("CYBOK_COLL", "cybok_sections")
CYBOK_VERSION = os.getenv("CYBOK_VERSION", "v1")
CYBOK_PDF_URLS = os.getenv(
    "CYBOK_PDF_URLS",
    "https://www.cybok.org/media/downloads/Introduction_v1.1.0.pdf,"
    "https://www.cybok.org/media/downloads/Risk-Management--Governance-issue-1.0.pdf,"
    "https://www.cybok.org/media/downloads/Law__Regulation_issue_1.0.pdf,"
    "https://www.cybok.org/media/downloads/Human_Factors_issue_1.0.pdf,"
    "https://www.cybok.org/media/downloads/Risk-Management--Governance-issue-1.0.pdf,"
    "https://www.cybok.org/media/downloads/Privacy__Online_Rights_issue_1.0_FNULPeI.pdf,"
    "https://www.cybok.org/media/downloads/Malware__Attack_Technology_issue_1.0.pdf,"
    "https://www.cybok.org/media/downloads/Adversarial_Behaviours_issue_1.0.pdf,"
    "https://www.cybok.org/media/downloads/Security_Operations__Incident_Management_issue_1.0.pdf,"
    "https://www.cybok.org/media/downloads/Distributed_Systems_Security_issue_1.0.pdf,"
    "https://www.cybok.org/media/downloads/AAA_issue_1.0_q3qspzo.pdf,"
    "https://www.cybok.org/media/downloads/Software_Security_issue_1.0_1M7Kfk2.pdf,"
    "https://www.cybok.org/media/downloads/Web__Mobile_Security_issue_1.0_XFpbYNz.pdf,"
    "https://www.cybok.org/media/downloads/Secure_Software_Lifecycle_issue_1.0.pdf,"
    "https://www.cybok.org/media/downloads/Network_Security_issue_1.0_qsCh0SR.pdf,"
    "https://www.cybok.org/media/downloads/Hardware_Security_issue_1.0.pdf,"
    "https://www.cybok.org/media/downloads/Cyber-Physical_Systems_Security_issue_1.0.pdf,"
    "https://www.cybok.org/media/downloads/Physical_Layer__Telecommunications_Security_issue_1.0.pdf,"
).split(",")
CYBOK_PDF_URLS = [u.strip() for u in CYBOK_PDF_URLS if u.strip()]

# TOC level selection: 1 = chapter, 2 = section (adjust as needed)
MIN_TOC_LEVEL = int(os.getenv("CYBOK_MIN_TOC_LEVEL", "1"))
MAX_TOC_LEVEL = int(os.getenv("CYBOK_MAX_TOC_LEVEL", "2"))

# ===== Utility: download a PDF =====
def download_pdf(url: str) -> bytes:
    logging.info("Downloading PDF from %s", url)
    resp = requests.get(url, timeout=60)
    resp.raise_for_status()
    return resp.content

# ===== Split into sections using TOC =====
_rx_sec = re.compile(r'^\s*(\d+(?:\.\d+)*)(?:\s+|:)?\s*(.*?)\s*$')  # e.g., "5.4 Enacting Security Policy"

def _parse_toc_title(title: str):
    """
    Returns (section, pure_title, chapter).
    If the title has no numeric prefix, then section=None, chapter=None, pure_title=title.
    """
    m = _rx_sec.match(title or "")
    if not m:
        return None, (title or "").strip(), None
    section = m.group(1).strip()
    pure_title = m.group(2).strip()
    chapter = section.split(".")[0]
    return section, pure_title, chapter

def split_sections_by_toc(pdf_bytes: bytes, min_level=1, max_level=2):
    """
    Split using the embedded TOC (bookmarks):
    - Only include entries whose levels are within [min_level, max_level]
    - Each entry's content is the concatenated text from its start page
      up to the page before the next entry starts.
    Returns: [{section, title, chapter, content}]
    """
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    toc = doc.get_toc(simple=True)  # [(level, title, page1), ...]
    if not toc:
        logging.warning("No embedded TOC found in PDF; skipping TOC-based split.")
        return []

    # Filter by levels
    items = [(lvl, ttl.strip(), p1) for (lvl, ttl, p1) in toc if min_level <= lvl <= max_level]
    if not items:
        logging.warning("TOC present, but contains no entries in levels [%d, %d].", min_level, max_level)
        return []

    sections = []
    for i, (lvl, ttl, p1) in enumerate(items):
        start = max(1, int(p1))
        end = (items[i + 1][2] - 1) if (i + 1) < len(items) else doc.page_count
        end = max(start, min(end, doc.page_count))

        # Concatenate page texts
        page_texts = []
        for pno in range(start - 1, end):
            page_texts.append(doc.load_page(pno).get_text("text"))
        content = "\n".join(page_texts).strip()

        sec, pure_title, chapter = _parse_toc_title(ttl)
        sections.append({
            "section": sec if sec else "",       # may be empty (non-numbered TOC entry)
            "title": pure_title if pure_title else (ttl or "").strip(),
            "chapter": chapter if chapter else (sec.split(".")[0] if sec else ""),
            "content": content
        })
    return sections

# ===== Save sections to MongoDB =====
def save_to_mongo(sections, mongo):
    coll = mongo[DB_NAME][COLL_NAME]
    coll.delete_many({"version": CYBOK_VERSION})
    for sec in sections:
        sec["version"] = CYBOK_VERSION
    if sections:
        coll.insert_many(sections)
    logging.info("Inserted %d sections into %s.%s", len(sections), DB_NAME, COLL_NAME)

# ===== Build FAISS index and store in GridFS =====
def build_and_store_index(sections, mongo):
    model = SentenceTransformer("all-MiniLM-L6-v2")
    texts = [f"{s.get('title','')} {s.get('content','')}" for s in sections]
    if not texts:
        logging.warning("No text available to build index; skipping FAISS.")
        return

    vecs = model.encode(texts, batch_size=64, normalize_embeddings=True).astype("float32")
    index = faiss.IndexFlatIP(vecs.shape[1])
    index.add(vecs)

    # Robust serialization compatible with multiple faiss builds
    def _serialize_index(idx) -> bytes:
        try:
            buf = faiss.serialize_index(idx)  # available in newer faiss
            return bytes(buf)                 # some envs return a bytes-like SWIG object
        except Exception:
            # Fallback: write to temp file and read back
            tmp_path = None
            try:
                with tempfile.NamedTemporaryFile(suffix=".faiss", delete=False) as f:
                    tmp_path = f.name
                faiss.write_index(idx, tmp_path)
                with open(tmp_path, "rb") as rf:
                    return rf.read()
            finally:
                if tmp_path and os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except Exception:
                        pass

    idx_bytes = _serialize_index(index)

    fs = gridfs.GridFS(mongo[DB_NAME])

    # Metadata
    meta = []
    for i, s in enumerate(sections):
        chapter = s.get("chapter", "") or ""
        meta.append({
            "ka_id": f"KA-{chapter.zfill(2)}" if chapter else "KA-00",
            "title": s.get("title", ""),
            "section": s.get("section", ""),
            "chapter": chapter,
            "url": None
        })

    # Overwrite old files
    old = fs.find_one({"filename": f"cybok.index.{CYBOK_VERSION}"})
    if old: fs.delete(old._id)
    old = fs.find_one({"filename": f"cybok_meta.json.{CYBOK_VERSION}"})
    if old: fs.delete(old._id)

    fs.put(idx_bytes, filename=f"cybok.index.{CYBOK_VERSION}")
    fs.put(json.dumps(meta, ensure_ascii=False).encode("utf-8"), filename=f"cybok_meta.json.{CYBOK_VERSION}")
    logging.info("Stored FAISS index & metadata to GridFS")

# ===== Main =====
def main():
    mongo = MongoClient(MONGODB_URI)
    all_sections = []
    for url in CYBOK_PDF_URLS:
        try:
            pdf_data = download_pdf(url)
            sections = split_sections_by_toc(pdf_data, min_level=MIN_TOC_LEVEL, max_level=MAX_TOC_LEVEL)
            logging.info("Parsed %d sections from %s", len(sections), url)
            all_sections.extend(sections)
        except Exception as e:
            logging.exception("Failed to process %s: %s", url, e)

    save_to_mongo(all_sections, mongo)
    build_and_store_index(all_sections, mongo)
    logging.info("Done.")

if __name__ == "__main__":
    main()
