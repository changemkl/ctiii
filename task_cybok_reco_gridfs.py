# task_cybok_reco_gridfs.py
# -*- coding: utf-8 -*-
"""
Reads CyBOK section-level index (FAISS + meta) from GridFS,
performs similarity matching against the `threats` collection
(default only MSRC Blog items), and writes recommendations back
to `threats.recommendations.cybok`.

Write-back example:
threats.recommendations.cybok = [
  {
    "sid": "64f2...c9b1",
    "ka_id": "...",
    "title": "...",
    "section": "3.2",
    "chapter": "3",
    "score": 0.78,
    "url": "/cybok/64f2...c9b1"
  }
]
"""
import os, json, logging, re
from datetime import datetime, timezone, timedelta

import faiss
import gridfs
import numpy as np
from pymongo import MongoClient, UpdateOne
from sentence_transformers import SentenceTransformer

# ---------- Configuration ----------
MONGODB_URI = os.getenv(
    "MONGODB_URI",
    "mongodb+srv://yzhang850:a237342160@cluster0.cficuai.mongodb.net/?retryWrites=true&w=majority&authSource=admin"
)
DB_NAME     = os.getenv("DB_NAME", "cti_platform")
COLL_NAME   = os.getenv("COLL_NAME", "threats")

CYBOK_VERSION = os.getenv("CYBOK_VERSION", "v1")
IDX_NAME  = f"cybok.index.{CYBOK_VERSION}"
META_NAME = f"cybok_meta.json.{CYBOK_VERSION}"

MODEL_NAME  = os.getenv("CYBOK_MODEL", "all-MiniLM-L6-v2")
SOURCE_LIST = os.getenv("RECO_SOURCES", "msrc_blog").split(",")
DAYS_LIMIT  = int(os.getenv("RECO_DAYS", "30"))
TOPK        = int(os.getenv("RECO_TOPK", "5"))
BATCH       = int(os.getenv("RECO_BATCH", "48"))
MIN_SCORE   = float(os.getenv("RECO_MIN_SCORE", "0.25"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# ---------- CyBOK Index Loader ----------
class CybokIndex:
    """
    Wrapper for loading CyBOK FAISS index + metadata from Mongo GridFS.
    """
    def __init__(self, mongo: MongoClient):
        db = mongo[DB_NAME]
        fs = gridfs.GridFS(db)

        fidx  = fs.find_one({"filename": IDX_NAME})
        fmeta = fs.find_one({"filename": META_NAME})
        if not fidx or not fmeta:
            raise RuntimeError(f"GridFS did not contain {IDX_NAME} or {META_NAME}")

        idx_bytes  = fidx.read()
        meta_bytes = fmeta.read()

        # Try deserializing FAISS index directly from bytes,
        # if not possible, fallback to uint8 numpy buffer
        try:
            self.index = faiss.deserialize_index(idx_bytes)
        except Exception:
            idx_arr = np.frombuffer(idx_bytes, dtype='uint8')
            self.index = faiss.deserialize_index(idx_arr)

        self.meta  = json.loads(meta_bytes.decode("utf-8"))
        self.count = len(self.meta)
        logging.info("Cybok index loaded: items=%d", self.count)

        self.model = SentenceTransformer(MODEL_NAME)

    def search_texts(self, texts, topk=TOPK):
        """
        Encode and search multiple texts against the FAISS index.
        Returns distances and indices.
        """
        if not texts:
            return None, None
        vecs = self.model.encode(
            texts,
            batch_size=64,
            normalize_embeddings=True
        ).astype("float32")
        D, I = self.index.search(vecs, topk)
        return D, I

# ---------- Recommendation Logic ----------
def normalize_text(s: str):
    import html
    s = s or ""
    s = html.unescape(s)
    s = re.sub(r"\s+", " ", s)
    return s.strip()

def doc_to_query_text(doc):
    """
    Build a query string from document title + content.
    """
    title = normalize_text(doc.get("title") or "")
    content = normalize_text(doc.get("content") or "")
    return (title + " " + content)[:2000]

def recommend_for_docs(mongo: MongoClient):
    """
    Generate CyBOK recommendations for matching docs in `threats`.
    """
    db = mongo[DB_NAME]
    coll = db[COLL_NAME]

    idx = CybokIndex(mongo)

    since = datetime.now(timezone.utc) - timedelta(days=DAYS_LIMIT)
    filt = {
        "source": {"$in": SOURCE_LIST},
        "timestamp": {"$gte": since},
        "content": {"$exists": True, "$ne": ""},
    }
    fields = {"_id": 1, "title": 1, "content": 1, "source": 1}
    docs = list(coll.find(filt, fields).sort([("timestamp", -1)]))
    logging.info("Docs to process: %d", len(docs))

    ops = []
    batch_texts, batch_ids = [], []
    for d in docs:
        q = doc_to_query_text(d)
        if not q:
            continue
        batch_texts.append(q); batch_ids.append(d["_id"])

        if len(batch_texts) >= BATCH:
            D, I = idx.search_texts(batch_texts, TOPK)
            if D is not None:
                ops.extend(make_ops(batch_ids, D, I, idx.meta))
            batch_texts, batch_ids = [], []

    if batch_texts:
        D, I = idx.search_texts(batch_texts, TOPK)
        if D is not None:
            ops.extend(make_ops(batch_ids, D, I, idx.meta))

    if ops:
        res = coll.bulk_write(ops, ordered=False)
        logging.info(
            "Updated docs: matched=%s modified=%s",
            getattr(res, "matched_count", 0),
            getattr(res, "modified_count", 0)
        )
    else:
        logging.info("No updates to write.")

def _extract_sid_from_meta(m):
    """
    Extract `sid` (ObjectId string) from metadata:
    1) Prefer `_id` / `sid` (handle {"$oid": "..."} form).
    2) Otherwise parse from URL `/cybok/<sid>`.
    """
    sid = m.get("_id") or m.get("sid") or ""
    if isinstance(sid, dict) and "$oid" in sid:
        sid = sid["$oid"]
    if not isinstance(sid, str):
        sid = str(sid or "")
    if not sid:
        u = (m.get("url") or "").strip()
        m2 = re.search(r"/cybok/([0-9a-fA-F]{24})", u)
        if m2:
            sid = m2.group(1)
    return sid

def make_ops(ids, D, I, meta):
    """
    Construct MongoDB bulk update operations with recommendations.
    """
    ops = []
    for row, _id in enumerate(ids):
        recs = []
        for j, midx in enumerate(I[row]):
            if midx < 0 or midx >= len(meta):
                continue
            score = float(D[row, j])
            if score < MIN_SCORE:
                continue

            m = meta[midx]
            sid = _extract_sid_from_meta(m)
            url = f"/cybok/{sid}" if sid else (m.get("url") or None)

            recs.append({
                "sid": sid or None,
                "ka_id": m.get("ka_id"),
                "title": m.get("title"),
                "section": m.get("section"),
                "chapter": m.get("chapter"),
                "score": score,
                "url": url,
            })

        if recs:
            ops.append(UpdateOne({"_id": _id}, {"$set": {"recommendations.cybok": recs}}))
    return ops

# ---------- Entry ----------
def main():
    mongo = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=20000, connectTimeoutMS=20000)
    recommend_for_docs(mongo)

if __name__ == "__main__":
    main()
