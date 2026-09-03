"""Local document ingestion and citation-friendly retrieval."""

from __future__ import annotations

import hashlib
import io
import json
import math
import re
import shutil
from pathlib import Path
from typing import Any

from .infra_store import OpsStore, store, utc_now
from .platform_security import app_data_dir, redact_text


ALLOWED_SUFFIXES = {".md", ".txt", ".log", ".yaml", ".yml", ".json", ".pdf"}
MAX_DOCUMENT_BYTES = 20 * 1024 * 1024


def _extract(filename: str, data: bytes) -> str:
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        raise ValueError("支持导入 .md、.txt、.log、.yaml、.yml、.json 和 .pdf")
    if len(data) > MAX_DOCUMENT_BYTES:
        raise ValueError("知识文档不能超过 20MB")
    if suffix == ".pdf":
        try:
            from pypdf import PdfReader
        except ImportError as exc:
            raise RuntimeError("缺少 pypdf，无法解析 PDF") from exc
        reader = PdfReader(io.BytesIO(data))
        return "\n\n".join((page.extract_text() or "").strip() for page in reader.pages).strip()
    text = data.decode("utf-8-sig", "replace")
    if suffix == ".json":
        try:
            text = json.dumps(json.loads(text), ensure_ascii=False, indent=2)
        except ValueError:
            pass
    return text.strip()


def _chunks(text: str, size: int = 1200, overlap: int = 180) -> list[str]:
    normalized = re.sub(r"\r\n?", "\n", text).strip()
    if not normalized:
        return []
    parts = []
    start = 0
    while start < len(normalized):
        end = min(len(normalized), start + size)
        if end < len(normalized):
            boundary = max(normalized.rfind("\n", start + size // 2, end),
                           normalized.rfind("。", start + size // 2, end))
            if boundary > start:
                end = boundary + 1
        parts.append(normalized[start:end].strip())
        if end >= len(normalized):
            break
        start = max(start + 1, end - overlap)
    return [part for part in parts if part]


def _tokens(text: str) -> list[str]:
    try:
        import jieba
        values = [part.strip().lower() for part in jieba.cut_for_search(text) if part.strip()]
    except ImportError:
        values = re.findall(r"[A-Za-z0-9_.:/-]+|[\u4e00-\u9fff]{1,4}", text.lower())
    return values[:5000]


def import_document(filename: str, data: bytes, source_type: str = "manual", source_ref: str = "",
                    ops_store: OpsStore = store) -> dict[str, Any]:
    text = redact_text(_extract(filename, data))
    if not text:
        raise ValueError("文档没有可提取的文本；扫描版 PDF 暂不支持 OCR")
    digest = hashlib.sha256(data).hexdigest()
    existing = ops_store.query_one("SELECT id FROM knowledge_document WHERE sha256=?", (digest,))
    if existing:
        result = get_document(existing["id"], ops_store)
        result["duplicate"] = True
        return result
    safe_name = re.sub(r"[^\w.\-\u4e00-\u9fff]+", "_", Path(filename).name)[:160] or "document.txt"
    stored_path = app_data_dir() / "knowledge" / f"{digest[:16]}-{safe_name}"
    stored_path.write_bytes(data)
    now = utc_now()
    document_id = ops_store.execute(
        "INSERT INTO knowledge_document(title,source_type,source_ref,sha256,file_path,created_at,updated_at) "
        "VALUES(?,?,?,?,?,?,?)", (Path(filename).stem, source_type, source_ref, digest, str(stored_path), now, now),
    )
    for index, chunk in enumerate(_chunks(text)):
        search_text = " ".join(_tokens(chunk))
        chunk_id = ops_store.execute(
            "INSERT INTO knowledge_chunk(document_id,chunk_index,content,search_text) VALUES(?,?,?,?)",
            (document_id, index, chunk, search_text),
        )
        ops_store.execute(
            "INSERT INTO knowledge_fts(chunk_id,title,search_text) VALUES(?,?,?)",
            (chunk_id, Path(filename).stem, search_text),
        )
    return get_document(document_id, ops_store)


def index_record(title: str, content: str, source_type: str, source_ref: str,
                 ops_store: OpsStore = store) -> dict[str, Any]:
    data = redact_text(content).encode("utf-8")
    virtual_name = f"{title}.md"
    return import_document(virtual_name, data, source_type, source_ref, ops_store)


def get_document(document_id: int, ops_store: OpsStore = store) -> dict[str, Any]:
    row = ops_store.query_one(
        "SELECT d.*,COUNT(c.id) AS chunk_count FROM knowledge_document d "
        "LEFT JOIN knowledge_chunk c ON c.document_id=d.id WHERE d.id=? GROUP BY d.id", (document_id,),
    )
    if not row:
        raise ValueError("知识文档不存在")
    row["favorite"] = bool(row["favorite"])
    return row


def list_documents(ops_store: OpsStore = store) -> list[dict[str, Any]]:
    rows = ops_store.query(
        "SELECT d.*,COUNT(c.id) AS chunk_count FROM knowledge_document d "
        "LEFT JOIN knowledge_chunk c ON c.document_id=d.id GROUP BY d.id ORDER BY d.updated_at DESC"
    )
    for row in rows:
        row["favorite"] = bool(row["favorite"])
    return rows


def delete_document(document_id: int, ops_store: OpsStore = store) -> None:
    row = ops_store.query_one("SELECT file_path FROM knowledge_document WHERE id=?", (document_id,))
    if not row:
        raise ValueError("知识文档不存在")
    chunk_ids = [item["id"] for item in ops_store.query(
        "SELECT id FROM knowledge_chunk WHERE document_id=?", (document_id,)
    )]
    for chunk_id in chunk_ids:
        ops_store.execute("DELETE FROM knowledge_fts WHERE chunk_id=?", (chunk_id,))
    ops_store.execute("DELETE FROM knowledge_document WHERE id=?", (document_id,))
    path = Path(row["file_path"] or "")
    if path.is_file() and path.parent.resolve() == (app_data_dir() / "knowledge").resolve():
        path.unlink(missing_ok=True)


def _cosine(left: list[float], right: list[float]) -> float:
    if not left or len(left) != len(right):
        return 0.0
    dot = sum(a * b for a, b in zip(left, right))
    norm = math.sqrt(sum(a * a for a in left)) * math.sqrt(sum(b * b for b in right))
    return dot / norm if norm else 0.0


def search(query: str, limit: int = 8, query_embedding: list[float] | None = None,
           embedding_model: str = "", ops_store: OpsStore = store) -> list[dict[str, Any]]:
    words = list(dict.fromkeys(_tokens(query)))[:24]
    lexical: dict[int, float] = {}
    if words:
        expression = " OR ".join(f'"{word.replace(chr(34), "")}"' for word in words)
        try:
            for row in ops_store.query(
                "SELECT CAST(chunk_id AS INTEGER) AS chunk_id,bm25(knowledge_fts) AS rank "
                "FROM knowledge_fts WHERE knowledge_fts MATCH ? LIMIT 50", (expression,),
            ):
                lexical[int(row["chunk_id"])] = 1 / (1 + abs(float(row["rank"])))
        except Exception:
            lexical = {}
    rows = ops_store.query(
        "SELECT c.id,c.document_id,c.chunk_index,c.content,c.embedding_json,c.embedding_model,"
        "d.title,d.source_type,d.source_ref,d.updated_at FROM knowledge_chunk c "
        "JOIN knowledge_document d ON d.id=c.document_id"
    )
    scored = []
    for row in rows:
        lex = lexical.get(int(row["id"]), 0.0)
        sem = 0.0
        if query_embedding and row["embedding_json"] and row["embedding_model"] == embedding_model:
            sem = max(0.0, _cosine(query_embedding, json.loads(row["embedding_json"])))
        score = (0.45 * lex + 0.55 * sem) if query_embedding else lex
        if score > 0:
            scored.append({**row, "score": round(score, 5)})
    scored.sort(key=lambda item: item["score"], reverse=True)
    for item in scored:
        item.pop("embedding_json", None)
    return scored[:max(1, min(limit, 30))]

