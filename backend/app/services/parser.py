import io
from typing import Optional
from fastapi import UploadFile, HTTPException


async def parse_file(file: UploadFile) -> str:
    """Extract plain text from an uploaded file (PDF, DOCX, TXT, LOG)."""
    filename = file.filename or ""
    ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""

    raw_bytes = await file.read()

    if ext == "pdf":
        return _parse_pdf(raw_bytes, filename)
    elif ext in ("doc", "docx"):
        return _parse_docx(raw_bytes, filename)
    elif ext in ("txt", "log", "csv", "sql"):
        return _parse_text(raw_bytes, filename)
    else:
        # Try UTF-8 decode for any unknown text-like file
        try:
            return raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            raise HTTPException(
                status_code=415,
                detail=f"Unsupported file type: .{ext}. Supported: pdf, doc, docx, txt, log, sql.",
            )


def _parse_pdf(data: bytes, filename: str) -> str:
    try:
        from pypdf import PdfReader

        reader = PdfReader(io.BytesIO(data))
        pages = [page.extract_text() or "" for page in reader.pages]
        return "\n".join(pages)
    except ImportError:
        raise HTTPException(status_code=500, detail="pypdf not installed — cannot parse PDF.")
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Failed to parse PDF '{filename}': {exc}")


def _parse_docx(data: bytes, filename: str) -> str:
    try:
        from docx import Document

        doc = Document(io.BytesIO(data))
        paragraphs = [p.text for p in doc.paragraphs]
        return "\n".join(paragraphs)
    except ImportError:
        raise HTTPException(status_code=500, detail="python-docx not installed — cannot parse DOCX.")
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Failed to parse DOCX '{filename}': {exc}")


def _parse_text(data: bytes, filename: str) -> str:
    try:
        return data.decode("utf-8", errors="replace")
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Failed to read '{filename}': {exc}")


def parse_sql(sql: str) -> str:
    """Return SQL as-is; detection engine handles the rest."""
    return sql


def parse_chat(chat: str) -> str:
    """Return chat content as-is."""
    return chat
