"""
Report file upload (Team 4)

Lets an investigator load a report from a file instead of pasting it, in the
"Ingest report" step. Accepted formats: .txt, .pdf and .docx.

The file is only turned into plain text here. Nothing else in the app changes:
the text goes back into the paste box, the investigator can check or edit it,
and the analysis then runs exactly as it does for pasted text.

Same rule as the rest of the app: if a file can't be read cleanly, say so.
Never return garbled, partial or made-up text.

Protection against harmful files (anyone can make a file that LOOKS like a report):
- The file type is decided by its name AND checked against its contents, so a
  program renamed to report.pdf is refused.
- A .docx file is a compressed (zip) folder. A tiny one can be built to expand to
  gigabytes (a "zip bomb"), so its real size is checked before it is opened.
- PDFs: only the first MAX_PDF_PAGES pages are allowed, and the PDF library's own
  limits stop a small stream from expanding to a huge one.
- Reading stops as soon as the text is longer than the report limit.
- Old-style .doc files, macros and embedded objects are never opened or run -
  only the text is read.
"""

import zipfile
from io import BytesIO
from typing import FrozenSet, List

ALLOWED_EXTENSIONS: FrozenSet[str] = frozenset({".txt", ".pdf", ".docx"})

MAX_PDF_PAGES = 500
MAX_DOCX_UNPACKED_BYTES = 100 * 1024 * 1024   # everything inside the .docx, pictures included
MAX_DOCX_XML_PART_BYTES = 20 * 1024 * 1024    # any single text/layout part inside it
MAX_DOCX_PARTS = 2_000


class FileExtractionError(ValueError):
    """The file could not be turned into text. The message is safe to show the investigator."""


class ReportTooLongError(FileExtractionError):
    """The file was readable, but its text is longer than one report may be."""


def extract_text(filename: str, content: bytes, max_chars: int) -> str:
    """
    Turn an uploaded file into plain report text.

    Raises FileExtractionError (or ReportTooLongError) with a message that is safe
    to show the investigator. Never returns empty or partial text.
    """
    ext = file_extension(filename)
    if ext not in ALLOWED_EXTENSIONS:
        raise FileExtractionError(
            f"Files of type '{ext or 'unknown'}' can't be uploaded. "
            f"Accepted formats: {', '.join(sorted(ALLOWED_EXTENSIONS))}."
        )
    if not content:
        raise FileExtractionError("This file is empty.")

    if ext == ".txt":
        text = _read_txt(content)
    elif ext == ".pdf":
        text = _read_pdf(content, max_chars)
    else:
        text = _read_docx(content)

    # Same line endings everywhere (Windows files use \r\n).
    text = text.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not text:
        raise FileExtractionError(
            "No readable text was found in this file. (A scanned PDF, for example, is only a "
            "picture of text - copy the text out of it, or paste it in instead.)"
        )
    if len(text) > max_chars:
        raise _too_long(max_chars)
    return text


def file_extension(filename: str) -> str:
    name = (filename or "").strip().lower()
    return "." + name.rsplit(".", 1)[-1] if "." in name else ""


def _too_long(max_chars: int) -> ReportTooLongError:
    return ReportTooLongError(
        f"The text in this file is longer than {max_chars:,} characters (one report's limit). "
        "Please split the report into parts."
    )


# --- .txt -------------------------------------------------------------------
def _read_txt(content: bytes) -> str:
    # Only encodings we can recognise for certain. Guessing (for example trying
    # UTF-16 on any file) turns an unknown file into nonsense instead of refusing it.
    if content.startswith((b"\xff\xfe", b"\xfe\xff")):          # UTF-16, with its marker
        try:
            text = content.decode("utf-16")
        except UnicodeDecodeError:
            raise FileExtractionError("This text file is damaged and can't be read.")
    else:
        try:
            text = content.decode("utf-8-sig")                     # UTF-8, with or without a marker
        except UnicodeDecodeError:
            raise FileExtractionError(
                "This text file isn't saved as UTF-8, so it can't be read reliably. "
                "Open it in Notepad and use 'Save as' with Encoding: UTF-8, then upload it again."
            )
    if "\x00" in text:
        raise FileExtractionError("This file doesn't look like a text file.")
    return text


# --- .pdf -------------------------------------------------------------------
def _read_pdf(content: bytes, max_chars: int) -> str:
    if b"%PDF-" not in content[:1024]:
        raise FileExtractionError("This file is named .pdf but is not a PDF.")

    from pypdf import PdfReader
    from pypdf.errors import DependencyError

    try:
        # A PDF that is "locked" only against copying or printing still opens with
        # an empty password, like it does in any PDF viewer - the library tries that.
        reader = PdfReader(BytesIO(content))
        if reader.is_encrypted and not reader.decrypt(""):
            raise FileExtractionError(
                "This PDF needs a password to open. Remove the password (or paste the text in) and try again."
            )
        page_count = len(reader.pages)
    except FileExtractionError:
        raise
    except DependencyError:
        raise FileExtractionError("This PDF uses a kind of encryption this app can't open.")
    except Exception:
        raise FileExtractionError("This PDF could not be read. It may be damaged.")

    if page_count > MAX_PDF_PAGES:
        raise FileExtractionError(
            f"This PDF has {page_count:,} pages; the limit is {MAX_PDF_PAGES}. Please split it into parts."
        )

    pages: List[str] = []
    total = 0
    for page in reader.pages:
        try:
            page_text = page.extract_text() or ""
        except Exception:
            raise FileExtractionError("This PDF could not be read. It may be damaged.")
        pages.append(page_text)
        total += len(page_text)
        if total > max_chars:          # stop early: no point reading the rest
            raise _too_long(max_chars)
    return "\n\n".join(pages)


# --- .docx ------------------------------------------------------------------
def _read_docx(content: bytes) -> str:
    not_docx = FileExtractionError(
        "This file is named .docx but is not a Word document. (Old .doc files are not "
        "supported - open it in Word and save it as .docx.)"
    )
    try:
        archive = zipfile.ZipFile(BytesIO(content))
        parts = archive.infolist()
    except zipfile.BadZipFile:
        raise not_docx

    # Check the real sizes BEFORE unpacking anything (see "zip bomb" at the top).
    too_big = FileExtractionError("This Word document is too large or unusually built, so it was not opened.")
    if len(parts) > MAX_DOCX_PARTS or sum(p.file_size for p in parts) > MAX_DOCX_UNPACKED_BYTES:
        raise too_big
    if any(p.file_size > MAX_DOCX_XML_PART_BYTES for p in parts if p.filename.endswith((".xml", ".rels"))):
        raise too_big
    if "word/document.xml" not in {p.filename for p in parts}:
        raise not_docx

    import docx
    from docx.table import Table

    try:
        document = docx.Document(BytesIO(content))
        lines: List[str] = []
        # Paragraphs and tables in the order they appear in the document.
        for block in document.iter_inner_content():
            if isinstance(block, Table):
                for row in block.rows:
                    lines.append(" | ".join(cell.text.strip() for cell in row.cells))
            else:
                lines.append(block.text)
    except Exception:
        raise FileExtractionError("This Word document could not be read. It may be damaged.")
    return "\n".join(lines)
