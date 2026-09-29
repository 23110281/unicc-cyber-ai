"""
Tests for reading report files (.txt, .pdf, .docx).
Run with:  pytest -q test_file_extractor.py

The sample files are built inside the tests, so no test files need to be stored.
"""
import zipfile
from io import BytesIO

import docx
import pytest
from pypdf import PdfReader, PdfWriter

from backend.ingest import file_extractor
from backend.ingest.file_extractor import FileExtractionError, ReportTooLongError, extract_text

LIMIT = 200_000


# ---------------------------------------------------------------------------
# Sample-file builders (also used by test_api.py)
# ---------------------------------------------------------------------------
def make_pdf(pages):
    """A real, minimal PDF with one page per string in `pages`, text readable by any PDF viewer."""
    objects = {1: b"<< /Type /Catalog /Pages 2 0 R >>",
               3: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"}
    kids, next_id = [], 4
    for text in pages:
        page_id, content_id = next_id, next_id + 1
        next_id += 2
        kids.append(f"{page_id} 0 R")
        ops = ["BT", "/F1 11 Tf", "14 TL", "40 760 Td"]
        for line in text.split("\n"):
            ops.append("(" + line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)") + ") Tj T*")
        ops.append("ET")
        stream = "\n".join(ops).encode("latin-1")
        objects[content_id] = b"<< /Length %d >>\nstream\n%s\nendstream" % (len(stream), stream)
        objects[page_id] = (f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>").encode()
    objects[2] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {len(kids)} >>".encode()

    out, offsets = bytearray(b"%PDF-1.4\n"), {}
    for number in range(1, next_id):
        offsets[number] = len(out)
        out += b"%d 0 obj\n%s\nendobj\n" % (number, objects[number])
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % next_id
    for number in range(1, next_id):
        out += b"%010d 00000 n \n" % offsets[number]
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (next_id, xref)
    return bytes(out)


def make_locked_pdf(text, user_password, owner_password="owner-only"):
    """`user_password=""` = locked only against copying/printing; anything else = needs a password to open."""
    writer = PdfWriter(clone_from=PdfReader(BytesIO(make_pdf([text]))))
    writer.encrypt(user_password=user_password, owner_password=owner_password, algorithm="AES-128")
    buffer = BytesIO()
    writer.write(buffer)
    return buffer.getvalue()


def make_docx(build):
    """A real .docx made by python-docx; `build(document)` adds the content."""
    document = docx.Document()
    build(document)
    buffer = BytesIO()
    document.save(buffer)
    return buffer.getvalue()


def add_to_zip(data, name, content, compress=True):
    """Return a copy of the zip file `data` with one more file inside it."""
    buffer = BytesIO(data)
    with zipfile.ZipFile(buffer, "a", zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED) as archive:
        archive.writestr(name, content)
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# File types
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name", ["malware.exe", "report.doc", "notes.rtf", "report", "report.pdf.exe", ""])
def test_only_txt_pdf_and_docx_are_accepted(name):
    with pytest.raises(FileExtractionError, match="can't be uploaded"):
        extract_text(name, b"anything", LIMIT)


def test_file_type_is_checked_against_the_contents():
    # A program renamed to look like a report must not be opened as one.
    program = b"MZ\x90\x00" + b"\x00" * 200
    with pytest.raises(FileExtractionError, match="not a PDF"):
        extract_text("report.pdf", program, LIMIT)
    with pytest.raises(FileExtractionError, match="not a Word document"):
        extract_text("report.docx", program, LIMIT)


def test_extension_check_ignores_upper_case():
    assert extract_text("REPORT.TXT", b"CVE-2023-23397", LIMIT) == "CVE-2023-23397"


def test_empty_file_is_refused():
    with pytest.raises(FileExtractionError, match="empty"):
        extract_text("report.txt", b"", LIMIT)


# ---------------------------------------------------------------------------
# .txt
# ---------------------------------------------------------------------------
def test_txt_utf8_with_and_without_marker():
    text = "Host 10.0.0.5 talked to evil[.]com – café"
    assert extract_text("a.txt", text.encode("utf-8"), LIMIT) == text
    assert extract_text("a.txt", b"\xef\xbb\xbf" + text.encode("utf-8"), LIMIT) == text   # Notepad's UTF-8 marker


def test_txt_utf16_is_read_when_marked():
    text = "CVE-2023-23397 exploited"
    assert extract_text("a.txt", text.encode("utf-16"), LIMIT) == text   # includes the UTF-16 marker


def test_txt_in_unknown_encoding_is_refused_not_guessed():
    # The bug this guards against: an old Windows ("ANSI") file came back as
    # nonsense characters instead of being refused.
    with pytest.raises(FileExtractionError, match="UTF-8"):
        extract_text("a.txt", "café report".encode("cp1252"), LIMIT)


def test_binary_file_named_txt_is_refused():
    with pytest.raises(FileExtractionError, match="doesn't look like a text file"):
        extract_text("a.txt", b"abc\x00\x00def", LIMIT)


def test_whitespace_only_file_is_refused():
    with pytest.raises(FileExtractionError, match="No readable text"):
        extract_text("a.txt", b"  \r\n \n\t ", LIMIT)


def test_windows_line_endings_are_normalised():
    assert extract_text("a.txt", b"line one\r\nline two\r\n", LIMIT) == "line one\nline two"


# ---------------------------------------------------------------------------
# .pdf
# ---------------------------------------------------------------------------
def test_pdf_text_is_read_from_every_page():
    pdf = make_pdf(["Host 10.14.6.23 beaconed to 185.220.101.47", "Exploit: CVE-2023-23397"])
    text = extract_text("report.pdf", pdf, LIMIT)
    assert "185.220.101.47" in text
    assert "CVE-2023-23397" in text
    assert text.index("185.220.101.47") < text.index("CVE-2023-23397")   # pages stay in order


def test_pdf_without_text_is_refused():
    # For example a scanned report: a picture of text, with no text inside.
    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    buffer = BytesIO()
    writer.write(buffer)
    with pytest.raises(FileExtractionError, match="No readable text"):
        extract_text("scan.pdf", buffer.getvalue(), LIMIT)


def test_damaged_pdf_is_refused():
    with pytest.raises(FileExtractionError):
        extract_text("report.pdf", b"%PDF-1.4\nthis is not really a pdf", LIMIT)


def test_pdf_locked_only_against_copying_opens_like_in_a_viewer():
    pdf = make_locked_pdf("Beacon to 185.220.101.47", user_password="")
    assert "185.220.101.47" in extract_text("report.pdf", pdf, LIMIT)


def test_pdf_that_needs_a_password_is_refused():
    pdf = make_locked_pdf("Beacon to 185.220.101.47", user_password="secret")
    with pytest.raises(FileExtractionError, match="needs a password"):
        extract_text("report.pdf", pdf, LIMIT)


def test_pdf_with_too_many_pages_is_refused(monkeypatch):
    monkeypatch.setattr(file_extractor, "MAX_PDF_PAGES", 3)
    with pytest.raises(FileExtractionError, match="4 pages; the limit is 3"):
        extract_text("report.pdf", make_pdf(["a", "b", "c", "d"]), LIMIT)


def test_pdf_reading_stops_once_the_text_is_too_long():
    pdf = make_pdf(["x" * 60, "y" * 60, "z" * 60])
    with pytest.raises(ReportTooLongError):
        extract_text("report.pdf", pdf, max_chars=100)


# ---------------------------------------------------------------------------
# .docx
# ---------------------------------------------------------------------------
def test_docx_paragraphs_and_tables_keep_their_order():
    def build(document):
        document.add_paragraph("Summary: beaconing observed.")
        table = document.add_table(rows=2, cols=2)
        table.cell(0, 0).text, table.cell(0, 1).text = "Indicator", "Type"
        table.cell(1, 0).text, table.cell(1, 1).text = "185.220.101.47", "IP"
        document.add_paragraph("Recommendation: block at the firewall.")

    text = extract_text("report.docx", make_docx(build), LIMIT)
    assert "185.220.101.47 | IP" in text
    assert text.index("Summary") < text.index("185.220.101.47") < text.index("Recommendation")


def test_zip_file_that_is_not_a_word_document_is_refused():
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("readme.txt", "hello")
    with pytest.raises(FileExtractionError, match="not a Word document"):
        extract_text("report.docx", buffer.getvalue(), LIMIT)


def test_docx_zip_bomb_is_refused_before_unpacking():
    # 25 MB of zeros squeezes into a few kilobytes; unpacked, it would be parsed in memory.
    bomb = add_to_zip(make_docx(lambda d: d.add_paragraph("hi")), "word/bomb.xml", b"0" * (25 * 1024 * 1024))
    assert len(bomb) < 200 * 1024
    with pytest.raises(FileExtractionError, match="too large or unusually built"):
        extract_text("report.docx", bomb, LIMIT)


def test_docx_total_unpacked_size_is_limited(monkeypatch):
    monkeypatch.setattr(file_extractor, "MAX_DOCX_UNPACKED_BYTES", 1024 * 1024)
    big = add_to_zip(make_docx(lambda d: d.add_paragraph("hi")), "word/media/image1.png", b"\x00" * (2 * 1024 * 1024))
    with pytest.raises(FileExtractionError, match="too large or unusually built"):
        extract_text("report.docx", big, LIMIT)


def test_empty_docx_is_refused():
    with pytest.raises(FileExtractionError, match="No readable text"):
        extract_text("report.docx", make_docx(lambda d: None), LIMIT)


def test_docx_text_over_the_limit_is_refused():
    with pytest.raises(ReportTooLongError, match="longer than 100 characters"):
        extract_text("report.docx", make_docx(lambda d: d.add_paragraph("x" * 150)), max_chars=100)
