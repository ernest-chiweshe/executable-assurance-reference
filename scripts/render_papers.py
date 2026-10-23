"""Render the new manuscript editions as self-contained HTML and paginated PDFs.

Uses local fonts/assets only. Browser requests to remote resources are blocked.
The source manuscripts and historical assets are never rewritten by rendering.
"""
import base64
import hashlib
import json
import mimetypes
from pathlib import Path

import fitz
import markdown
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "docs/papers"
OUT = BUNDLE
QA = ROOT / "tmp/paper-qa-20261018"

CSS = """
@page { size: A4; margin: 18mm 17mm 20mm; }
* { box-sizing: border-box; }
html { color: #172b2b; background: #eef3f1; }
body { max-width: 980px; margin: 32px auto; padding: 48px 64px; background: white;
       font-family: Georgia, 'Times New Roman', serif; font-size: 17px; line-height: 1.6; }
.edition { font-family: Arial,sans-serif; font-size: 11px; font-weight: bold;
           letter-spacing: .12em; color: #0f766e; border-bottom: 2px solid #0f766e;
           padding-bottom: 12px; margin-bottom: 24px; }
h1,h2,h3,h4 { font-family: Arial,sans-serif; color: #133e3b; line-height: 1.23;
              break-after: avoid; page-break-after: avoid; }
h1 { font-size: 36px; letter-spacing: -.025em; }
h2 { margin-top: 30px; font-size: 23px; }
h3 { margin-top: 24px; font-size: 18px; }
h4 { font-size: 16px; }
p { margin: 0 0 12px; orphans: 3; widows: 3; }
a { color: #116e67; overflow-wrap: anywhere; }
li { margin-bottom: 7px; }
hr { border: 0; border-top: 1px solid #cbd9d5; margin: 24px 0; }
table { width: 100%; border-collapse: collapse; margin: 16px 0;
        font-family: Arial,sans-serif; font-size: 12px; line-height: 1.38; }
thead { display: table-header-group; }
th { background: #e8f2ef; color: #143f3a; text-align: left; }
td,th { border: 1px solid #d5dfdc; padding: 7px; vertical-align: top;
        overflow-wrap: anywhere; }
tr { break-inside: avoid; }
figure { margin: 22px 0; break-inside: avoid; }
figure img { display: block; width: 100%; height: auto; max-height: 145mm; object-fit: contain; }
figcaption { margin-top: 9px; font: 12px/1.45 Arial,sans-serif; color: #3e5350; }
code,pre { font-family: Consolas,'Courier New',monospace; font-size: .85em; }
code { overflow-wrap: anywhere; }
pre { white-space: pre-wrap; padding: 12px; background: #f1f5f3; }
blockquote { margin: 15px 0; padding: 4px 16px; border-left: 3px solid #3b8b7b; }
@media print {
 html,body { background: white; }
 body { width: auto; max-width: none; margin: 0; padding: 0; font-size: 10.5pt; line-height: 1.42; }
 h1 { font-size: 27pt; } h2 { font-size: 16pt; margin-top: 20px; }
 h3 { font-size: 12.3pt; margin-top: 16px; } h4 { font-size: 11pt; }
 table { font-size: 8pt; line-height: 1.35; } td,th { padding: 5px; }
 figcaption { font-size: 8.5pt; } figure { margin: 14px 0; }
 a { color: inherit; text-decoration: none; } .edition { font-size: 8pt; }
}
@media (max-width: 700px) { body { padding: 22px; margin: 0; } table { font-size: 10px; } }
"""


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def html_for(source, label):
    body = markdown.markdown(source.read_text(encoding="utf-8"), extensions=["tables", "fenced_code", "toc", "sane_lists"])
    soup = BeautifulSoup(body, "html.parser")
    # Paper B supplies explicit heading anchors. Remove duplicate empty anchors
    # only when the converter has generated the same ID on its heading.
    for anchor in list(soup.select("a[id]")):
        if len(soup.find_all(id=anchor["id"])) > 1 and not anchor.get_text(strip=True):
            anchor.decompose()
    for image in list(soup.find_all("img")):
        local = (source.parent / image["src"]).resolve()
        if not local.is_relative_to(BUNDLE.resolve()):
            raise ValueError("Image leaves publication bundle")
        data = local.read_bytes()
        mime = mimetypes.guess_type(local.name)[0] or "application/octet-stream"
        image["src"] = "data:" + mime + ";base64," + base64.b64encode(data).decode("ascii")
        paragraph = image.parent
        if paragraph.name != "p":
            raise ValueError("Expected standalone figure paragraph")
        caption = paragraph.find_next_sibling()
        figure = soup.new_tag("figure")
        paragraph.replace_with(figure)
        figure.append(image.extract())
        if caption and caption.name == "p" and caption.get_text(strip=True).startswith("Figure "):
            cap = soup.new_tag("figcaption")
            for child in list(caption.contents):
                cap.append(child.extract())
            caption.decompose()
            figure.append(cap)
    ids = [tag["id"] for tag in soup.select("[id]")]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate HTML anchor")
    broken = [link["href"] for link in soup.select('a[href^="#"]') if link["href"][1:] not in ids]
    if broken:
        raise ValueError(f"Broken internal links: {broken}")
    return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>' + label + '</title><style>' + CSS + '</style></head><body><div class="edition">PUBLICATION CANDIDATE · 18 OCTOBER 2026 · ' + label + '</div>' + str(soup) + '</body></html>'


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    QA.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((BUNDLE / "ADOPTION.json").read_text(encoding="utf-8"))
    reports = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel="chrome", headless=True, chromium_sandbox=True, timeout=20000)
        context = browser.new_context(offline=True)
        context.route("**/*", lambda route: route.continue_() if route.request.url.startswith(("file:", "data:")) else route.abort())
        page = context.new_page()
        for key, name, label in [("paper_a", "Paper-A-v1.8", "Paper A / v1.8"), ("paper_b", "Paper-B-v14", "Paper B / v14")]:
            source = BUNDLE / manifest[key]
            html = OUT / (name + ".html")
            pdf = OUT / (name + ".pdf")
            html.write_text(html_for(source, label), encoding="utf-8", newline="\n")
            page.goto(html.as_uri(), wait_until="load")
            page.evaluate("document.fonts.ready")
            images = page.locator("img").evaluate_all("xs => xs.map(x => ({ok:x.complete && x.naturalWidth>0, alt:x.alt}))")
            if not all(x["ok"] for x in images):
                raise ValueError("Missing image: " + repr(images))
            page.pdf(path=str(pdf), format="A4", print_background=True, prefer_css_page_size=True,
                     display_header_footer=True, header_template="<span></span>",
                     footer_template='<div style="font-size:8px;color:#516661;width:100%;margin:0 17mm;display:flex;justify-content:space-between"><span>' + label + ' · Publication candidate</span><span><span class="pageNumber"></span> / <span class="totalPages"></span></span></div>')
            document = fitz.open(pdf)
            text = "\n".join(p.get_text() for p in document)
            if "Physical G4" not in text or "COMPLIANCE" not in text or "GOVERNANCE" not in text:
                raise ValueError("Missing critical scope text in PDF")
            # Review every rendered page via contact sheets; retain full pages for zoom.
            for index, pdf_page in enumerate(document):
                pdf_page.get_pixmap(matrix=fitz.Matrix(1, 1)).save(QA / f"{name}-{index+1:03d}.png")
            reports.append({"source": str(source.relative_to(ROOT)), "source_sha256": digest(source), "html": str(html.relative_to(ROOT)), "html_sha256": digest(html), "pdf": str(pdf.relative_to(ROOT)), "pdf_sha256": digest(pdf), "pages": len(document), "images": len(images), "pdf_text_chars": len(text)})
        version = browser.version
        browser.close()
    (OUT / "RENDER.json").write_text(json.dumps({"renderer": "Chromium/Chrome " + version, "network": "offline; remote resource requests blocked", "documents": reports}, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(reports, indent=2))


if __name__ == "__main__":
    main()
