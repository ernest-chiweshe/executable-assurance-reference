"""Polished output: a real .docx, and a print-ready page for PDF.

Written against the stdlib on purpose. A `.docx` is a zip of XML, so producing
one needs no dependency, and a print stylesheet turns the browser's own "Save
as PDF" into a properly typeset document on every machine a clinician owns.
Adding two rendering libraries to a production image to achieve the same thing
would be a worse trade.

Both outputs carry the same rule: an unsigned document is watermarked DRAFT on
every page. A draft that can be printed to look final is how an unreviewed note
ends up in a patient's file.
"""
from __future__ import annotations

import html
import zipfile
from io import BytesIO
from xml.sax.saxutils import escape

from factory.health_ui import documents as doc_mod
from factory.health_ui import sketches as sketch_mod

_CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Default Extension="png" ContentType="image/png"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
</Types>"""

_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""

def _doc_rels(image_count: int) -> str:
    images = "".join(
        '<Relationship Id="rId{rid}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/'
        'relationships/image" Target="media/sketch-{number}.png"/>'
        .format(rid=number + 1, number=number)
        for number in range(1, image_count + 1)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/'
        'officeDocument/2006/relationships/styles" Target="styles.xml"/>'
        f'{images}</Relationships>'
    )

_STYLES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:docDefaults><w:rPrDefault><w:rPr>
<w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="22"/>
</w:rPr></w:rPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:pPr>
<w:spacing w:after="160"/></w:pPr><w:rPr><w:b/><w:sz w:val="40"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/>
<w:pPr><w:spacing w:before="280" w:after="120"/><w:outlineLvl w:val="0"/></w:pPr>
<w:rPr><w:b/><w:sz w:val="26"/><w:color w:val="0B6B63"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Meta"><w:name w:val="Meta"/>
<w:rPr><w:sz w:val="18"/><w:color w:val="5B7183"/></w:rPr></w:style>
</w:styles>"""


def runs(section: doc_mod.DocSection) -> list[str]:
    """A section's lines as PARAGRAPHS, the way a report is written.

    Consecutive lines known the same way and written by the same author join
    into one paragraph. Not a word is added, changed or reordered — only the
    line breaks between them go. A document that prints one quoted line per
    paragraph reads as a transcript filed under headings, and a clinician
    hands that to nobody.
    """

    out: list[str] = []
    current: list[str] = []
    key: tuple[str, str, str] | None = None
    for para in section.paragraphs:
        # The source is part of the key: a witness statement and a custody
        # record are both documentary, and running them into one paragraph
        # would read as a single account when they are two.
        origin_source = para.citations[0].source_id if para.citations else ""
        this = (para.origin, para.evidence_class, origin_source)
        if key is not None and this != key and current:
            out.append(" ".join(current))
            current = []
        key = this
        current.append(para.text)
    if current:
        out.append(" ".join(current))
    return out


def _p(text: str, style: str | None = None, italic: bool = False) -> str:
    ppr = f'<w:pPr><w:pStyle w:val="{style}"/></w:pPr>' if style else ""
    rpr = "<w:rPr><w:i/></w:rPr>" if italic else ""
    return (f"<w:p>{ppr}<w:r>{rpr}"
            f'<w:t xml:space="preserve">{escape(text)}</w:t></w:r></w:p>')


def _drawing(relationship_id: int, width: int, height: int) -> str:
    """A bounded inline PNG drawing for WordprocessingML."""

    max_width = 5_850_000  # roughly 6.4 inches, within the A4 text area
    cx = max_width
    cy = max(1, int(cx * height / width))
    max_height = 4_500_000
    if cy > max_height:
        cx = max(1, int(cx * max_height / cy))
        cy = max_height
    return f"""<w:p><w:r><w:drawing>
<wp:inline xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing">
<wp:extent cx="{cx}" cy="{cy}"/><wp:docPr id="{relationship_id}" name="Clinician sketch"/>
<a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
<a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">
<pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">
<pic:nvPicPr><pic:cNvPr id="0" name="Clinician sketch"/><pic:cNvPicPr/></pic:nvPicPr>
<pic:blipFill><a:blip xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" r:embed="rId{relationship_id}"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>
<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>
</pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>"""


def docx_bytes(doc: doc_mod.Document) -> bytes:
    """A real Word document. Unsigned drafts say so at the top of the file."""

    body: list[str] = []
    sketch_sources = [source for source in doc.sources if source.sketch is not None]
    if doc.status != doc_mod.SIGNED:
        body.append(_p("DRAFT — NOT SIGNED — NOT FOR CLINICAL OR LEGAL USE",
                       style="Title"))
    body.append(_p(doc.title or doc.template_name, style="Title"))

    meta = []
    if doc.case_ref:
        meta.append(f"Case reference: {doc.case_ref}")
    if doc.subject_ref:
        meta.append(f"Subject: {doc.subject_ref}")
    meta.append(f"Prepared: {doc.created_utc}")
    if doc.signed_by:
        meta.append(f"Signed by: {doc.signed_by} at {doc.signed_utc}")
        if doc.frozen_export_digest_version == 3:
            meta.append(f"Record digest: {doc.frozen_export_digest}")
            meta.append(f"Content digest: {doc.frozen_digest}")
        elif doc.frozen_export_digest:
            meta.append(
                "Record digest (legacy v2; displayed content digest not bound): "
                f"{doc.frozen_export_digest}"
            )
            meta.append(
                "Content digest (legacy v2; not covered by record digest): "
                f"{doc.frozen_digest}"
            )
        else:
            meta.append(
                "Content digest (legacy; export metadata not bound): "
                f"{doc.frozen_digest}"
            )
    for line in meta:
        body.append(_p(line, style="Meta"))

    # A document that already carries its own evidence index must not have a
    # second list appended below it.
    if doc.sources and not any(s.index for s in doc.sections):
        body.append(_p("Sources reviewed", style="Heading1"))
        for i, src in enumerate(doc.sources, 1):
            bits = [f"{i}. [{src.kind_label}] {src.title}"]
            if src.author:
                bits.append(f"— {src.author}")
            if src.dated:
                bits.append(f", {src.dated}")
            body.append(_p(" ".join(bits)))

    for section in doc.sections:
        if not section.paragraphs:
            continue
        body.append(_p(section.name, style="Heading1"))
        if section.index:
            for number, para in enumerate(section.paragraphs, 1):
                body.append(_p(f"{number}. {para.text}"))
        else:
            for block in runs(section):
                body.append(_p(block))

    if sketch_sources:
        body.append(_p("Included sketches", style="Heading1"))
        for number, source in enumerate(sketch_sources, 1):
            asset = source.sketch
            assert asset is not None
            body.append(_p(source.title))
            body.append(_drawing(number + 1, asset.width, asset.height))
            caption = source.fragments[0].text if source.fragments else ""
            detail = f"{caption} — {source.author}, {source.dated}. Asset {asset.digest[:16]}."
            body.append(_p(detail, style="Meta"))

    if doc.model_receipts:
        body.append(_p("Reviewed model assistance", style="Heading1"))
        body.append(_p(
            "The clinician adopted or rewrote suggestions before signing; these "
            "receipts identify the governed runs and evidence snapshots.",
            italic=True,
        ))
        for receipt in doc.model_receipts:
            body.append(_p(
                f"Run {receipt.run_id}; lane {receipt.lane}; model {receipt.model}; "
                f"billing {receipt.billing}; calls {receipt.call_count}; "
                f"cost USD {receipt.cost_usd:.6f}; evidence "
                f"{receipt.evidence_digest}; reviewed by {receipt.reviewed_by} "
                f"at {receipt.reviewed_utc}; tokens {receipt.token_accounting}.",
                style="Meta",
            ))

    if doc.validations:
        body.append(_p("Clinician rubric validation", style="Heading1"))
        body.append(_p(
            "This records the clinician's review of visible structure. It does "
            "not grade clinical correctness, credibility, admissibility, "
            "persuasion or outcome.",
            italic=True,
        ))
        for validation in doc.validations:
            body.append(_p(
                f"{validation.rubric_id} v{validation.rubric_version}; "
                f"decision {validation.decision}; draft "
                f"{validation.document_digest}; reviewed by "
                f"{validation.reviewed_by} at {validation.reviewed_utc}.",
                style="Meta",
            ))
            for item in validation.feedback:
                detail = f" — {item.comment}" if item.comment else ""
                body.append(_p(
                    f"{item.criterion_id}: {item.outcome}{detail}"
                ))

    if doc.status != doc_mod.SIGNED:
        body.append(_p("This document is a draft and has not been signed.",
                       italic=True))

    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/'
        'wordprocessingml/2006/main"><w:body>'
        + "".join(body)
        + '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/>'
        '<w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134"/>'
        "</w:sectPr></w:body></w:document>"
    )

    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", _CONTENT_TYPES)
        zf.writestr("_rels/.rels", _RELS)
        zf.writestr("word/_rels/document.xml.rels", _doc_rels(len(sketch_sources)))
        zf.writestr("word/styles.xml", _STYLES)
        zf.writestr("word/document.xml", document)
        for number, source in enumerate(sketch_sources, 1):
            assert source.sketch is not None
            zf.writestr(
                f"word/media/sketch-{number}.png",
                sketch_mod.asset_bytes(source.sketch),
            )
    return buffer.getvalue()


def print_html(doc: doc_mod.Document) -> str:
    """A page built for the browser's own Save-as-PDF.

    Print rules matter more than screen rules here: a clinical document that
    breaks a heading across pages, or loses its draft marking on page two,
    reads as careless to the person relying on it.
    """

    def esc(text: str) -> str:
        return html.escape(text)

    draft = doc.status != doc_mod.SIGNED
    meta: list[str] = []
    if doc.case_ref:
        meta.append(f"Case reference: {esc(doc.case_ref)}")
    if doc.subject_ref:
        meta.append(f"Subject: {esc(doc.subject_ref)}")
    meta.append(f"Prepared: {esc(doc.created_utc)}")
    if doc.signed_by:
        meta.append(f"Signed by <strong>{esc(doc.signed_by)}</strong> "
                    f"at {esc(doc.signed_utc or '')}")
        if doc.frozen_export_digest_version == 3:
            meta.append(
                "Record digest <code>"
                + esc(doc.frozen_export_digest or "")
                + "</code>"
            )
            meta.append(f"Content digest <code>{esc(doc.frozen_digest or '')}</code>")
        elif doc.frozen_export_digest:
            meta.append(
                "Record digest (legacy v2; displayed content digest not bound) <code>"
                + esc(doc.frozen_export_digest)
                + "</code>"
            )
            meta.append(
                "Content digest (legacy v2; not covered by record digest) <code>"
                + esc(doc.frozen_digest or "")
                + "</code>"
            )
        else:
            meta.append(
                "Content digest (legacy; export metadata not bound) <code>"
                + esc(doc.frozen_digest or "")
                + "</code>"
            )

    sections: list[str] = []
    if doc.sources and not any(s.index for s in doc.sections):
        items = "".join(
            f"<li><span class='k'>{esc(s.kind_label)}</span> {esc(s.title)}"
            + (f" — {esc(s.author)}" if s.author else "")
            + (f", {esc(s.dated)}" if s.dated else "")
            + "</li>"
            for s in doc.sources
        )
        sections.append(f"<section><h2>Sources reviewed</h2><ol>{items}</ol></section>")

    for section in doc.sections:
        if not section.paragraphs:
            continue
        if section.index:
            paras = "<ol>" + "".join(
                f"<li>{esc(p.text)}</li>" for p in section.paragraphs) + "</ol>"
        else:
            paras = "".join(f"<p>{esc(block)}</p>" for block in runs(section))
        sections.append(
            f"<section><h2>{esc(section.name)}</h2>{paras}</section>")

    sketch_sources = [source for source in doc.sources if source.sketch is not None]
    if sketch_sources:
        figures = []
        for source in sketch_sources:
            assert source.sketch is not None
            caption = source.fragments[0].text if source.fragments else ""
            figures.append(
                "<figure>"
                f"<img src='data:image/png;base64,{source.sketch.png_base64}' "
                f"alt='{esc(caption)}'>"
                f"<figcaption>{esc(source.title)} — {esc(caption)} — "
                f"{esc(source.author)}, {esc(source.dated)}. "
                f"Asset {esc(source.sketch.digest[:16])}.</figcaption></figure>"
            )
        sections.append(
            "<section><h2>Included sketches</h2>" + "".join(figures) + "</section>"
        )

    if doc.model_receipts:
        receipts = "".join(
            "<li>Run <code>" + esc(item.run_id) + "</code>; lane "
            + esc(item.lane) + "; model " + esc(item.model) + "; billing "
            + esc(item.billing) + f"; calls {item.call_count}; cost USD "
            + f"{item.cost_usd:.6f}; evidence <code>" + esc(item.evidence_digest)
            + "</code>; reviewed by " + esc(item.reviewed_by) + " at "
            + esc(item.reviewed_utc) + "; tokens "
            + esc(item.token_accounting) + ".</li>"
            for item in doc.model_receipts
        )
        sections.append(
            "<section><h2>Reviewed model assistance</h2>"
            "<p>The clinician adopted or rewrote suggestions before signing; "
            "these receipts identify the governed runs and evidence snapshots.</p>"
            f"<ul>{receipts}</ul></section>"
        )

    if doc.validations:
        validations = []
        for validation in doc.validations:
            feedback = "".join(
                "<li><strong>" + esc(item.criterion_id) + ": "
                + esc(item.outcome) + "</strong>"
                + (" — " + esc(item.comment) if item.comment else "")
                + "</li>"
                for item in validation.feedback
            )
            validations.append(
                "<article><p><strong>" + esc(validation.rubric_id) + " v"
                + esc(validation.rubric_version) + ": "
                + esc(validation.decision) + "</strong><br>Draft <code>"
                + esc(validation.document_digest) + "</code><br>Reviewed by "
                + esc(validation.reviewed_by) + " at "
                + esc(validation.reviewed_utc) + ".</p><ul>"
                + feedback + "</ul></article>"
            )
        sections.append(
            "<section><h2>Clinician rubric validation</h2>"
            "<p>This records the clinician's review of visible structure. It "
            "does not grade clinical correctness, credibility, admissibility, "
            "persuasion or outcome.</p>" + "".join(validations) + "</section>"
        )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{esc(doc.title or doc.template_name)}</title>
<style>
  @page {{ size: A4; margin: 20mm 18mm; }}
  body {{ font: 11.5pt/1.55 Georgia, "Times New Roman", serif; color:#15242e;
          margin:0 auto; max-width:190mm; padding:14mm 0; }}
  .draft {{ border:2px solid #a3271f; color:#a3271f; padding:8px 12px;
            font:700 12pt/1.3 -apple-system,Segoe UI,sans-serif;
            letter-spacing:.06em; margin-bottom:18px; text-align:center; }}
  h1 {{ font-size:20pt; margin:0 0 6px; }}
  .meta {{ font:9.5pt/1.5 -apple-system,Segoe UI,sans-serif; color:#5b7183;
           border-bottom:1px solid #dbe4ea; padding-bottom:10px;
           margin-bottom:16px; }}
  .meta div {{ margin:1px 0; }}
  h2 {{ font:600 12pt/1.3 -apple-system,Segoe UI,sans-serif; color:#0b6b63;
        margin:16pt 0 6pt; page-break-after:avoid; }}
  section {{ page-break-inside:auto; }}
  p {{ margin:0 0 7pt; text-align:justify; orphans:3; widows:3; }}
  ol {{ margin:0; padding-left:18px; font-size:10.5pt; }}
  li {{ margin-bottom:4px; }}
  figure {{ margin:10pt 0 16pt; page-break-inside:avoid; }}
  figure img {{ display:block; max-width:100%; max-height:150mm; border:1px solid #dbe4ea; }}
  figcaption {{ margin-top:4pt; font:9pt/1.4 -apple-system,Segoe UI,sans-serif; color:#5b7183; }}
  .k {{ font:600 8.5pt -apple-system,Segoe UI,sans-serif; color:#0b6b63;
        text-transform:uppercase; letter-spacing:.05em; margin-right:5px; }}
  code {{ font-size:9pt; }}
  .foot {{ margin-top:22pt; padding-top:8pt; border-top:1px solid #dbe4ea;
           font:9pt -apple-system,Segoe UI,sans-serif; color:#5b7183; }}
  .bar {{ position:fixed; top:0; left:0; right:0; background:#0b6b63;
          color:#fff; padding:9px 16px; font:600 13px -apple-system,sans-serif;
          display:flex; gap:12px; align-items:center; }}
  .bar button {{ background:#fff; color:#0b6b63; border:0; border-radius:6px;
                 padding:6px 13px; font-weight:700; cursor:pointer; }}
  @media print {{ .bar {{ display:none; }} body {{ padding-top:0; }} }}
  @media screen {{ body {{ padding-top:56px; }} }}
</style></head><body>
<div class="bar">Print or save as PDF from your browser
  <button onclick="window.print()">Print / Save as PDF</button></div>
{'<div class="draft">DRAFT — NOT SIGNED — NOT FOR CLINICAL OR LEGAL USE</div>' if draft else ''}
<h1>{esc(doc.title or doc.template_name)}</h1>
<div class="meta">{''.join(f'<div>{m}</div>' for m in meta)}</div>
{''.join(sections)}
<div class="foot">{
  'This document is a draft and has not been signed.' if draft
  else f'Signed by {esc(doc.signed_by or "")} on {esc(doc.signed_utc or "")}.'
}</div>
</body></html>"""
