from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from xml.sax.saxutils import escape
from zipfile import ZIP_DEFLATED, ZipFile

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


@dataclass(frozen=True, slots=True)
class ExportCell:
    value: str | int | float | bool | None
    style: int = 0


def _column_name(index: int) -> str:
    result = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        result = chr(65 + remainder) + result
    return result


def _xlsx_cell(reference: str, value: object, style: int = 0) -> str:
    style_attr = f' s="{style}"' if style else ""
    if value is None:
        return f'<c r="{reference}"{style_attr}/>'
    if isinstance(value, bool):
        return f'<c r="{reference}" t="b"{style_attr}><v>{1 if value else 0}</v></c>'
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f'<c r="{reference}"{style_attr}><v>{value}</v></c>'
    text = escape(str(value), {'"': '&quot;'})
    preserve = ' xml:space="preserve"' if text[:1].isspace() or text[-1:].isspace() else ""
    return (
        f'<c r="{reference}" t="inlineStr"{style_attr}>'
        f'<is><t{preserve}>{text}</t></is></c>'
    )


def _worksheet_xml(headers: Sequence[str], rows: list[list[object | ExportCell]]) -> str:
    widths: list[float] = []
    for column, header in enumerate(headers):
        maximum = len(str(header))
        for row in rows[:5000]:
            if column >= len(row):
                continue
            cell = row[column]
            raw = cell.value if isinstance(cell, ExportCell) else cell
            if raw is not None:
                maximum = max(maximum, min(len(str(raw)), 60))
        widths.append(float(max(10, min(maximum + 2, 42))))

    xml_rows: list[str] = []
    header_cells = "".join(
        _xlsx_cell(f"{_column_name(index)}1", value, 1)
        for index, value in enumerate(headers, start=1)
    )
    xml_rows.append(f'<row r="1" ht="23" customHeight="1">{header_cells}</row>')
    for row_index, row in enumerate(rows, start=2):
        cells: list[str] = []
        for column_index, item in enumerate(row, start=1):
            if isinstance(item, ExportCell):
                value, style = item.value, item.style
            else:
                value, style = item, 0
            cells.append(_xlsx_cell(f"{_column_name(column_index)}{row_index}", value, style))
        xml_rows.append(f'<row r="{row_index}">{"".join(cells)}</row>')

    columns_xml = "".join(
        f'<col min="{index}" max="{index}" width="{width}" customWidth="1"/>'
        for index, width in enumerate(widths, start=1)
    )
    last_column = _column_name(max(1, len(headers)))
    last_row = max(1, len(rows) + 1)
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">\n'
        '  <sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" '
        'activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>\n'
        f'  <cols>{columns_xml}</cols>\n'
        f'  <sheetData>{"".join(xml_rows)}</sheetData>\n'
        f'  <autoFilter ref="A1:{last_column}{last_row}"/>\n'
        '</worksheet>'
    )


def xlsx_sheets_bytes(
    sheets: Sequence[tuple[str, Sequence[str], Iterable[Sequence[object | ExportCell]]]],
) -> bytes:
    """Build a compact XLSX workbook with one or more tabular sheets."""
    if not sheets:
        raise ValueError("Нужен хотя бы один лист XLSX")

    payloads: list[tuple[str, str]] = []
    for name, headers, rows in sheets:
        materialized = [list(row) for row in rows]
        safe_name = escape(name[:31], {'"': '&quot;'})
        payloads.append((safe_name, _worksheet_xml(headers, materialized)))

    workbook_sheets = "".join(
        f'<sheet name="{name}" sheetId="{index}" r:id="rId{index}"/>'
        for index, (name, _xml) in enumerate(payloads, start=1)
    )
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">\n'
        f'  <sheets>{workbook_sheets}</sheets>\n'
        '</workbook>'
    )
    styles = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><color rgb="FFFFFFFF"/><sz val="11"/><name val="Calibri"/></font></fonts>
  <fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF2563EB"/><bgColor indexed="64"/></patternFill></fill></fills>
  <borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/></cellXfs>
  <cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>'''
    content_overrides = "".join(
        f'<Override PartName="/xl/worksheets/sheet{index}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        for index in range(1, len(payloads) + 1)
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">\n'
        '  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>\n'
        '  <Default Extension="xml" ContentType="application/xml"/>\n'
        '  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>\n'
        f'  {content_overrides}\n'
        '  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>\n'
        '</Types>'
    )
    root_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>'''
    relationships = "".join(
        f'<Relationship Id="rId{index}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{index}.xml"/>'
        for index in range(1, len(payloads) + 1)
    )
    styles_id = len(payloads) + 1
    workbook_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
        f'  {relationships}\n'
        f'  <Relationship Id="rId{styles_id}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>\n'
        '</Relationships>'
    )
    output = BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", root_rels)
        archive.writestr("xl/workbook.xml", workbook)
        archive.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        archive.writestr("xl/styles.xml", styles)
        for index, (_name, xml) in enumerate(payloads, start=1):
            archive.writestr(f"xl/worksheets/sheet{index}.xml", xml)
    return output.getvalue()


def xlsx_bytes(
    sheet_name: str,
    headers: Sequence[str],
    rows: Iterable[Sequence[object | ExportCell]],
) -> bytes:
    return xlsx_sheets_bytes(((sheet_name, headers, rows),))


def _register_pdf_font() -> str:
    font_path = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
    if not font_path.exists():
        raise RuntimeError("Для PDF-экспорта не найден системный шрифт DejaVu Sans")
    name = "MonitoringDejaVu"
    if name not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont(name, str(font_path)))
    return name


def availability_pdf_bytes(
    *,
    period_label: str,
    site_label: str,
    kind_label: str,
    site_rows: Sequence[object],
    target_rows: Sequence[object],
    kind_labels: dict[str, str] | None = None,
) -> bytes:
    font = _register_pdf_font()
    output = BytesIO()
    document = SimpleDocTemplate(
        output,
        pagesize=A4,
        leftMargin=5 * mm,
        rightMargin=5 * mm,
        topMargin=6 * mm,
        bottomMargin=6 * mm,
        title="Мониторинг Maxval - отчёт доступности",
        author="Мониторинг Maxval",
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "MonitoringTitle",
        parent=styles["Title"],
        fontName=font,
        fontSize=17,
        leading=20,
        alignment=TA_LEFT,
        spaceAfter=6,
    )
    section_style = ParagraphStyle(
        "MonitoringSection",
        parent=styles["Heading2"],
        fontName=font,
        fontSize=11,
        leading=14,
        spaceAfter=5,
    )
    body_style = ParagraphStyle(
        "MonitoringBody",
        parent=styles["BodyText"],
        fontName=font,
        fontSize=8.5,
        leading=11,
    )
    small_style = ParagraphStyle(
        "MonitoringSmall",
        parent=body_style,
        fontSize=7.5,
        leading=9.5,
    )
    story: list[object] = [
        Paragraph("Мониторинг Maxval - отчёт доступности", title_style),
        Paragraph(
            f"Период: {escape(period_label)} | Площадка: {escape(site_label)} | "
            f"Тип объекта: {escape(kind_label)}",
            body_style,
        ),
        Paragraph(
            "Нерабочие часы площадок не участвуют в расчёте доступности. "
            f"Сформировано: {datetime.now(UTC).strftime('%d.%m.%Y %H:%M UTC')}",
            body_style,
        ),
        Spacer(1, 5 * mm),
        Paragraph("Сводка по площадкам", section_style),
    ]

    def availability_text(value: float | None) -> str:
        return f"{value:.2f}%" if value is not None else "Нет данных"

    site_data = [["Площадка", "Успешно", "Ошибки", "Нет данных", "Доступность"]]
    for row in site_rows:
        site_data.append(
            [
                Paragraph(escape(str(row.site_name)), small_style),
                str(row.up_count),
                str(row.down_count),
                str(row.unknown_count),
                availability_text(row.availability),
            ]
        )
    if len(site_data) == 1:
        site_data.append(["Нет данных", "", "", "", ""])
    site_table = Table(
        site_data,
        colWidths=[78 * mm, 27 * mm, 27 * mm, 31 * mm, 37 * mm],
        repeatRows=1,
    )
    site_table.setStyle(_pdf_table_style(font))
    story.extend([site_table, Spacer(1, 6 * mm), Paragraph("Объекты", section_style)])

    target_data = [
        ["Площадка", "Объект", "Тип", "Успешно", "Ошибки", "Нет данных", "Доступность"]
    ]
    for row in target_rows:
        target_data.append(
            [
                Paragraph(escape(str(row.site_name)), small_style),
                Paragraph(escape(str(row.target_name)), small_style),
                Paragraph(escape(str((kind_labels or {}).get(row.kind, row.kind))), small_style),
                str(row.up_count),
                str(row.down_count),
                str(row.unknown_count),
                availability_text(row.availability),
            ]
        )
    if len(target_data) == 1:
        target_data.append(["Нет данных", "", "", "", "", "", ""])
    target_table = Table(
        target_data,
        colWidths=[31 * mm, 52 * mm, 24 * mm, 20 * mm, 20 * mm, 23 * mm, 30 * mm],
        repeatRows=1,
    )
    target_table.setStyle(_pdf_table_style(font))
    story.append(target_table)
    document.build(story)
    return output.getvalue()


def _pdf_table_style(font: str) -> TableStyle:
    return TableStyle(
        [
            ("FONTNAME", (0, 0), (-1, -1), font),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("LEADING", (0, 0), (-1, -1), 9.5),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2563EB")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#DCE2E8")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]
    )
