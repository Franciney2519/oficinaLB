"""Gera MANUAL.pdf a partir de MANUAL.md usando fpdf2."""
import os
import re
from fpdf import FPDF

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MANUAL_MD  = os.path.join(BASE_DIR, "MANUAL.md")
MANUAL_PDF = os.path.join(BASE_DIR, "MANUAL.pdf")

DARK_BLUE  = (26, 55, 102)
YELLOW     = (244, 195, 28)
LIGHT_GRAY = (240, 240, 240)
MID_GRAY   = (180, 180, 180)
TEXT_COLOR = (40, 40, 40)


def safe(text: str) -> str:
    replacements = {
        "—": "-", "–": "-", "’": "'", "‘": "'",
        "“": '"', "”": '"', "•": "*", "ã": "a",
        "é": "e", "ê": "e", "à": "a", "á": "a",
        "â": "a", "í": "i", "ó": "o", "ô": "o",
        "ú": "u", "ü": "u", "ç": "c", "õ": "o",
        "Ã": "A", "É": "E", "Ê": "E", "Á": "A",
        "Â": "A", "Í": "I", "Ó": "O", "Ô": "O",
        "Ú": "U", "Ü": "U", "Ç": "C", "Õ": "O",
        "ª": "a", "º": "o",
    }
    for orig, repl in replacements.items():
        text = text.replace(orig, repl)
    return text.encode("latin-1", errors="replace").decode("latin-1")


class ManualPDF(FPDF):
    def header(self):
        self.set_fill_color(*YELLOW)
        self.rect(0, 0, 210, 10, "F")
        self.set_fill_color(*DARK_BLUE)
        self.rect(0, 10, 210, 4, "F")
        self.set_xy(10, 2)
        self.set_font("Arial", "B", 11)
        self.set_text_color(255, 255, 255)
        self.cell(0, 6, safe("LB AUTOCAR — Manual de Uso"), ln=0, align="L")
        self.ln(18)

    def footer(self):
        self.set_y(-12)
        self.set_fill_color(*DARK_BLUE)
        self.rect(0, self.get_y(), 210, 12, "F")
        self.set_font("Arial", "", 8)
        self.set_text_color(200, 200, 200)
        self.cell(0, 8, f"Pagina {self.page_no()}", align="C")


def render_manual(pdf: ManualPDF, lines: list[str]):
    in_table = False
    table_rows: list[list[str]] = []

    def flush_table():
        nonlocal in_table, table_rows
        if not table_rows:
            in_table = False
            return
        # Cabeçalho da tabela
        header = table_rows[0]
        col_w = (pdf.w - 20) / len(header)
        pdf.set_fill_color(*DARK_BLUE)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Arial", "B", 9)
        for cell in header:
            pdf.cell(col_w, 7, safe(cell.strip()), border=1, align="C", fill=True)
        pdf.ln()
        pdf.set_text_color(*TEXT_COLOR)
        pdf.set_font("Arial", "", 9)
        for idx, row in enumerate(table_rows[2:], 0):  # pula separador
            fill = idx % 2 == 0
            pdf.set_fill_color(*LIGHT_GRAY) if fill else pdf.set_fill_color(255, 255, 255)
            for cell in row:
                pdf.cell(col_w, 6, safe(cell.strip()), border=1, fill=fill)
            pdf.ln()
        pdf.ln(3)
        in_table = False
        table_rows.clear()

    i = 0
    while i < len(lines):
        line = lines[i].rstrip()

        # Tabela markdown
        if "|" in line and line.strip().startswith("|"):
            in_table = True
            cells = [c for c in line.strip().split("|") if c != ""]
            table_rows.append(cells)
            i += 1
            continue
        elif in_table:
            flush_table()

        # H1
        if line.startswith("# "):
            text = line[2:].strip()
            pdf.set_fill_color(*DARK_BLUE)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Arial", "B", 16)
            pdf.cell(0, 10, safe(text), ln=1, fill=True, align="C")
            pdf.ln(4)

        # H2
        elif line.startswith("## "):
            text = line[3:].strip()
            pdf.set_fill_color(*YELLOW)
            pdf.set_text_color(*DARK_BLUE)
            pdf.set_font("Arial", "B", 13)
            pdf.cell(0, 8, safe(text), ln=1, fill=True)
            pdf.ln(2)

        # H3
        elif line.startswith("### "):
            text = line[4:].strip()
            pdf.set_text_color(*DARK_BLUE)
            pdf.set_font("Arial", "B", 11)
            pdf.set_draw_color(*MID_GRAY)
            pdf.cell(0, 7, safe(text), ln=1, border="B")
            pdf.ln(1)

        # Separador ---
        elif re.match(r"^-{3,}$", line.strip()):
            pdf.set_draw_color(*MID_GRAY)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(4)

        # Blockquote >
        elif line.startswith("> "):
            text = line[2:].strip()
            pdf.set_fill_color(255, 249, 220)
            pdf.set_text_color(100, 80, 0)
            pdf.set_font("Arial", "I", 9)
            pdf.set_x(14)
            pdf.multi_cell(pdf.w - 28, 5, safe(text), fill=True, border=0)
            pdf.ln(2)

        # Item de lista -
        elif line.startswith("- ") or line.startswith("  - "):
            indent = 6 if line.startswith("  - ") else 0
            text = line.lstrip("- ").strip()
            # Remove marcação **bold** e *italic* para o PDF
            text = re.sub(r"\*\*(.*?)\*\*", r"\1", text)
            text = re.sub(r"\*(.*?)\*", r"\1", text)
            text = re.sub(r"`(.*?)`", r"\1", text)
            pdf.set_text_color(*TEXT_COLOR)
            pdf.set_font("Arial", "", 10)
            pdf.set_x(14 + indent)
            bullet_x = 12 + indent
            pdf.set_xy(bullet_x, pdf.get_y())
            pdf.cell(4, 5, safe("•"), ln=0)
            pdf.set_x(bullet_x + 4)
            pdf.multi_cell(pdf.w - bullet_x - 14, 5, safe(text))

        # Linha vazia
        elif line.strip() == "":
            pdf.ln(2)

        # Parágrafo normal
        else:
            text = re.sub(r"\*\*(.*?)\*\*", r"\1", line)
            text = re.sub(r"\*(.*?)\*", r"\1", text)
            text = re.sub(r"`(.*?)`", r"\1", text)
            pdf.set_text_color(*TEXT_COLOR)
            pdf.set_font("Arial", "", 10)
            pdf.set_x(10)
            pdf.multi_cell(pdf.w - 20, 5, safe(text))

        i += 1

    if in_table:
        flush_table()


def main():
    with open(MANUAL_MD, encoding="utf-8") as f:
        lines = f.readlines()

    pdf = ManualPDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()
    render_manual(pdf, lines)

    pdf.output(MANUAL_PDF)
    print(f"PDF gerado: {MANUAL_PDF}")


if __name__ == "__main__":
    main()
