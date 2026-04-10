from fpdf import FPDF
from datetime import datetime
import textwrap
from typing import Dict, Any, Optional

class RavenReporter(FPDF):
    """
    R.A.V.E.N. Automated Forensic Reporting Engine
    Şimdi çok dilli destek ve gelişmiş karakter temizleme ile güncellendi.
    """
    
    def header(self):
        # Header
        self.set_font('helvetica', 'B', 16)
        self.set_text_color(180, 0, 0)  # Kurumsal Kırmızı
        self.cell(0, 10, 'R.A.V.E.N. Analysis Report', align='C', ln=True)
        
        # Timestamped sub header
        self.set_font('helvetica', 'I', 9)
        self.set_text_color(80, 80, 80)
        generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.cell(0, 5, f'Generated on: {generated_at}', align='C', ln=True)
        
        # Line
        self.set_draw_color(180, 0, 0)
        self.line(10, 30, 200, 30)
        self.ln(12)

    def footer(self):
        # Page numbers
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}} - R.A.V.E.N. Forensic Unit', align='C')

    def _sanitize_text(self, text: str) -> str:
        """Türkçe karakterleri ve emojileri latin-1 uyumlu hale getirir."""
        replacements = {
            "İ": "I", "ı": "i", "Ş": "S", "ş": "s", "Ğ": "G", "ğ": "g",
            "✅": "[CLEAN]", "🚨": "[MALICIOUS]", "⚠️": "[SUSPICIOUS]", 
            "🔍": "", "🔑": "[KEY]", "ü": "u", "Ü": "U", "ö": "o", "Ö": "O", "ç": "c", "Ç": "C"
        }
        for k, v in replacements.items():
            text = text.replace(k, v)
        return text.encode('latin-1', 'replace').decode('latin-1')

    def generate(self, data: Dict[str, Any], vt_data: Optional[Dict] = None, filename: str = "raven_report.pdf", lang: str = "tr"):
        """
        PDF yapısını dile duyarlı başlıklarla oluşturur.
        """
        # Language based tags
        labels = {
            "tr": {
                "cat": "KATEGORI",
                "artifact": "Bulgu / Kanit",
                "reputation": "Durum / Itibar",
                "score": "Skor"
            },
            "en": {
                "cat": "CATEGORY",
                "artifact": "Artifact / Finding",
                "reputation": "Reputation",
                "score": "Score"
            }
        }
        l = labels.get(lang, labels["en"])

        self.add_page()
        self.set_auto_page_break(auto=True, margin=15)
        self.alias_nb_pages()
        
        margin_left = 10
        
        for category, items in data.items():
            if not items:
                continue
            
            # Category Headers
            self.set_x(margin_left)
            self.set_font('helvetica', 'B', 12)
            self.set_fill_color(240, 240, 240)
            self.set_text_color(40, 40, 40)
            cat_label = self._sanitize_text(f"{l['cat']}: {category.upper()}")
            self.cell(190, 9, f' {cat_label}', fill=True, ln=1)
            self.ln(2)

            # Table  Headers
            self.set_font('helvetica', 'B', 10)
            self.set_fill_color(60, 60, 60)
            self.set_text_color(255, 255, 255)
            self.cell(110, 8, f' {l["artifact"]}', border=1, fill=True)
            self.cell(50, 8, f' {l["reputation"]}', border=1, fill=True)
            self.cell(30, 8, f' {l["score"]}', border=1, fill=True, ln=1)

            # Data Lines
            self.set_font('courier', '', 9)
            self.set_text_color(0, 0, 0)
            
            for item in items:
                status = "N/A"
                score = "0/0"
                
                if vt_data and category in vt_data and item in vt_data[category]:
                    raw_status = vt_data[category][item].get('status', 'N/A')
                    status = self._sanitize_text(raw_status)
                    score = vt_data[category][item].get('score', '0/0')

                # Aligning long data
                wrapper = textwrap.TextWrapper(width=50)
                lines = wrapper.wrap(text=str(item))
                
                for i, line in enumerate(lines):
                    self.set_x(margin_left)
                    is_last_line = (i == len(lines) - 1)
                    line_to_print = self._sanitize_text(line)
                    
                    # Findings Column
                    self.cell(110, 7, line_to_print, border='LR' if not is_last_line else 'LRB')
                    
                    # Status & Score
                    if i == 0:
                        # Dinamik Renklendirme
                        if any(x in status.upper() for x in ["MALICIOUS", "ZARARLI"]):
                            self.set_text_color(180, 0, 0)
                        elif any(x in status.upper() for x in ["CLEAN", "TEMIZ"]):
                            self.set_text_color(0, 120, 0)
                        
                        self.cell(50, 7, status, border=1 if len(lines) == 1 else 'LRT')
                        self.set_text_color(0, 0, 0)
                        self.cell(30, 7, score, border=1 if len(lines) == 1 else 'LRT', ln=1)
                    else:
                        self.cell(50, 7, "", border='LR' if not is_last_line else 'LRB')
                        self.cell(30, 7, "", border='LR' if not is_last_line else 'LRB', ln=1)
            
            self.ln(6)
            
        self.output(filename)
        return filename