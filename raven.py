import argparse
import sys
import os
import time
from pathlib import Path
from datetime import datetime
from typing import Optional

# R.A.V.E.N. Core Modules
from core.base import IOCExtractor
from core.filter import DataFilter
from core.threat_intel import ThreatIntelProvider, silent_cache_cleanup 
from core.reporter import RavenReporter

# UI & UX Libraries (Rich)
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.align import Align
from rich import box
from rich.text import Text


__version__ = "1.0.0"
__author__ = "0xmet"

console = Console()


TEXTS = {
    "tr": {
        "file_ask": "Analiz edilecek dosya yolunu girin",
        "vt_ask": "VirusTotal sorgusu yapılsın mı?",
        "vt_warn": "[bold yellow]BİLGİ:[/bold yellow] API limitleri nedeniyle gecikme olabilir.",
        "loading": "[bold red]Veriler işleniyor...[/bold red]",
        "filter": "Süzgeç Devrede: Veriler temizleniyor...",
        "pdf_ask": "Analiz sonuçlarını PDF raporu olarak kaydetmek ister misiniz?",
        "done": "Analiz Tamamlandı!",
        "restart": "[bold cyan]Yeni bir analiz başlatmak istiyor musunuz?[/bold cyan]",
        "exit_msg": "\n[bold red]R.A.V.E.N. Gözlerini Kapatıyor... İyi avlar![/bold red]",
        "vt_not_found": "[bold yellow][!] VirusTotal API Anahtarı Bulunamadı.[/bold yellow]",
        "api_ask": "[bold cyan]Lütfen API Anahtarınızı girin[/bold cyan]",
        "api_success": "[bold green]✅ API Anahtarı başarıyla kaydedildi![/bold green]",
        "artifact": "Bulgu / Kanıt",
        "reputation": "Durum / İtibar",
        "score": "Skor",
        "malicious": "ZARARLI",
        "clean": "TEMİZ",
        "suspicious": "ŞÜPHELİ",
        "hash_alias": "HASH / DOSYA ANALİZİ"
    },
    "en": {
        "file_ask": "Enter the file path for analysis",
        "vt_ask": "Perform VirusTotal lookup?",
        "vt_warn": "[bold yellow]INFO:[/bold yellow] Delays expected due to API limits.",
        "loading": "[bold red]Processing data...[/bold red]",
        "filter": "Filter Active: Cleaning data...",
        "pdf_ask": "Do you want to save results as a PDF report?",
        "done": "Analysis Complete!",
        "restart": "Do you want to start a new analysis?",
        "exit_msg": "\n[bold red]R.A.V.E.N. Closing its eyes... Happy hunting![/bold red]",
        "vt_not_found": "[bold yellow][!] VirusTotal API Key Not Found.[/bold yellow]",
        "api_ask": "[bold cyan]Please enter your API Key[/bold cyan]",
        "api_success": "[bold green]✅ API Key saved successfully![/bold green]",
        "artifact": "Artifact / Finding",
        "reputation": "Reputation",
        "score": "Score",
        "malicious": "MALICIOUS",
        "clean": "CLEAN",
        "suspicious": "SUSPICIOUS",
        "hash_alias": "HASH / FILE ANALYSIS"
    }
}

def show_logo():
    logo = r"""
                  .¬%S$$Si•
             .:iI$S$Sª°¨
       .——  .:i$S$ª`  .
    .:d$S$$Si' -:i$ª`  .
   .:d$S'`° S:.:?`   .
  .:iIS$k¬d7 j'     .
 :i:-:i?$Si:-:¬,,.._
 i?:--::'°::.`°:;iI$Si%¬,..
 i:--:: -:-  -, -    ¨¨~^^¨¨
 :--:: -  - . .° -:-:-
 :--:i-  . .°  , d`?
 :iSi: - , , 'j ,° .
 ?::?i j' ?.'j' -:.
 ,op:- `?  • \ °  `.
 S7ji:  ` .  \ - -  .
 7j?ji:   -:- -  ::--
    """
    # Logo
    console.print(Align.center(f"[bold red]{logo}[/bold red]"))
    
    # Header/Version Panel
    version_text = Text.assemble(
        ("R.A.V.E.N. ", "bold red"),
        (f"v{__version__}", "bold white"),
        (" | ", "dim"),
        (f"Dev: {__author__}", "italic cyan")
    )
    
    console.print(Align.center(Panel(
        version_text,
        subtitle="[dim]Response Analysis & Verification Engine for Networks[/dim]",
        border_style="red",
        box=box.ROUNDED,
        width=60
    )))
    console.print("\n")

def run_analysis(lang: str, vt_obj: Optional[ThreatIntelProvider] = None):
    t = TEXTS[lang]
    
    file_input = Prompt.ask(f"\n[bold red]{t['file_ask']}[/bold red]").strip().replace('"', '')
    p = Path(file_input)
    if not p.exists():
        console.print(f"[bold red]❌ {file_input} Not Found / Bulunamadı![/bold red]")
        return

    use_vt = Confirm.ask(f"\n[bold red]{t['vt_ask']}[/bold red]", default=True)
    
    # API Key Control
    if use_vt and vt_obj and not vt_obj.api_key:
        console.print(f"\n{t['vt_not_found']}")
        user_key = Prompt.ask(t['api_ask']).strip()
        
        if len(user_key) > 10:
            try:
                os.makedirs("core", exist_ok=True)
                with open("core/api_key.txt", "w", encoding="utf-8") as f:
                    f.write(user_key)
                vt_obj.api_key = user_key
                console.print(f"{t['api_success']}\n")
            except Exception as e:
                console.print(f"[bold red]❌ Save Error: {e}[/bold red]")
                use_vt = False
        else:
            console.print("[bold red]❌ Invalid Key! Skipping Intel lookups.[/bold red]")
            use_vt = False

    extractor = IOCExtractor(str(p.absolute()))
    raw_results = extractor.extract()
    
    data_filter = DataFilter()
    console.print(f"\n[bold yellow]{t['filter']}[/bold yellow]")
    
    cleaned_results = {}
    for cat, items in raw_results.items():
        if items:
            cleaned_results[cat] = data_filter.clean(cat, items)

    vt_results_for_report = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30),
        transient=True,
    ) as progress:
        
        main_task = progress.add_task(description=t["loading"], total=len(cleaned_results))

        for cat, items in cleaned_results.items():
            if not items: 
                progress.update(main_task, advance=1)
                continue
            
            display_cat = t["hash_alias"] if any(x in cat.lower() for x in ["hash", "file"]) else cat.replace("_", " ").upper()
            
            vt_results_for_report[cat] = {}
            table = Table(title=f"🔍 {display_cat}", box=box.ROUNDED, border_style="bright_red")
            table.add_column("#", justify="center", style="dim")
            table.add_column(t["artifact"], style="bright_white", overflow="fold")
            
            is_intel_type = any(x in cat.lower() for x in ['ip', 'domain', 'hash', 'file', 'url'])
            
            if is_intel_type and use_vt and vt_obj and vt_obj.api_key:
                table.add_column(t["reputation"])
                table.add_column(t["score"], justify="right")

            for i, item in enumerate(items, 1):
                if is_intel_type and use_vt and vt_obj and vt_obj.api_key:
                    v_res = vt_obj.check(item)
                    raw_status = v_res.get('status', 'N/A').upper()
                    
                    if lang == "tr":
                        status_text = raw_status.replace("MALICIOUS", t["malicious"]).replace("CLEAN", t["clean"]).replace("SUSPICIOUS", t["suspicious"])
                    else:
                        status_text = raw_status

                    vt_results_for_report[cat][item] = {"status": status_text, "score": v_res.get('score', '0/0')}
                    
                    status_color = "bold red" if any(x in status_text.upper() for x in ["MALICIOUS", "ZARARLI"]) else "bold green"
                    table.add_row(str(i), str(item), f"[{status_color}]{status_text}[/{status_color}]", v_res.get('score', '0/0'))
                else:
                    table.add_row(str(i), str(item))
            
            progress.console.print(table)
            progress.update(main_task, advance=1)

    if Confirm.ask(f"\n[bold cyan]{t['pdf_ask']}[/bold cyan]"):
        os.makedirs("reports", exist_ok=True)
        report_filename = f"RAVEN_Report_{datetime.now().strftime('%d%m_%H%M')}.pdf"
        report_path = os.path.join("reports", report_filename)
        
        try:
            reporter = RavenReporter() 
            reporter.generate(cleaned_results, vt_data=vt_results_for_report, filename=report_path, lang=lang)
            console.print(f"[bold green]✅ OK: {report_path}[/bold green]")
        except Exception as e:
            console.print(f"[bold red]❌ Reporting Error: {e}[/bold red]")

    console.print(Panel(t["done"], style="bold green", box=box.DOUBLE, title="R.A.V.E.N."))

if __name__ == "__main__":
    try:
        silent_cache_cleanup("core/vt_cache.json", expiry_days=3)
    except:
        pass 

    vt_provider = ThreatIntelProvider()

    try:
        os.system('cls' if os.name == 'nt' else 'clear')
        show_logo()
        lang = Prompt.ask("Select Language / Dil Seçin", choices=["en", "tr"], default="tr")
        
        while True:
            run_analysis(lang, vt_provider)
            if not Confirm.ask(f"\n{TEXTS[lang]['restart']}"):
                console.print(TEXTS[lang]["exit_msg"])
                break
            os.system('cls' if os.name == 'nt' else 'clear')
            show_logo()

    except KeyboardInterrupt:
        console.print(f"\n[bold red]Terminated / Kapatılıyor...[/bold red]")
        sys.exit(0)