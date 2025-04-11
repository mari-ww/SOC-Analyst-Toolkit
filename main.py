from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich.prompt import Confirm
from datetime import datetime
from utils.normalizer import main as normalize_logs
from detection.detector import run_detection
import json
import csv
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

console = Console()

def banner():
    console.print(Panel.fit(
        "[bold magenta]SOC Analyst Toolkit[/bold magenta]\n[cyan]Detecção, Análise e Resposta a Incidentes[/cyan]",
        subtitle="Feito com 🐍 Python + MITRE ATT&CK"
    ))

def visualizar_alertas():
    alerts_path = Path("alerts/alerts.json")
    if not alerts_path.exists():
        console.print("[red]Nenhum alerta encontrado. Execute a detecção primeiro.[/red]")
        return

    with open(alerts_path) as f:
        alerts = json.load(f)

    if not alerts:
        console.print("[green]Nenhum alerta detectado. Tudo limpo![/green]")
        return

    console.print("\n[bold cyan]Deseja aplicar filtros antes de visualizar os alertas?[/bold cyan]")
    if Confirm.ask("Aplicar filtros?"):

        filtro_severidade = Prompt.ask("Filtrar por severidade (low, medium, high, todas)", default="todas")
        filtro_tipo = Prompt.ask("Filtrar por tipo de evento (ex: Credential Access, todas)", default="todas")
        filtro_data = Prompt.ask("Filtrar por data mínima (YYYY-MM-DD ou todas)", default="todas")

        def filtrar(alert):
            if filtro_severidade != "todas" and alert["severity"] != filtro_severidade:
                return False
            if filtro_tipo != "todas" and filtro_tipo.lower() not in alert["event_type"].lower():
                return False
            if filtro_data != "todas":
                try:
                    data_limite = datetime.fromisoformat(filtro_data)
                    data_alerta = datetime.fromisoformat(alert["timestamp"])
                    if data_alerta < data_limite:
                        return False
                except ValueError:
                    console.print("[yellow]Formato de data inválido. Ignorando filtro de data.[/yellow]")
            return True

        alerts = list(filter(filtrar, alerts))

    if not alerts:
        console.print("[yellow]Nenhum alerta corresponde aos filtros selecionados.[/yellow]")
        return

    table = Table(title="Alertas de Segurança Detectados (Filtrados)" if Confirm else "Todos os Alertas")
    table.add_column("Data/Hora", style="cyan", no_wrap=True)
    table.add_column("Evento")
    table.add_column("Severidade", style="red")
    table.add_column("MITRE ID", style="yellow")

    for alert in alerts:
        table.add_row(
            alert["timestamp"],
            alert["event_type"],
            alert["severity"].capitalize(),
            alert["rule_id"]
        )

    console.print(table)

def exportar_csv():
    alerts_path = Path("alerts/alerts.json")
    if not alerts_path.exists():
        console.print("[red]Nenhum alerta encontrado para exportar.[/red]")
        return

    with open(alerts_path) as f:
        alerts = json.load(f)

    if not alerts:
        console.print("[yellow]Não há alertas para exportar.[/yellow]")
        return

    csv_path = Path("alerts/alerts.csv")
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "event_type", "rule_id", "description", "severity"])
        for alert in alerts:
            writer.writerow([
                alert["timestamp"],
                alert["event_type"],
                alert["rule_id"],
                alert["description"],
                alert["severity"]
            ])

    console.print(f"[green]CSV exportado para {csv_path}[/green]")

def menu():
    while True:
        banner()
        console.print("\n[bold]Escolha uma opção:[/bold]")
        console.print("1. 📥 Normalizar logs")
        console.print("2. 🕵️‍♀️ Rodar detecção")
        console.print("3. 📄 Visualizar alertas")
        console.print("4. 📤 Exportar alertas em CSV")
        console.print("5. 🧾 Exportar alertas como HTML")
        console.print("6. 🚪 Sair")

        choice = Prompt.ask("\nDigite o número da opção", choices=["1", "2", "3", "4", "5", "6"])

        if choice == "1":
            normalize_logs()
        elif choice == "2":
            run_detection()
        elif choice == "3":
            visualizar_alertas()
        elif choice == "4":
            exportar_csv()
        elif choice == "5":
            exportar_html()
        elif choice == "6":
            console.print("\n[bold red]Saindo... Até logo![/bold red]")
            break

def exportar_html():
    alerts_path = Path("alerts/alerts.json")
    if not alerts_path.exists():
        console.print("[red]Nenhum alerta encontrado. Execute a detecção primeiro.[/red]")
        return

    with open(alerts_path) as f:
        alertas = json.load(f)

    if not alertas:
        console.print("[yellow]Nenhum alerta encontrado.[/yellow]")
        return

    env = Environment(loader=FileSystemLoader('templates'))
    template = env.get_template('report_template.html')

    output = template.render(alertas=alertas, data_geracao=datetime.now().strftime('%Y-%m-%d %H:%M'))

    Path("exports").mkdir(exist_ok=True)
    output_path = Path("exports/alertas.html")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(output)

    console.print(f"[green]Relatório exportado para:[/green] {output_path}")

if __name__ == "__main__":
    menu()