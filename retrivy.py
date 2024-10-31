import json
import os
import logging
from datetime import datetime, timezone

# Configurazione del logging per mostrare messaggi di info e warning.
logging.basicConfig(level=logging.INFO)

def validate_directories(*directories: str) -> bool:
    """
    Verifica che tutte le directory specificate esistano.

    Args:
        *directories (str): Lista dei percorsi delle directory da verificare.

    Returns:
        bool: True se tutte le directory esistono, False se manca almeno una directory.
    """
    missing_directories = [d for d in directories if not os.path.isdir(d)]
    if missing_directories:
        for directory in missing_directories:
            logging.warning(f"Attenzione: La directory '{directory}' non esiste.")
        return False
    return True

def load_file(file_path: str) -> str:
    """
    Legge il contenuto di un file e lo restituisce come stringa.

    Args:
        file_path (str): Il percorso del file da leggere.

    Returns:
        str: Contenuto del file come stringa, o una stringa vuota se si verifica un errore.
    """
    try:
        with open(file_path, 'r') as file:
            return file.read()
    except FileNotFoundError:
        logging.error(f"Errore: Il file '{file_path}' non è stato trovato.")
    except PermissionError:
        logging.error(f"Errore: Permesso negato per leggere il file '{file_path}'.")
    return ""

def format_date(iso_string: str) -> str:
    """
    Converte una stringa di data in formato ISO in un formato leggibile.

    Args:
        iso_string (str): Stringa della data in formato ISO.

    Returns:
        str: Data formattata in "YYYY-MM-DD HH:MM:SS" o un messaggio di errore se non valida.
    """
    try:
        date_time = datetime.fromisoformat(iso_string)
        return date_time.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        logging.error("Errore: Formato di data ISO non valido.")
        return "Formato data non valido"

def generate_table_rows(vulnerabilities):
    """
    Genera le righe HTML per la tabella delle vulnerabilità.

    Args:
        vulnerabilities (list): Lista dei dati delle vulnerabilità.

    Returns:
        str: Stringa HTML con le righe della tabella per ogni vulnerabilità.
    """
    return "".join([
        f"""
        <tr class="severity-{v['Severity']}">
            <td title="{v['PkgIdentifier']['PURL']}">{v['PkgName']}</td>
            <td>{v['VulnerabilityID']}</td>
            <td class="severity">{v['Severity']}</td>
            <td class="centered">{v['InstalledVersion']}</td>
            <td class="centered">{v['FixedVersion']}</td>
            <td>
                <strong>{v['Title']}</strong><br>
                <a href="{v['PrimaryURL']}">{v['PrimaryURL']}</a>
                <div onclick="toggleReferences(this)" class="show-references" style="cursor: pointer; text-decoration: underline;">
                    Show References
                </div>
                <div class="references" style="display: none;">
                    {"<br>".join(f'<a href="{link}">{link}</a>' for link in v['References'])}
                </div>
            </td>
        </tr>
        """
        for v in vulnerabilities
    ])

def generate_html_report(vulnerabilities, report_title, results_target, results_type, css_directory, js_directory, formatted_json_created_at):
    """
    Genera il contenuto HTML per il report delle vulnerabilità.

    Args:
        vulnerabilities (list): Lista delle vulnerabilità da includere nel report.
        report_title (str): Titolo del report.
        results_target (str): Sistema o software analizzato.
        results_type (str): Tipo di analisi eseguita.
        css_directory (str): Directory contenente i file CSS.
        js_directory (str): Directory contenente i file JavaScript.
        formatted_json_created_at (str): Data di creazione del JSON, in formato leggibile.

    Returns:
        str: Contenuto HTML come stringa.
    """
    severity_counts = {'UNKNOWN': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
    for v in vulnerabilities:
        if v['Severity'] in severity_counts:
            severity_counts[v['Severity']] += 1
    
    total_vulnerabilities = sum(severity_counts.values())
    summary_line = f"Total vulnerabilities: {total_vulnerabilities} (UNKNOWN: {severity_counts['UNKNOWN']}, LOW: {severity_counts['LOW']}, MEDIUM: {severity_counts['MEDIUM']}, HIGH: {severity_counts['HIGH']}, CRITICAL: {severity_counts['CRITICAL']})"

    css_code = load_file(os.path.join(css_directory, 'style.css'))
    sortable_js_code = load_file(os.path.join(js_directory, 'sortable.js'))
    toggleReferences_js_code = load_file(os.path.join(js_directory, 'toggleReferences.js'))

    rows = generate_table_rows(vulnerabilities)
    
    html_report = f"""
<!DOCTYPE html>
<html>
<head>
    <style>{css_code}</style>
    <title>{report_title}</title>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
</head>
<body>
    <h1>{report_title}</h1>
    <p><strong>JSON generated on {formatted_json_created_at}</strong></p>
    <p><strong>Target: {results_target}&emsp;&emsp;Type: {results_type}</strong></p>
    <p><strong>{summary_line}</strong></p>
    <table id="sortable-table">
        <thead>
            <tr class="sub-header">
                <th onclick="sortTable(0)">Package<span class='sort-icon'></span></th>
                <th onclick="sortTable(1)">Vulnerability ID<span class='sort-icon'></span></th>
                <th onclick="sortTable(2)">Severity<span class='sort-icon'></span></th>
                <th onclick="sortTable(3)">Version<span class='sort-icon'></span></th>
                <th onclick="sortTable(4)">Fixed Version<span class='sort-icon'></span></th>
                <th onclick="sortTable(5)">Links<span class='sort-icon'></span></th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
    <script>{toggleReferences_js_code}</script>
    <script>{sortable_js_code}</script>
</body>
</html>
    """
    return html_report

def read_json_input(file_path: str):
    """
    Legge un file JSON di input ed estrae i risultati delle vulnerabilità.

    Args:
        file_path (str): Percorso del file JSON.

    Returns:
        list: Lista di tuple, ciascuna contenente dati delle vulnerabilità, target, tipo e data di creazione.
    """
    with open(file_path, 'r') as file:
        data = json.load(file)
    
    json_created_at = data.get('CreatedAt', None)
    results_list = []
    for result in data['Results']:
        vulnerabilities = result.get('Vulnerabilities', [])
        results_target = result.get('Target', 'Unknown')
        results_type = result.get('Type', 'Unknown')
        results_list.append((vulnerabilities, results_target, results_type, json_created_at))
    
    return results_list

def main(json_file_path: str, css_directory: str, js_directory: str):
    """
    Esegue il processo di generazione del report HTML.

    Args:
        json_file_path (str): Percorso del file JSON contenente i dati delle vulnerabilità.
        css_directory (str): Directory dei file CSS.
        js_directory (str): Directory dei file JavaScript.
    """
    results_list = read_json_input(json_file_path)
    
    for index, (vulnerabilities, results_target, results_type, json_created_at) in enumerate(results_list):
        formatted_json_created_at = format_date(json_created_at)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        report_title = f"Trivy Report - {formatted_json_created_at} - {index+1}"
        output_html_filename = f"trivy_report_{timestamp}_{index+1}.html"
        output_html_path = f"./{output_html_filename}"
        
        html_report = generate_html_report(vulnerabilities, report_title, results_target, results_type, css_directory, js_directory, formatted_json_created_at)
        
        with open(output_html_path, 'w') as file:
            file.write(html_report)
        logging.info(f"Report saved to {output_html_path}")

# Percorsi dei file e directory richiesti
if __name__ == "__main__":
    css_directory = 'css/'
    js_directory = 'js/'
    json_file_path = 'results.json'

    # Controlla se le directory CSS e JS esistono prima di generare il report
    if validate_directories(css_directory, js_directory):
        main(json_file_path, css_directory, js_directory)
