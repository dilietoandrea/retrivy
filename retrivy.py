import json
import os
from datetime import datetime, timezone

def validate_directories(*directories):
    for directory in directories:
        if not os.path.isdir(directory):
            print(f"Attenzione: la directory '{directory}' non esiste.")
            return False
    return True
    
def load_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return file.read()
    except FileNotFoundError:
        print(f"Errore: Il file '{file_path}' non è stato trovato.")
    except PermissionError:
        print(f"Errore: Permesso negato per leggere il file '{file_path}'.")
    return ""
    
def format_date(iso_string: str) -> str:
    #Formatta una stringa ISO in un formato leggibile. Restituisce un messaggio di errore se la formattazione fallisce.
    if not iso_string:
        return "Formato data non valido"
    try:
        # Rimuove il suffisso 'Z' se presente, per evitare problemi di parsing
        clean_iso_string = iso_string.rstrip('Z')
        
        # Tenta di creare il datetime ignorando i microsecondi in eccesso
        if '.' in clean_iso_string:
            parts = clean_iso_string.split('.')
            seconds = parts[0]
            microseconds = parts[1][:6]  # Limita i microsecondi a 6 cifre
            clean_iso_string = f"{seconds}.{microseconds}"
        
        # Converti la stringa in un oggetto datetime
        date_time = datetime.fromisoformat(clean_iso_string)
        
        # Aggiungi il fuso orario UTC se la stringa originale terminava con 'Z'
        if iso_string.endswith('Z'):
            date_time = date_time.replace(tzinfo=timezone.utc)
        
        # Formatta la data e l'ora nel formato desiderato
        formatted_date_time = date_time.strftime("%Y-%m-%d %H:%M:%S %z")
        return formatted_date_time

    except ValueError:
        # Se non riesce a formattare, restituisci un messaggio di errore o un valore predefinito
        print("Errore: il formato della stringa ISO non è valido.")
        return "Formato data non valido"
        
def generate_table_rows(vulnerabilities):
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

def generate_html_report(vulnerabilities, report_title, results_target, results_type,css_directory, js_directory, formatted_json_created_at):
    # Calcolo del riepilogo
    severity_counts = {'UNKNOWN': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
    for v in vulnerabilities:
        if v['Severity'] in severity_counts:
            severity_counts[v['Severity']] += 1
    
    total_vulnerabilities = sum(severity_counts.values())
    summary_line = f"Total vulnerabilities: {total_vulnerabilities} (UNKNOWN: {severity_counts['UNKNOWN']}, LOW: {severity_counts['LOW']}, MEDIUM: {severity_counts['MEDIUM']}, HIGH: {severity_counts['HIGH']}, CRITICAL: {severity_counts['CRITICAL']})"

    # Carica il CSS
    css_code = load_file(os.path.join(css_directory, 'style.css'))    

    # Carica specifici file JavaScript
    sortable_js_code = load_file(os.path.join(js_directory, 'sortable.js'))
    toggleReferences_js_code = load_file(os.path.join(js_directory, 'toggleReferences.js'))

    # Generazione delle righe della tabella
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


def read_json_input(file_path):
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

def main(json_file_path, css_directory, js_directory):
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
        print(f"Report saved to {output_html_path}")

# Percorsi dei file e directory
css_directory = 'css/'
js_directory = 'js/'
json_file_path = 'results.json'
#output_html_path = 'report.html'

# Esegue lo script principale
if __name__ == "__main__":
    if validate_directories(css_directory, js_directory):
        main(json_file_path, css_directory, js_directory)
