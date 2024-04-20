import os
import json
from datetime import datetime

def format_date(iso_string):
    # Converte una stringa ISO 8601 nel formato "Data - Ora - Offset di fuso orario"
    date_time = datetime.fromisoformat(iso_string)
    return date_time.strftime("%Y-%m-%d %H:%M:%S %z")

def load_js_file(js_file_path):
    with open(js_file_path, 'r') as file:
        return file.read()

def generate_html_report(vulnerabilities, report_title, results_type, js_directory, json_created_at):
    # Calcolo del riepilogo
    severity_counts = {'UNKNOWN': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
    for v in vulnerabilities:
        if v['Severity'] in severity_counts:
            severity_counts[v['Severity']] += 1
    
    total_vulnerabilities = sum(severity_counts.values())
    summary_line = f"Total vulnerabilities: {total_vulnerabilities} (UNKNOWN: {severity_counts['UNKNOWN']}, LOW: {severity_counts['LOW']}, MEDIUM: {severity_counts['MEDIUM']}, HIGH: {severity_counts['HIGH']}, CRITICAL: {severity_counts['CRITICAL']})"

    # Carica specifici file JavaScript
    sortable_js_code = load_js_file(os.path.join(js_directory, 'sortable.js'))
    toggleReferences_js_code = load_js_file(os.path.join(js_directory, 'toggleReferences.js'))

    # Generazione delle righe della tabella
    rows = "".join([
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
                <div onclick="toggleReferences(this)" style="cursor: pointer; color: blue; text-decoration: underline;">
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
    
    html_report = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>{report_title}</title>
        <script>{toggleReferences_js_code}</script>
        <script>{sortable_js_code}</script>
        <script src="sortable.js"></script>
        <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
        <style>
            * {{
                font-family: Arial, Helvetica, sans-serif;
            }}
            h1, h2 {{
                text-align: center;
            }}
            .group-header th {{
                font-size: 200%;
            }}
            .sub-header th {{
                font-size: 150%;
            }}
            table, th, td {{
                border: 1px solid black;
                border-collapse: collapse;
                white-space: nowrap;
                padding: .3em;
            }}
            table {{
                margin: 0 auto;
            }}
            .centered {{
                text-align: center; /* Allinea centralmente il contenuto della cella */
            }}
            .severity {{
                text-align: center;
                font-weight: bold;
                color: #fafafa;
            }}
            .severity-LOW .severity {{ background-color: #5fbb31; }}
            .severity-MEDIUM .severity {{ background-color: #e9c600; }}
            .severity-HIGH .severity {{ background-color: #ff8800; }}
            .severity-CRITICAL .severity {{ background-color: #e40000; }}
            .severity-UNKNOWN .severity {{ background-color: #747474; }}
            .severity-LOW {{ background-color: #5fbb3160; }}
            .severity-MEDIUM {{ background-color: #e9c60060; }}
            .severity-HIGH {{ background-color: #ff880060; }}
            .severity-CRITICAL {{ background-color: #e4000060; }}
            .severity-UNKNOWN {{ background-color: #74747460; }}
            table tr td:first-of-type {{
                font-weight: bold;
            }}
            a {{
                color: #0000EE;
                text-decoration: none;
            }}
            a:hover {{
                text-decoration: underline;
            }}
            th {{
                cursor: pointer; /* Cambia il cursore in un puntatore */
            }}
            th:hover {{
                background-color: #f2f2f2; /* Cambia lo sfondo al passaggio del mouse per maggior feedback */
            }}
            .sort-icon {{
                display: inline-block;
                margin-left: 5px;
            }}
        </style>
    </head>
    <body>
        <h1>{report_title}</h1>
        <h2>json generated on {json_created_at}</h2>
        <h2>Type: {results_type}</h2>
        <p style="text-align: center; font-size: 20px;"><strong>{summary_line}</strong></p>
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
    </body>
    </html>
    """
    
    return html_report


def read_json_input(file_path):
    # Funzione per leggere il file JSON e restituire i dati delle vulnerabilità
    with open(file_path, 'r') as file:
        data = json.load(file)
    vulnerabilities = data['Results'][0]['Vulnerabilities']
    results_type = data["Results"][0]["Type"]
    json_created_at = data['CreatedAt']
    return vulnerabilities, results_type, json_created_at

def main(json_file_path):
    # Leggi le vulnerabilità dal file JSON
    vulnerabilities, results_type, json_created_at = read_json_input(json_file_path)
    
    # Ottieni la data e l'ora correnti nel formato desiderato per il nome del file
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_html_filename = f"trivy_report_{timestamp}.html"
    output_html_path = f"./{output_html_filename}"  # Salva il file nella directory corrente
    
    formatted_json_created_at = format_date(json_created_at)
    formatted_html_created_at = format_date(datetime.now().isoformat())
    report_title = datetime.now().strftime(f"Trivy Report - {formatted_html_created_at}")
    # Genera il report HTML
    html_report = generate_html_report(vulnerabilities, report_title, results_type, js_directory, formatted_json_created_at)
    
    # Scrivi il report HTML sul file di output
    with open(output_html_path, 'w') as file:
        file.write(html_report)
    print(f"Report saved to {output_html_path}")

# Percorsi dei file e directory
js_directory = 'js/'
json_file_path = 'results.json'
#output_html_path = 'report.html'

# Esegui lo script principale
if __name__ == "__main__":
    # Sostituisci con il percorso effettivo del tuo file results.json
    json_file_path = 'results.json'
    main(json_file_path)
