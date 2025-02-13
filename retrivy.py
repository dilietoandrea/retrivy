import json
import chardet
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
    rows = []
    for v in vulnerabilities:
        pkg_name = v.get("PkgName", "Unknown Package")
        vuln_id = v.get("VulnerabilityID", "Unknown ID")
        severity = v.get("Severity", "UNKNOWN").upper()  # Assicura che sia maiuscolo
        installed_version = v.get("InstalledVersion", "Unknown Version")
        fixed_version = v.get("FixedVersion", "N/A")
        title = v.get("Title", "No description available.")
        primary_url = v.get("PrimaryURL", "#")
        references = v.get("References", [])
        purl = v.get("PURL", "N/A")

        # Mappa le classi CSS per garantire la colorazione corretta
        severity_class = f"severity-{severity}"

        # Crea la riga HTML con i riferimenti multipli
        references_html = "<br>".join(f'<a href="{link}">{link}</a>' for link in references) if references else "N/A"

        row_html = f"""
        <tr class="{severity_class}">
            <td title="{purl}">{pkg_name}</td>
            <td>{vuln_id}</td>
            <td class="severity">{severity}</td>
            <td class="centered">{installed_version}</td>
            <td class="centered">{fixed_version}</td>
            <td>
                <strong>{title}</strong><br>
                <a href="{primary_url}">{primary_url}</a>
                <div onclick="toggleReferences(this)" class="show-references" style="cursor: pointer; text-decoration: underline;">
                    Show References
                </div>
                <div class="references" style="display: none;">
                    {references_html}
                </div>
            </td>
        </tr>
        """
        rows.append(row_html)

    return "".join(rows)

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

def generate_html_section(vulnerabilities, target, analysis_type, table_index):
    """
    Genera una sezione HTML per un target specifico.

    Args:
        vulnerabilities (list): Lista delle vulnerabilità da includere nella tabella.
        target (str): Nome del target analizzato.
        analysis_type (str): Tipo di analisi eseguita.
        table_index (int): Indice univoco della tabella per garantire un ID univoco.

    Returns:
        str: Stringa HTML della sezione.
    """
    # Conta le vulnerabilità per livello di severità
    severity_levels = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    severity_counts = {level: 0 for level in severity_levels}

    for v in vulnerabilities:
        severity = v.get("Severity", "UNKNOWN").upper()
        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            severity_counts["UNKNOWN"] += 1  # Se il valore non è riconosciuto, lo considera come UNKNOWN

    # Calcola il totale delle vulnerabilità
    total_vulnerabilities = sum(severity_counts.values())

    # Genera la stringa riepilogativa
    summary_line = (
        f"Total vulnerabilities: {total_vulnerabilities} "
        f"(UNKNOWN: {severity_counts['UNKNOWN']}, LOW: {severity_counts['LOW']}, "
        f"MEDIUM: {severity_counts['MEDIUM']}, HIGH: {severity_counts['HIGH']}, "
        f"CRITICAL: {severity_counts['CRITICAL']})"
    )
    
    # Genera le righe della tabella
    rows = generate_table_rows(vulnerabilities)
    table_id = f"sortable-table-{table_index}"  # ID univoco per ogni tabella

    return f"""
    <section>
        <div style="margin-top: 60px;"></div> <!-- Spazio prima di Target -->
        <h2>Target: {target} (Type: {analysis_type})</h2>
        <p class="summary">{summary_line}</p>
        <table id="{table_id}" class="sortable-table">
            <thead>
                <tr class="sub-header">
                    <th onclick="sortTable('{table_id}', 0)">Package<span class='sort-icon'></span></th>
                    <th onclick="sortTable('{table_id}', 1)">Vulnerability ID<span class='sort-icon'></span></th>
                    <th onclick="sortTable('{table_id}', 2)">Severity<span class='sort-icon'></span></th>
                    <th onclick="sortTable('{table_id}', 3)">Version<span class='sort-icon'></span></th>
                    <th onclick="sortTable('{table_id}', 4)">Fixed Version<span class='sort-icon'></span></th>
                    <th onclick="sortTable('{table_id}', 5)">Links<span class='sort-icon'></span></th>
                </tr>
            </thead>
            <tbody>
                {rows if rows else '<tr><td colspan="6" class="centered">No vulnerabilities found</td></tr>'}
            </tbody>
        </table>
    </section>
    """


def generate_full_html_report(sections, report_title, css_directory, js_directory, formatted_json_created_at):
    """
    Genera l'intero report HTML includendo tutte le sezioni.
    """
    css_code = load_file(os.path.join(css_directory, 'style.css'))
    sortable_js_code = load_file(os.path.join(js_directory, 'sortable.js'))
    toggleReferences_js_code = load_file(os.path.join(js_directory, 'toggleReferences.js'))

    sections_html = "".join(sections)

    return f"""
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
        {sections_html}
        <script>{toggleReferences_js_code}</script>
        <script>{sortable_js_code}</script>
    </body>
    </html>
    """

def parse_trivy_json(data):
    """
    Parsea un file JSON di Trivy per estrarre le vulnerabilità in un formato uniforme.

    Args:
        data (dict): Contenuto JSON del report Trivy.

    Returns:
        list: Lista di tuple (vulnerabilities, target, type, creation_date).
    """
    json_created_at = data.get('CreatedAt', None)
    results_list = []

    for result in data.get('Results', []):
        vulnerabilities = []

        for vuln in result.get('Vulnerabilities', []):
            vuln_data = {
                "PkgName": vuln.get("PkgName", "Unknown Package"),
                "VulnerabilityID": vuln.get("VulnerabilityID", "Unknown ID"),
                "Severity": vuln.get("Severity", "UNKNOWN"),
                "InstalledVersion": vuln.get("InstalledVersion", "Unknown Version"),
                "FixedVersion": vuln.get("FixedVersion", "N/A"),
                "PrimaryURL": vuln.get("PrimaryURL", "N/A"),
                "References": vuln.get("References", []),
                "Title": vuln.get("Title", "No description available.")
            }
            vulnerabilities.append(vuln_data)

        results_target = result.get("Target", "Unknown Target")
        results_type = result.get("Type", "Unknown Type")

        results_list.append((vulnerabilities, results_target, results_type, json_created_at))

    return results_list
    
def parse_grype_json(data, max_description_length=200):
    """Parsa un file JSON di Grype e usa `relatedVulnerabilities` al posto di `vulnerability` se disponibile."""

    json_created_at = data.get('descriptor', {}).get('timestamp', None)
    vulnerabilities_by_path = {}

    for match in data.get('matches', []):
        artifact = match.get('artifact', {})
        locations = artifact.get('locations', [])  # Percorsi in cui è stato trovato il pacchetto

        # Definisce il tipo di analisi basato su artifact.type
        results_type = artifact.get('type', 'Grype Scan')

        # Determina se usare `relatedVulnerabilities` o `vulnerability`
        vulnerabilities_data = match.get('relatedVulnerabilities', []) or [match.get('vulnerability', {})]

        # Estrarre le informazioni necessarie
        pkg_name = artifact.get('name', 'Unknown Package')
        installed_version = artifact.get('version', 'Unknown Version')
        purl = artifact.get('purl', 'N/A')

        for vuln in vulnerabilities_data:
            vuln_id = vuln.get('id', 'Unknown ID')
            severity = vuln.get('severity', 'UNKNOWN')
            fix_versions = vuln.get('fix', {}).get('versions', [])
            fixed_version = fix_versions[0] if fix_versions else 'N/A'
            primary_url = vuln.get('dataSource', 'N/A')
            references = vuln.get('urls', [])

            # Troncamento della description
            full_title = vuln.get('description', 'No description available.')
            truncated_title = (full_title[:max_description_length] + '...') if len(full_title) > max_description_length else full_title

            # Per ogni percorso trovato, crea un target separato con il corretto results_type
            for location in locations:
                target_path = location.get('path', 'Unknown Path')

                if target_path not in vulnerabilities_by_path:
                    vulnerabilities_by_path[target_path] = {"vulnerabilities": [], "results_type": results_type}

                vuln_data = {
                    "PkgName": pkg_name,
                    "PURL": purl,
                    "VulnerabilityID": vuln_id,
                    "Severity": severity,
                    "InstalledVersion": installed_version,
                    "FixedVersion": fixed_version,
                    "PrimaryURL": primary_url,
                    "References": references,
                    "Title": truncated_title  # Usa la description troncata
                }

                vulnerabilities_by_path[target_path]["vulnerabilities"].append(vuln_data)

    # Converti il dizionario in una lista di tuple per compatibilità con la funzione main
    results_list = []
    for path, data in vulnerabilities_by_path.items():
        results_list.append((data["vulnerabilities"], path, data["results_type"], json_created_at))

    return results_list

def read_json_input(file_path: str):
    """
    Legge un file JSON di output e determina se è un report di Trivy o Grype.

    Args:
        file_path (str): Il percorso del file JSON.

    Returns:
        list: Lista di tuple contenenti dati sulle vulnerabilità, target, tipo e data di creazione.
    """
    try:
        # Rileva la codifica leggendo solo i primi byte del file
        with open(file_path, 'rb') as raw_file:
            raw_data = raw_file.read(10000)  # Legge i primi 10KB per l'analisi
            detected_encoding = chardet.detect(raw_data)['encoding']

        # Se la codifica non è stata rilevata, usa UTF-8 come fallback
        encoding_to_use = detected_encoding if detected_encoding else 'utf-8'

        # Ora leggiamo il file con la codifica rilevata
        with open(file_path, 'r', encoding=encoding_to_use) as file:
            data = json.load(file)

        # Determina il formato del file JSON e chiama il parser corretto
        if 'Results' in data:
            scanner_tool ="Trivy"
            logging.info(f"Formato JSON riconosciuto: {scanner_tool}")
            return parse_trivy_json(data),scanner_tool
        elif 'matches' in data:
            scanner_tool ="Grype"
            logging.info(f"Formato JSON riconosciuto: {scanner_tool}")
            return parse_grype_json(data),scanner_tool
        else:
            logging.error("Formato JSON non riconosciuto. Verifica che il file sia corretto.")
            return []

    except FileNotFoundError:
        logging.error(f"Errore: Il file '{file_path}' non è stato trovato.")
        return []
    except json.JSONDecodeError:
        logging.error(f"Errore: Il file '{file_path}' non è un JSON valido.")
        return []
    except Exception as e:
        logging.error(f"Errore imprevisto durante la lettura del file '{file_path}': {e}")
        return []

def main(json_file_path: str, css_directory: str, js_directory: str):
    """
    Esegue il processo di generazione di un unico report HTML con separazione per target.
    """
    results_list,scanner_tool = read_json_input(json_file_path)

    sections = []
    json_created_at = None
    #scanner_name = "Security Scan"

    for index, (vulnerabilities, results_target, results_type, created_at) in enumerate(results_list):
        json_created_at = created_at or json_created_at
        #scanner_name = results_type
        section_html = generate_html_section(
            vulnerabilities,
            results_target,
            results_type,
            index
        )
        sections.append(section_html)

    formatted_json_created_at = format_date(json_created_at)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_title = f"{scanner_tool} Report - {timestamp}"
    output_html_filename = f"{scanner_tool.lower().replace(' ', '_')}_report_{timestamp}.html"
    output_html_path = f"./{output_html_filename}"

    full_html_report = generate_full_html_report(
        sections,
        report_title,
        css_directory,
        js_directory,
        formatted_json_created_at
    )

    with open(output_html_path, 'w') as file:
        file.write(full_html_report)

    logging.info(f"Report separato per target salvato in {output_html_path}")

# Percorsi dei file e directory richiesti
if __name__ == "__main__":
    css_directory = 'css/'
    js_directory = 'js/'
    json_file_path = 'results.json'

    # Controlla se le directory CSS e JS esistono prima di generare il report
    if validate_directories(css_directory, js_directory):
        main(json_file_path, css_directory, js_directory)
