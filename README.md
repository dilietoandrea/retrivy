
# RETRIVY

**Tool per generare report di vulnerabilità utilizzando il risultato di una scansione con trivy ([trivy.dev](https://trivy.dev/))**

## INPUT

- **results.json**
  - File json risultato della scansione con trivy
  - Comando di scansione:
    ```bash
    trivy fs --scanners vuln --format json -o results.json .
    ```
  - Analizzando i file:
    - `requirements.txt`
    - `composer.lock`
  - Genera il file:
    - `results.json`

## OUTPUT

- **trivy_report_DATA_ORA.html**
  - File html contenente un report sulle vulnerabilità individuate in `results.json`

## PROJECT FILES

- `retrivy.py`
- `sortable.js`

## UTILIZZO

```bash
python retrivy.py
```

## DESCRIZIONE

- Titolo del report con data e ora
- Restituisce le informazioni sul primo result (`['Results'][0]`) di `results.json`
- Type: Gestore dei pacchetti
- Summary line con conteggio delle vulnerabilità totali e raggruppate per severity
- Ordinamento delle colonne con freccia (ordinamento personalizzato non alfabetico per la colonna Severity)
- Colonna Links: Title, PrimaryUrl, Show References - Hide References
