INPUT:
results.json
	File json risustato della scansione con trivy
		trivy fs --scanners vuln --format json -o results.json .
			Analizzando i file:
				- requiremets.txt
				- composer.lock
			Genera il file:
				- results.json

OUTPUT:
trivy_report_DATA_ORA.html
	File html contente un report sulle vulnerabilità individuate in results.json

FILE:
retrivy.py
sortable.js

UTILIZZO:
python retrivy.py

DESCRIZIONE:
Titolo report con data e ora
Restituisce le informazioni sul primo result (["Results"][0]) di results.json
Type: Gestore dei pacchetti
Summary line con conteggio delle vulnerabilità totali e raggruppate per severity
Ordinamento delle colonne con freccia (ordinamento personalizzato non alfabetico per la colonna Severity)
Colonna Links: Title, PrimaryUrl, Show References - Hide References