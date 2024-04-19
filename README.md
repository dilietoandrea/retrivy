
# RETRIVY

**Tool per generare report di vulnerabilità utilizzando il risultato di una scansione con trivy ([trivy.dev](https://trivy.dev/))**

## INPUT

- **results.json**
  - File json risultato della scansione con trivy
  - Comando di scansione:
		```bash
		trivy fs --scanners vuln --format json -o results.json .
		```
		  - analizzando i file:
			- `requirements.txt`
			- `composer.lock`
			- ...
		  - genera il file:
			- `results.json`

## OUTPUT

- File html contenente un report sulle vulnerabilità individuate in `results.json`

## PROJECT FILES

- `retrivy.py`
- `sortable.js`

## UTILIZZO

```bash
python retrivy.py
```
