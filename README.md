
# RETRIVY

**Tool per generare report di vulnerabilità utilizzando il risultato di una scansione con trivy ([trivy.dev](https://trivy.dev/))**

## INPUT

- **results.json**
  - File json risultato della scansione con trivy
  - Comando di scansione:
	- analizzando i file:
		- `requirements.txt`
		- `composer.lock`
		- ...
	- genera il file:
		- `results.json`
 ```bash
trivy fs --scanners vuln --format json -o results.json .
```

## OUTPUT

- File html contenente un report sulle vulnerabilità individuate in `results.json`


## UTILIZZO

```bash
python retrivy.py
```
