
# RETRIVY

Tool per generare report di vulnerabilità utilizzando il risultato di una scansione con trivy o grype.

## SUPPORTED SCANNERS

- **[Trivy](https://trivy.dev)**
- **[Grype](https://github.com/anchore/grype)**


## INPUT

`results.json`
  - File json risultato della scansione con trivy
  - Comando di scansione:
    ```bash
    trivy fs --scanners vuln --format json -o results.json .
    ```
	
	oppure
	
	```bash
	grype . -o json > results_grype.json
	```
  	Con questo comando trivy (o grype) cercherà nella cartella corrente i file di gestione delle dipendenze (requirements.txt, composer.lock, ...) riportando le vulnerabilità individuate nel file results.json

    L'elenco dei file individuabili nel filesystem scanning è disponibilie nella documentazione ufficiale
	trivy:
    https://trivy.dev/latest/docs/coverage/language/
	
	grye:
	https://github.com/anchore/grype

## OUTPUT

`File html` 
  - Report in formato html sulle vulnerabilità individuate in results.json

## UTILIZZO

```bash
python retrivy.py
```
