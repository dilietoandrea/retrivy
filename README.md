
# RETRIVY

Tool per generare report di vulnerabilità utilizzando il risultato di una scansione con [trivy](https://trivy.dev)
## INPUT

`results.json`
  - File json risultato della scansione con trivy
  - Comando di scansione:
    ```bash
    trivy fs --scanners vuln --format json -o results.json .
    ```
  	Con questo comando trivy cercherà nella cartella corrente i file di gestione delle dipendenze (requirements.txt, composer.lock, ...) riportando le vulnerabilità individuate nel file results.json

    L'elenco dei file individuabili nel filesystem scanning è disponibilie nella documentazione ufficiale di trivy:
    https://aquasecurity.github.io/trivy/v0.50/docs/coverage/language/

## OUTPUT

`File html` 
  - Report in formato html sulle vulnerabilità individuate in results.json

## UTILIZZO

```bash
python retrivy.py
```
