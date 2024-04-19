
# RETRIVY

Tool per generare report di vulnerabilità utilizzando il risultato di una scansione con trivy ([trivy.dev](https://trivy.dev))

## INPUT

`results.json`
  - File json risultato della scansione con trivy
  - Comando di scansione:
    ```bash
    trivy fs --scanners vuln --format json -o results.json .
    ```
  	Con questo comando Trivy cercherà nella cartella corrente i file di gestione delle dipendenze (requirements.txt, composer.lock, package-lock.json,...) riportando le vulnerabilità individuate nel file results.json 

## OUTPUT

`File html` 
  - Report in formato html sulle vulnerabilità individuate in results.json

## UTILIZZO

```bash
python retrivy.py
```
