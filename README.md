# RETRIVY

Tool per generare report HTML di vulnerabilità a partire dal risultato JSON di una scansione con Trivy o Grype.

## Scanner supportati

- [Trivy](https://trivy.dev)
- [Grype](https://github.com/anchore/grype)

## Installazione

Uso consigliato: lascia creare l'ambiente virtuale al runner del progetto.

```bash
python run.py --input "input examples/results.json" --output report.html
```

Alla prima esecuzione viene creata la cartella `.venv/` e vengono installate le dipendenze di `requirements.txt`.

Installazione manuale alternativa:

```bash
pip install -r requirements.txt
```

## Installazione scanner

Trivy e Grype non sono librerie Python, quindi vengono installati separatamente nella cartella locale `.tools/`.

Per installare o aggiornare entrambi all'ultima release disponibile su GitHub:

```bash
python install_tools.py
```

Per vedere cosa verrebbe installato senza scaricare nulla:

```bash
python install_tools.py --dry-run
```

Gli eseguibili vengono salvati in `.tools/bin/`. Su Windows puoi usarli cosi':

```bash
.\.tools\bin\trivy.exe --version
.\.tools\bin\grype.exe version
```

L'installer scarica gli archivi dagli asset ufficiali GitHub della release piu' recente e verifica lo SHA256 usando il file `checksums.txt` pubblicato nella stessa release.

Esempio di scansione con Trivy:

```bash
.\.tools\bin\trivy.exe fs --scanners vuln --format json -o results.json .
python run.py --input results.json --output report.html
```

Esempio di scansione con Grype:

```bash
.\.tools\bin\grype.exe . -o json > results_grype.json
python run.py --input results_grype.json --output report.html
```

## Input

RETRIVY legge un file JSON prodotto da Trivy o Grype.

Esempio con Trivy:

```bash
trivy fs --scanners vuln --format json -o results.json .
```

Esempio con Grype:

```bash
grype . -o json > results_grype.json
```

Entrambi gli scanner cercano nel filesystem file di gestione delle dipendenze, come `requirements.txt`, `composer.lock` e altri manifest supportati.

Documentazione utile:

- Trivy filesystem/language coverage: <https://trivy.dev/latest/docs/coverage/language/>
- Grype: <https://github.com/anchore/grype>

## Utilizzo

Uso completo consigliato: installa lo scanner se manca, esegue la scansione e crea JSON + report HTML nella cartella `reports/`.

```bash
python scan.py --scanner trivy --target "input examples/classifica-film-2.8.0"
```

Con Grype:

```bash
python scan.py --scanner grype --target "input examples/classifica-film-2.8.0"
```

I file generati avranno un nome simile a:

```text
reports/classifica-film-2.8.0-trivy-20260423-153000.json
reports/classifica-film-2.8.0-trivy-20260423-153000.html
```

Per scegliere manualmente i percorsi di output:

```bash
python scan.py --scanner trivy --target . --json-output results.json --report report.html
```

Uso base, con `results.json` nella root del progetto:

```bash
python run.py
```

Uso con input e output espliciti:

```bash
python run.py --input "input examples/results.json" --output report.html
```

Opzioni disponibili:

```bash
python run.py --help
```

## Output

Lo script genera un report HTML con:

- vulnerabilità raggruppate per target
- conteggio per severità
- tabella ordinabile
- link primario e riferimenti espandibili

Con `scan.py`, se non vengono indicati `--json-output` e `--report`, i file vengono creati in `reports/` con nome automatico basato su target, scanner e timestamp. La cartella `reports/` e' ignorata da Git, quindi puoi generare report locali senza sporcare i commit.

Con `run.py`, se non viene indicato `--output`, il file viene creato con un nome automatico basato su scanner e timestamp.

## Test

Installa le dipendenze di sviluppo:

```bash
pip install -r requirements.txt -r requirements-dev.txt
```

Esegui i test:

```bash
pytest
```

La CI GitHub Actions esegue compilazione Python e test su Linux e Windows.
