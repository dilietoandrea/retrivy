# RETRIVY

Tool per generare report HTML di vulnerabilità a partire dal risultato JSON di una scansione con Trivy o Grype.

## Scanner supportati

- [Trivy](https://trivy.dev)
- [Grype](https://github.com/anchore/grype)

## Installazione

```bash
pip install -r requirements.txt
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

Uso base, con `results.json` nella root del progetto:

```bash
python retrivy.py
```

Uso con input e output espliciti:

```bash
python retrivy.py --input "input examples/results.json" --output report.html
```

Opzioni disponibili:

```bash
python retrivy.py --help
```

## Output

Lo script genera un report HTML con:

- vulnerabilità raggruppate per target
- conteggio per severità
- tabella ordinabile
- link primario e riferimenti espandibili

Se non viene indicato `--output`, il file viene creato con un nome automatico basato su scanner e timestamp.
