var currentSort = { columnIndex: null, direction: 'asc' };

function customSeveritySort(a, b) {
    const order = { 'UNKNOWN': 1, 'LOW': 2, 'MEDIUM': 3, 'HIGH': 4, 'CRITICAL': 5 };
    return order[a] - order[b];
}

function sortTable(columnIndex) {
    var table, rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;
    table = document.getElementById("sortable-table");
    switching = true;
    // Determina la direzione iniziale basandosi sull'ultimo stato di ordinamento per questa colonna
    dir = currentSort.columnIndex === columnIndex && currentSort.direction === 'asc' ? 'desc' : 'asc';

    // Funzione di comparazione personalizzata per la severità
    const severityOrder = { 'UNKNOWN': 1, 'LOW': 2, 'MEDIUM': 3, 'HIGH': 4, 'CRITICAL': 5 };
    function compareSeverity(a, b) {
        return severityOrder[a] - severityOrder[b];
    }

    while (switching) {
        switching = false;
        rows = table.getElementsByTagName("TR");
        for (i = 1; i < (rows.length - 1); i++) {
            shouldSwitch = false;
            x = rows[i].getElementsByTagName("TD")[columnIndex];
            y = rows[i + 1].getElementsByTagName("TD")[columnIndex];

            let comparison = 0;
            if (columnIndex === 2) { // Assumi che la colonna "Severity" abbia indice 2
                comparison = compareSeverity(x.innerHTML.toUpperCase(), y.innerHTML.toUpperCase());
            } else {
                comparison = x.innerHTML.toLowerCase().localeCompare(y.innerHTML.toLowerCase());
            }

            if (dir === "asc" && comparison > 0) {
                shouldSwitch = true;
                break;
            } else if (dir === "desc" && comparison < 0) {
                shouldSwitch = true;
                break;
            }
        }
        if (shouldSwitch) {
            rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
            switching = true;
            switchcount++;
        } else {
            if (switchcount == 0 && dir === "asc") {
                dir = "desc";
                switching = true;
            }
        }
    }
    // Aggiorna lo stato di ordinamento corrente e le icone
    currentSort.columnIndex = columnIndex;
    currentSort.direction = dir;

    var headers = document.querySelectorAll('#sortable-table th');
    headers.forEach((header, index) => {
        if (index === columnIndex) {
            header.innerHTML = header.innerHTML.replace(/▲|▼|$/, currentSort.direction === 'asc' ? '▲' : '▼');
        } else {
            header.innerHTML = header.innerHTML.replace(/▲|▼|$/, '');
        }
    });
}
