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
function sortTable(columnIndex) {
    var table = document.getElementById("sortable-table");
    var rows = Array.from(table.rows).slice(1); // Escludi l'header

    // Determina la direzione dell'ordinamento
    var dir = currentSort.columnIndex === columnIndex && currentSort.direction === 'asc' ? 'desc' : 'asc';
    currentSort = { columnIndex, direction: dir };

    // Mappa di ordinamento per la severità
    const severityOrder = { 'UNKNOWN': 1, 'LOW': 2, 'MEDIUM': 3, 'HIGH': 4, 'CRITICAL': 5 };

    rows.sort((rowA, rowB) => {
        let cellA = rowA.cells[columnIndex].textContent.trim();
        let cellB = rowB.cells[columnIndex].textContent.trim();

        let comparison = 0;

        // 🔹 Ordinamento speciale per la colonna "Severity" (indice 2)
        if (columnIndex === 2) {
            comparison = (severityOrder[cellA] || 0) - (severityOrder[cellB] || 0);
        }
        // 🔹 Ordinamento numerico (se entrambi i valori sono numeri)
        else if (!isNaN(cellA) && !isNaN(cellB)) {
            comparison = parseFloat(cellA) - parseFloat(cellB);
        }
        // 🔹 Ordinamento alfabetico standard
        else {
            comparison = cellA.localeCompare(cellB);
        }

        return dir === 'asc' ? comparison : -comparison;
    });

    // 🔹 Aggiorna la tabella con le righe ordinate
    rows.forEach(row => table.appendChild(row));

    // 🔹 Aggiorna le icone di ordinamento nelle intestazioni
    document.querySelectorAll('#sortable-table th').forEach((th, index) => {
        th.innerHTML = th.innerHTML.replace(/▲|▼|$/, index === columnIndex ? (dir === 'asc' ? '▲' : '▼') : '');
    });
}
function sortTable(tableId, columnIndex) {
    var table = document.getElementById(tableId);
    if (!table) return; // Se la tabella non esiste, esci

    var rows = Array.from(table.getElementsByTagName("TR")).slice(1); // Escludi l'header
    var dir = currentSort[tableId]?.columnIndex === columnIndex && currentSort[tableId]?.direction === 'asc' ? 'desc' : 'asc';
    currentSort[tableId] = { columnIndex, direction: dir };

    // Mappa di ordinamento per la severità
    const severityOrder = { 'UNKNOWN': 1, 'LOW': 2, 'MEDIUM': 3, 'HIGH': 4, 'CRITICAL': 5 };

    rows.sort((rowA, rowB) => {
        let cellA = rowA.cells[columnIndex]?.textContent.trim() || "";
        let cellB = rowB.cells[columnIndex]?.textContent.trim() || "";

        let comparison = 0;

        // 🔹 Ordinamento speciale per la colonna "Severity" (indice 2)
        if (columnIndex === 2) {
            comparison = (severityOrder[cellA] || 0) - (severityOrder[cellB] || 0);
        }
        // 🔹 Ordinamento numerico (se entrambi i valori sono numeri)
        else if (!isNaN(cellA) && !isNaN(cellB)) {
            comparison = parseFloat(cellA) - parseFloat(cellB);
        }
        // 🔹 Ordinamento alfabetico standard
        else {
            comparison = cellA.localeCompare(cellB);
        }

        return dir === 'asc' ? comparison : -comparison;
    });

    // 🔹 Aggiorna la tabella con le righe ordinate
    rows.forEach(row => table.appendChild(row));

    // 🔹 Aggiorna le icone di ordinamento nelle intestazioni della tabella specifica
    document.querySelectorAll(`#${tableId} th`).forEach((th, index) => {
        th.innerHTML = th.innerHTML.replace(/▲|▼|$/, index === columnIndex ? (dir === 'asc' ? '▲' : '▼') : '');
    });
}
// Oggetto per tenere traccia dell'ordinamento di ogni tabella
var currentSort = {};

// Funzione per ordinare la tabella
function sortTable(tableId, columnIndex, initialDir = 'asc') {
    var table = document.getElementById(tableId);
    if (!table) return;

    var rows = Array.from(table.getElementsByTagName("TR")).slice(1); // Escludi l'header
    var dir = currentSort[tableId]?.columnIndex === columnIndex && currentSort[tableId]?.direction === 'asc' ? 'desc' : 'asc';
    
    // Se la colonna è "Severity" (indice 2), impostala sempre su 'desc' alla prima esecuzione
    if (!currentSort[tableId] && columnIndex === 2) {
        dir = 'desc';
    }

    currentSort[tableId] = { columnIndex, direction: dir };

    // Mappa di ordinamento per la severità
    const severityOrder = { 'UNKNOWN': 1, 'LOW': 2, 'MEDIUM': 3, 'HIGH': 4, 'CRITICAL': 5 };

    rows.sort((rowA, rowB) => {
        let cellA = rowA.cells[columnIndex]?.textContent.trim() || "";
        let cellB = rowB.cells[columnIndex]?.textContent.trim() || "";

        let comparison = 0;

        // Ordinamento speciale per la colonna "Severity" (indice 2)
        if (columnIndex === 2) {
            comparison = (severityOrder[cellA] || 0) - (severityOrder[cellB] || 0);
        }
        // Ordinamento numerico (se entrambi i valori sono numeri)
        else if (!isNaN(cellA) && !isNaN(cellB)) {
            comparison = parseFloat(cellA) - parseFloat(cellB);
        }
        // Ordinamento alfabetico standard
        else {
            comparison = cellA.localeCompare(cellB);
        }

        return dir === 'asc' ? comparison : -comparison;
    });

    // Aggiorna la tabella con le righe ordinate
    rows.forEach(row => table.appendChild(row));

    // Aggiorna le icone di ordinamento nelle intestazioni della tabella specifica
    document.querySelectorAll(`#${tableId} th`).forEach((th, index) => {
        th.innerHTML = th.innerHTML.replace(/▲|▼|$/, index === columnIndex ? (dir === 'asc' ? '▲' : '▼') : '');
    });
}

// Quando la pagina è caricata, ordina automaticamente la colonna "Severity" (indice 2)
window.onload = function() {
    document.querySelectorAll("table[id^='sortable-table']").forEach((table) => {
        sortTable(table.id, 2, 'desc'); // Ordina automaticamente la colonna "Severity" in modo decrescente
    });
};
