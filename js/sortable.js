var currentSort = {};

var severityOrder = {
    UNKNOWN: 1,
    LOW: 2,
    MEDIUM: 3,
    HIGH: 4,
    CRITICAL: 5
};

function normalizeSortArgs(tableIdOrColumn, columnIndex, initialDir) {
    if (typeof columnIndex === "undefined") {
        return {
            tableId: "sortable-table",
            columnIndex: tableIdOrColumn,
            initialDir: initialDir
        };
    }

    return {
        tableId: tableIdOrColumn,
        columnIndex: columnIndex,
        initialDir: initialDir
    };
}

function compareCells(cellA, cellB, columnIndex) {
    var valueA = (cellA && cellA.textContent ? cellA.textContent : "").trim();
    var valueB = (cellB && cellB.textContent ? cellB.textContent : "").trim();

    if (columnIndex === 2) {
        return (severityOrder[valueA.toUpperCase()] || 0) - (severityOrder[valueB.toUpperCase()] || 0);
    }

    var numberA = Number(valueA);
    var numberB = Number(valueB);
    if (valueA !== "" && valueB !== "" && !Number.isNaN(numberA) && !Number.isNaN(numberB)) {
        return numberA - numberB;
    }

    return valueA.localeCompare(valueB);
}

function updateSortIcons(table, columnIndex, direction) {
    Array.from(table.querySelectorAll("th")).forEach(function(header, index) {
        var icon = header.querySelector(".sort-icon");
        if (!icon) return;

        icon.textContent = index === columnIndex ? (direction === "asc" ? " ^" : " v") : "";
    });
}

function sortTable(tableIdOrColumn, columnIndex, initialDir) {
    var args = normalizeSortArgs(tableIdOrColumn, columnIndex, initialDir);
    var table = document.getElementById(args.tableId);
    if (!table || !table.tBodies.length) return;

    var previousSort = currentSort[args.tableId];
    var direction = previousSort && previousSort.columnIndex === args.columnIndex && previousSort.direction === "asc"
        ? "desc"
        : "asc";

    if (!previousSort && args.initialDir) {
        direction = args.initialDir;
    }

    currentSort[args.tableId] = {
        columnIndex: args.columnIndex,
        direction: direction
    };

    var tbody = table.tBodies[0];
    var rows = Array.from(tbody.rows);

    rows.sort(function(rowA, rowB) {
        var comparison = compareCells(rowA.cells[args.columnIndex], rowB.cells[args.columnIndex], args.columnIndex);
        return direction === "asc" ? comparison : -comparison;
    });

    rows.forEach(function(row) {
        tbody.appendChild(row);
    });

    updateSortIcons(table, args.columnIndex, direction);
}

window.addEventListener("load", function() {
    document.querySelectorAll("table[id^='sortable-table']").forEach(function(table) {
        sortTable(table.id, 2, "desc");
    });
});
