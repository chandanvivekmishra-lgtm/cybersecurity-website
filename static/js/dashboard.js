const form = document.querySelector("#scan-form");
const toast = document.querySelector("#toast");
const menuButton = document.querySelector(".menu-button");
const sidebar = document.querySelector(".sidebar");
const searchInput = document.querySelector("#dashboard-search");
const severityFilter = document.querySelector("#dashboard-severity-filter");
const tableRows = Array.from(document.querySelectorAll("tbody tr"));
const tableCount = document.querySelector("#table-count");

function showToast(message) {
    if (!toast) return;
    toast.textContent = message;
    toast.classList.add("show");
    window.setTimeout(() => toast.classList.remove("show"), 4000);
}

function applyDashboardFilters() {
    if (!tableRows.length) return;
    const value = (searchInput ? searchInput.value.toLowerCase() : "").trim();
    const severity = severityFilter ? severityFilter.value : "all";
    let visible = 0;

    tableRows.forEach((row) => {
        const target = row.dataset.target || "";
        const rowSeverity = row.dataset.severity || "low";
        const matchText = !value || target.includes(value) || row.textContent.toLowerCase().includes(value);
        const matchSeverity = severity === "all" || rowSeverity === severity;
        const isVisible = matchText && matchSeverity;
        row.style.display = isVisible ? "" : "none";
        if (isVisible) visible += 1;
    });

    if (tableCount) {
        tableCount.textContent = `${visible} RECORD${visible === 1 ? "" : "S"}`;
    }
}

if (menuButton && sidebar) {
    menuButton.addEventListener("click", () => sidebar.classList.toggle("open"));
}

if (searchInput) {
    searchInput.addEventListener("input", applyDashboardFilters);
}

if (severityFilter) {
    severityFilter.addEventListener("change", applyDashboardFilters);
}

if (form) {
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const submitButton = form.querySelector("button[type='submit']");
        const targetInput = form.querySelector("#target");
        const originalLabel = submitButton.querySelector(".button-label").textContent;

        submitButton.disabled = true;
        submitButton.querySelector(".button-label").textContent = "Scanning target…";
        try {
            const response = await fetch("/api/scan", {
                method: "POST",
                body: new FormData(form),
            });
            const payload = await response.json();
            if (!response.ok) {
                throw new Error(payload.error || "The scan could not be completed.");
            }
            showToast(`Assessment complete — score ${payload.score}/100`);
            window.location.href = `/reports/${payload.scan_id}`;
        } catch (error) {
            showToast(error.message);
            submitButton.querySelector(".button-label").textContent = originalLabel;
            submitButton.disabled = false;
            targetInput.focus();
        }
    });
}

const printButton = document.querySelector("#print-report");
if (printButton) {
    printButton.addEventListener("click", () => window.print());
}

applyDashboardFilters();
