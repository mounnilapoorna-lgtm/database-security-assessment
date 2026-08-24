(async function(){
    await requireLogin();
    const body = document.getElementById("auditBody");
    try {
        const rows = await api("/api/audit");
        rows.forEach(r => {
            const tr = document.createElement("tr");
            tr.innerHTML = `<td>${r.timestamp}</td><td>${r.username || ""}</td><td>${r.action}</td><td>${r.result}</td><td>${r.details || ""}</td>`;
            body.appendChild(tr);
        });
    } catch(e) { body.innerHTML = `<tr><td colspan="5" class="error">${e.message}</td></tr>`; }
})();
