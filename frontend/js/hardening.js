(async function(){
    const user = await requireLogin();
    if (!user) return;
    const container = document.getElementById("controls");
    try {
        const controls = await api("/api/hardening");
        controls.forEach(c => {
            const row = document.createElement("div");
            row.className = "control";
            const status = c.enabled ? "ENABLED" : "DISABLED";
            row.innerHTML = `<div><strong>${c.control_name}</strong><div class="muted">${status}</div></div>`;
            const btn = document.createElement("button");
            btn.textContent = c.enabled ? "Disable" : "Enable";
            btn.disabled = user.role !== "admin";
            btn.onclick = async () => {
                try {
                    await api(`/api/hardening/${c.id}`, {
                        method:"POST",
                        body:JSON.stringify({enabled:!Boolean(c.enabled)})
                    });
                    location.reload();
                } catch(e) { alert(e.message); }
            };
            row.appendChild(btn);
            container.appendChild(row);
        });
    } catch(e) { container.innerHTML = `<p class="error">${e.message}</p>`; }
})();
