async function showResult(id, data) {
    const el = document.getElementById(id);
    const cls = data.result === "VULNERABLE" ? "error" : "success";
    el.innerHTML = `<div class="result ${cls}"><strong>${data.result}</strong>${data.details || ""}</div>`;
}
async function runSQLTest() {
    try {
        const data = await api("/api/security-tests/sql-injection", {
            method:"POST", body:JSON.stringify({input:document.getElementById("sqlInput").value})
        });
        showResult("sqlResult", data);
    } catch(e) { document.getElementById("sqlResult").innerHTML=`<div class="result error">${e.message}</div>`; }
}
async function runPasswordTest() {
    try {
        const data = await api("/api/security-tests/password", {
            method:"POST", body:JSON.stringify({password:document.getElementById("testPassword").value})
        });
        const checks = Object.entries(data.checks).map(([k,v])=>`${k}: ${v ? "✓":"✗"}`).join(" · ");
        showResult("passwordResult", {...data, details:`${data.details}<br>${checks}`});
    } catch(e) { document.getElementById("passwordResult").innerHTML=`<div class="result error">${e.message}</div>`; }
}
async function runAuthTest() {
    try { showResult("authResult", await api("/api/security-tests/authentication",{method:"POST"})); }
    catch(e) { document.getElementById("authResult").innerHTML=`<div class="result error">${e.message}</div>`; }
}
async function runAccessTest() {
    try { showResult("accessResult", await api("/api/security-tests/access-control",{method:"POST"})); }
    catch(e) { document.getElementById("accessResult").innerHTML=`<div class="result error">${e.message}</div>`; }
}
requireLogin();
