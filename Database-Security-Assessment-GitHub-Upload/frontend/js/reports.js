(async function(){
    await requireLogin();
    const el = document.getElementById("report");
    try {
        const r = await api("/api/report");
        const vulnerable = r.tests.filter(t=>t.result==="VULNERABLE");
        el.innerHTML = `
        <div class="report-card">
            <p class="muted">Generated: ${r.generated_at}</p>
            <div class="score">${r.security_score}/100</div>
            <p>Current security score</p>
        </div>
        <div class="report-card">
            <h2>Vulnerabilities</h2>
            <p>${vulnerable.length ? vulnerable.length+" vulnerability finding(s)" : "No vulnerability findings recorded."}</p>
        </div>
        <div class="report-card table-wrap">
            <h2>Test History</h2>
            <table><thead><tr><th>Test</th><th>Severity</th><th>Result</th><th>Time</th></tr></thead>
            <tbody>${r.tests.map(t=>`<tr><td>${t.test_name}</td><td>${t.severity}</td><td>${t.result}</td><td>${t.timestamp}</td></tr>`).join("")}</tbody></table>
        </div>`;
    } catch(e) { el.innerHTML=`<p class="error">${e.message}</p>`; }
})();
