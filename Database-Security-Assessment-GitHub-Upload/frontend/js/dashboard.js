(async function(){
    const user = await requireLogin();
    if (!user) return;
    document.getElementById("userInfo").textContent = `${user.username} · ${user.role.toUpperCase()}`;
    try {
        const d = await api("/api/dashboard");
        document.getElementById("score").textContent = d.security_score;
        document.getElementById("vulns").textContent = d.vulnerabilities;
        document.getElementById("tests").textContent = d.tests_performed;
        document.getElementById("passed").textContent = d.passed;
    } catch (e) { console.error(e); }
})();
