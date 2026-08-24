async function api(url, options = {}) {
    const response = await fetch(url, {
        credentials: "include",
        headers: {"Content-Type": "application/json"},
        ...options
    });
    let data = {};
    try { data = await response.json(); } catch (_) {}
    if (!response.ok) throw new Error(data.error || "Request failed");
    return data;
}

async function logout() {
    try { await api("/api/logout", {method:"POST"}); } finally { window.location.href = "/"; }
}

async function requireLogin() {
    try { return await api("/api/me"); }
    catch (_) { window.location.href = "/"; }
}
