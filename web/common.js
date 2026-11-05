// Shared helpers: read a server-sent event stream from a POST, and the decision colours.
const COLORS = {"APPROVE": "var(--ok)", "APPROVE WITH CONDITIONS": "var(--warn)", "REJECT": "var(--bad)", "REFER TO HUMAN": "var(--ref)", "ERROR": "var(--bad)"};

async function postStream(url, body, onEvent) {
  const res = await fetch(url, {method: "POST", body});
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try { msg = (await res.json()).detail || msg; } catch (e) {}
    onEvent({type: "error", message: msg});
    return;
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  for (;;) {
    const {value, done} = await reader.read();
    if (done) break;
    buf += decoder.decode(value, {stream: true});
    let cut;
    while ((cut = buf.indexOf("\n\n")) >= 0) {
      const chunk = buf.slice(0, cut);
      buf = buf.slice(cut + 2);
      const line = chunk.split("\n").find(l => l.startsWith("data: "));
      if (line) onEvent(JSON.parse(line.slice(6)));
    }
  }
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
}
