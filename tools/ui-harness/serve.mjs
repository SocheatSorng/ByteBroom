// ByteBroom's UI harness: serves the real window (ui/) on http://127.0.0.1:1430 with a fake
// `window.__TAURI__` (mock-tauri.js) that answers every command with made-up data. Nothing here
// touches the disk beyond reading ui/ and this folder, and it never runs ByteBroom's Rust code,
// so a screenshot can never show or change the owner's real files.
//
// Usage, in your project folder:  node tools/ui-harness/serve.mjs
// Then open http://127.0.0.1:1430/ (the browser pane can emulate dark mode and sizes).
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { dirname, extname, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const ui = join(here, "..", "..", "ui");
const port = Number(process.env.PORT || 1430);
const types = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
};

// The same CSP the app sets (tauri.conf.json), so the harness catches anything it would block.
const csp =
  "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; " +
  "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'";

/** A file inside `root`, or null for anything that would leave it. */
function inside(root, urlPath) {
  const rel = normalize(decodeURIComponent(urlPath)).replace(/^([/\\])+/, "");
  const full = join(root, rel);
  return full === root || full.startsWith(root + sep) ? full : null;
}

createServer(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  let path = url.pathname === "/" ? "/index.html" : url.pathname;
  let file;
  if (path === "/__harness/mock-tauri.js") file = join(here, "mock-tauri.js");
  else file = inside(ui, path);
  if (!file) {
    res.writeHead(404).end();
    return;
  }
  try {
    let body = await readFile(file);
    if (path === "/index.html") {
      // Load the fake API before the app's own script.
      body = Buffer.from(
        body
          .toString("utf8")
          .replace(
            '<script src="app.js" defer></script>',
            '<script src="/__harness/mock-tauri.js"></script>\n    <script src="app.js" defer></script>',
          ),
      );
    }
    res.writeHead(200, {
      "Content-Type": types[extname(file)] || "application/octet-stream",
      "Content-Security-Policy": csp,
      "Cache-Control": "no-store",
    });
    res.end(body);
  } catch {
    res.writeHead(404).end();
  }
}).listen(port, "127.0.0.1", () => {
  console.log(`ByteBroom UI harness: http://127.0.0.1:${port}/`);
});
