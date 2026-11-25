// ByteBroom's window. Talks to Rust only through window.__TAURI__.core.invoke and sends only
// finding IDs, preview IDs and fixed action names: never a path. Every element is built with
// createElement and textContent, so file names are always shown as text, never as markup.
"use strict";

(() => {
  const invoke = (cmd, args) => window.__TAURI__.core.invoke(cmd, args);
  const $ = (id) => document.getElementById(id);

  /** Make an element: el("div", { className: "x", text: "hi", attrs: {...} }, ...children). */
  function el(tag, props = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (k === "text") node.textContent = v;
      else if (k === "attrs") for (const [a, b] of Object.entries(v)) node.setAttribute(a, b);
      else if (k === "on") for (const [ev, fn] of Object.entries(v)) node.addEventListener(ev, fn);
      else node[k] = v;
    }
    for (const c of children) if (c !== null && c !== undefined) node.append(c);
    return node;
  }

  function bytes(n) {
    if (n < 1024) return `${n} B`;
    const units = ["KB", "MB", "GB", "TB"];
    let v = n;
    let u = -1;
    do {
      v /= 1024;
      u += 1;
    } while (v >= 1024 && u < units.length - 1);
    return `${v >= 100 ? v.toFixed(0) : v.toFixed(1)} ${units[u]}`;
  }

  function plural(n, one, many = `${one}s`) {
    return `${n.toLocaleString()} ${n === 1 ? one : many}`;
  }

  const date = (secs) => (secs ? new Date(secs * 1000).toLocaleDateString() : "");
  const key = (id) => `${id.scan}:${id.index}`;

  // Owner's decision 1: green defaults to permanent delete, amber to the Recycle Bin.
  const ACTIONS = [
    ["Delete", "Delete for good"],
    ["Recycle", "Recycle Bin"],
    ["Move", "Move to folder"],
  ];
  const ACTION_WORDS = { delete: "Delete for good", recycle: "Recycle Bin", move: "Move" };
  const defaultAction = (f) => (f.tier === "green" ? "Delete" : "Recycle");
  const ROWS_PER_PAGE = 100;

  const state = {
    scan: 0,
    version: 0,
    phase: "idle",
    findings: [],
    choices: new Map(), // key -> { on, action }
    filter: "",
    moveTo: null,
    open: new Set(), // rule IDs whose list is open
    shown: new Map(), // rule ID -> rows shown
    preview: null,
  };

  function setStatus(text, isError = false) {
    const s = $("status");
    s.textContent = text;
    s.classList.toggle("error", isError);
  }

  function errorText(e) {
    return (e && e.message) || String(e);
  }

  // ---- Scan --------------------------------------------------------------------------------

  async function startScan() {
    try {
      await invoke("start_scan");
    } catch (e) {
      setStatus(`The scan could not start: ${errorText(e)}`, true);
      return;
    }
    state.version = 0;
    state.preview = null;
    setRunning(true);
    poll();
  }

  function setRunning(running) {
    $("scan").disabled = running;
    $("cancel").hidden = !running;
    $("progress").hidden = !running;
    $("preview").disabled = running || chosen().length === 0;
  }

  async function poll() {
    let v;
    try {
      v = await invoke("scan_state", { seen: state.version });
    } catch (e) {
      setStatus(`Could not read the scan: ${errorText(e)}`, true);
      setRunning(false);
      return;
    }
    apply(v);
    if (v.phase === "scanning" || v.phase === "hashing") {
      setTimeout(poll, 500);
    } else {
      setRunning(false);
    }
  }

  function apply(v) {
    const seconds = Math.round(v.elapsedMs / 1000);
    if (v.findings) {
      if (v.scan !== state.scan) {
        state.choices = new Map();
        state.open = new Set();
        state.shown = new Map();
      }
      state.scan = v.scan;
      state.findings = v.findings;
      for (const f of v.findings) {
        const k = key(f.id);
        if (!state.choices.has(k)) {
          state.choices.set(k, { on: f.preTicked && !f.notOffered, action: defaultAction(f) });
        }
      }
      state.version = v.version;
      render();
    }
    state.phase = v.phase;
    renderRed(v.red);
    renderUnscanned(v.skipped);
    const found = `${plural(v.items, "item")}, ${bytes(v.bytes)}`;
    const text = {
      scanning: `Scanning… ${seconds} s`,
      hashing: `Found ${found} so far. Looking for duplicates… ${seconds} s. You can look through the list; preview once the scan ends.`,
      done: `Found ${found} in ${seconds} s. Tick what to clean, choose an action, then Preview.`,
      cancelled: `Stopped after ${seconds} s. Showing the ${found} found so far.`,
      idle: $("status").textContent,
    }[v.phase];
    setStatus(text);
    $("main").hidden = v.phase === "idle";
  }

  // ---- Lists -------------------------------------------------------------------------------

  function matches(f) {
    return !state.filter || f.path.toLowerCase().includes(state.filter);
  }

  function chosen() {
    return state.findings.filter((f) => !f.notOffered && state.choices.get(key(f.id))?.on);
  }

  function updateTotals() {
    const list = chosen();
    $("chosen-count").textContent = `${plural(list.length, "item")} chosen`;
    $("chosen-size").textContent = bytes(list.reduce((s, f) => s + f.bytes, 0));
    $("preview").disabled =
      list.length === 0 || state.phase === "scanning" || state.phase === "hashing";
  }

  function groups(tier) {
    const out = new Map();
    for (const f of state.findings) {
      if (f.tier !== tier) continue;
      if (!out.has(f.rule)) out.set(f.rule, { label: f.label, items: [] });
      out.get(f.rule).items.push(f);
    }
    return out;
  }

  function render() {
    for (const tier of ["green", "amber"]) {
      const box = $(`${tier}-list`);
      box.replaceChildren();
      const g = groups(tier);
      if (g.size === 0) {
        box.append(el("p", { className: "empty", text: "Nothing found here." }));
        continue;
      }
      for (const [rule, group] of g) box.append(category(rule, group));
    }
    renderLargest();
    updateTotals();
  }

  function category(rule, group) {
    const visible = group.items.filter(matches);
    const offered = visible.filter((f) => !f.notOffered);
    const on = offered.filter((f) => state.choices.get(key(f.id)).on).length;
    const box = el("input", {
      type: "checkbox",
      checked: offered.length > 0 && on === offered.length,
      indeterminate: on > 0 && on < offered.length,
      disabled: offered.length === 0,
      attrs: { "aria-label": `Choose every item in ${group.label}` },
      on: {
        click: (e) => e.stopPropagation(),
        change: (e) => {
          for (const f of offered) state.choices.get(key(f.id)).on = e.target.checked;
          render();
        },
      },
    });
    const size = visible.reduce((s, f) => s + f.bytes, 0);
    const details = el(
      "details",
      { className: "category", open: state.open.has(rule) },
      el(
        "summary",
        {},
        box,
        el("span", { className: "cat-name", text: group.label }),
        el("span", { className: "cat-count", text: plural(visible.length, "item") }),
        el("span", { className: "size", text: bytes(size) }),
      ),
    );
    const rows = el("div", { className: "rows" });
    details.append(rows);
    const fill = () => {
      rows.replaceChildren();
      const limit = state.shown.get(rule) || ROWS_PER_PAGE;
      for (const f of visible.slice(0, limit)) rows.append(row(f));
      if (visible.length > limit) {
        rows.append(
          el(
            "div",
            { className: "more" },
            el("button", {
              type: "button",
              className: "link",
              text: `Show ${Math.min(ROWS_PER_PAGE, visible.length - limit)} more of ${plural(visible.length - limit, "item")}`,
              on: {
                click: () => {
                  state.shown.set(rule, limit + ROWS_PER_PAGE);
                  fill();
                },
              },
            }),
          ),
        );
      }
    };
    if (details.open) fill();
    details.addEventListener("toggle", () => {
      if (details.open) state.open.add(rule);
      else state.open.delete(rule);
      // The list may have been redrawn (a scan update) between the click and this event: then
      // this element is gone, so redraw to show the change on the one that replaced it.
      if (!details.isConnected) {
        render();
        return;
      }
      if (details.open) fill();
      else rows.replaceChildren();
    });
    return details;
  }

  function row(f) {
    const c = state.choices.get(key(f.id));
    const off = Boolean(f.notOffered);
    const label = f.name || f.path;
    const tick = el("input", {
      type: "checkbox",
      checked: c.on && !off,
      disabled: off,
      attrs: { "aria-label": `Choose ${label}` },
      on: {
        change: (e) => {
          c.on = e.target.checked;
          render();
        },
      },
    });
    const action = el(
      "select",
      {
        disabled: off,
        attrs: { "aria-label": `Action for ${label}` },
        on: {
          change: (e) => {
            c.action = e.target.value;
          },
        },
      },
      ...ACTIONS.map(([value, text]) => el("option", { value, text, selected: c.action === value })),
    );
    const tags = [];
    if (f.notOffered) tags.push(el("span", { className: "tag off", text: f.notOffered }));
    if (f.note) tags.push(el("span", { className: "tag", text: f.note }));
    if (f.duplicateOf) {
      tags.push(el("span", { className: "tag off", text: `copy of ${f.duplicateOf}` }));
    }
    return el(
      "div",
      { className: off ? "row off" : "row" },
      tick,
      el(
        "div",
        { className: "item" },
        el("span", {
          className: "item-name",
          text: f.isFolder ? `${label} (folder, ${plural(f.files, "file")})` : label,
        }),
        el("span", { className: "item-path", text: f.path, title: f.path }),
        ...tags,
      ),
      el("span", { className: "size", text: bytes(f.bytes) }),
      el("span", { className: "date", text: date(f.newest) }),
      action,
    );
  }

  function renderLargest() {
    const list = $("largest");
    list.replaceChildren();
    const top = state.findings
      .filter((f) => !f.notOffered && matches(f))
      .sort((a, b) => b.bytes - a.bytes)
      .slice(0, 15);
    for (const f of top) {
      list.append(
        el(
          "li",
          {},
          el(
            "div",
            { className: "item" },
            el("span", { className: "item-name", text: f.name || f.path }),
            el("span", { className: "item-path", text: `${f.label} · ${f.path}`, title: f.path }),
          ),
          el("span", { className: "size", text: bytes(f.bytes) }),
        ),
      );
    }
    if (top.length === 0) list.append(el("li", { className: "empty", text: "Nothing yet." }));
  }

  function renderRed(red) {
    const list = $("red-list");
    list.replaceChildren();
    if (!red) {
      list.append(el("li", {}, el("span", { text: "Measuring…" })));
      return;
    }
    for (const r of red) {
      list.append(el("li", {}, el("span", { text: r.label }), el("span", { className: "size", text: r.size })));
    }
  }

  function renderUnscanned(skipped) {
    $("unscanned-box").hidden = skipped.length === 0;
    const list = $("unscanned");
    list.replaceChildren();
    for (const s of skipped) list.append(el("li", { text: `${s.location}: ${s.why}` }));
  }

  // ---- Preview and clean -------------------------------------------------------------------

  async function openPreview() {
    const choices = chosen().map((f) => ({
      finding: f.id,
      action: state.choices.get(key(f.id)).action,
    }));
    let pv;
    try {
      pv = await invoke("preview", { choices });
    } catch (e) {
      setStatus(`Can't preview: ${errorText(e)}`, true);
      return;
    }
    state.preview = pv;
    showPreview(pv);
  }

  function pathList(items) {
    return el("ul", { className: "path-list" }, ...items.map((i) => el("li", { text: `${i.path} (${bytes(i.bytes)})` })));
  }

  function showPreview(pv) {
    const box = $("preview-content");
    box.replaceChildren();
    const confirms = [];
    const clean = $("confirm-clean");
    const refresh = () => {
      clean.disabled = pv.empty || confirms.some((c) => !c.checked);
    };

    const table = el(
      "table",
      { className: "summary-table" },
      el(
        "thead",
        {},
        el(
          "tr",
          {},
          el("th", { text: "Action" }),
          el("th", { className: "num", text: "Items" }),
          el("th", { className: "num", text: "Size" }),
          el("th", { className: "num", text: "Space back now" }),
        ),
      ),
      el(
        "tbody",
        {},
        ...pv.actions.map((a) =>
          el(
            "tr",
            {},
            el("td", { text: ACTION_WORDS[a.action] }),
            el("td", { className: "num", text: a.items.length.toLocaleString() }),
            el("td", { className: "num", text: bytes(a.bytes) }),
            el("td", { className: "num", text: bytes(a.freedNow) }),
          ),
        ),
      ),
    );
    box.append(table);
    box.append(el("p", {}, "Space back now: ", el("strong", { text: bytes(pv.freedNow) })));

    const recycle = pv.actions.find((a) => a.action === "recycle");
    if (recycle) {
      box.append(
        el("p", {
          className: "callout",
          text: `${bytes(recycle.bytes)} go to the Recycle Bin. That space comes back only when you empty the bin (each drive's bin is on that drive).`,
        }),
      );
    }
    if (pv.moveTo && pv.actions.some((a) => a.action === "move")) {
      box.append(el("p", { text: `Moved items go to ${pv.moveTo}.` }));
    }
    if (pv.leftOut.length > 0) {
      box.append(
        el("h3", { text: `Left as they are (${pv.leftOut.length})` }),
        el("ul", { className: "path-list" }, ...pv.leftOut.map((l) => el("li", { text: `${l.path}: ${l.why}` }))),
      );
    }
    if (pv.empty) {
      box.append(el("p", { className: "error", text: "Nothing here can be cleaned. Go back and choose other items." }));
    }

    if (pv.confirmGreen) {
      const greens = pv.actions.flatMap((a) => a.items).filter((i) => i.tier === "green").length;
      const c = el("input", { type: "checkbox", id: "confirm-green", on: { change: refresh } });
      confirms.push(c);
      box.append(
        el(
          "label",
          { className: "confirm" },
          c,
          el("span", {
            text: `Clean the ${plural(greens, "green item")} as shown. Windows or the app rebuilds them.`,
          }),
        ),
      );
    }
    if (pv.confirmAmber.length > 0) {
      const c = el("input", { type: "checkbox", id: "confirm-amber", on: { change: refresh } });
      confirms.push(c);
      box.append(
        el(
          "div",
          { className: "confirm" },
          c,
          el(
            "div",
            {},
            el("label", {
              htmlFor: "confirm-amber",
              text:
                pv.confirmAmber.length === 1
                  ? "I checked this file of my own, and want it cleaned as shown:"
                  : `I checked these ${plural(pv.confirmAmber.length, "file")} of my own, and want them cleaned as shown:`,
            }),
            pathList(pv.confirmAmber),
          ),
        ),
      );
    }
    refresh();
    $("preview-dialog").showModal();
  }

  async function confirmClean() {
    const pv = state.preview;
    if (!pv) return;
    const clean = $("confirm-clean");
    clean.disabled = true;
    clean.textContent = "Cleaning…";
    setStatus("Cleaning… each item is checked again right before it is removed.");
    let done;
    try {
      done = await invoke("clean", { previewId: pv.id });
    } catch (e) {
      $("preview-dialog").close();
      setStatus(`Nothing was cleaned: ${errorText(e)}`, true);
      return;
    } finally {
      clean.textContent = "Clean now";
      state.preview = null;
    }
    $("preview-dialog").close();
    showResult(done);
  }

  function showResult(done) {
    const box = $("result-content");
    box.replaceChildren();
    box.append(el("p", {}, "Space back now: ", el("span", { className: "big-number", text: bytes(done.freedNow) })));
    if (done.recycled > 0) {
      box.append(
        el("p", {
          className: "callout",
          text: `${bytes(done.recycled)} are in the Recycle Bin. Empty it to get that space back, or restore anything from there.`,
        }),
      );
    }
    for (const a of done.actions) {
      const parts = [`${ACTION_WORDS[a.action]}: ${plural(a.removed, "item")} done`];
      if (a.bytesMoved > 0) parts.push(`${bytes(a.bytesMoved)} moved${done.moveTo ? ` to ${done.moveTo}` : ""}`);
      box.append(el("p", { text: parts.join(", ") }));
      const stayed = [...a.skipped, ...a.warnings];
      if (stayed.length > 0) {
        box.append(
          el("h3", { text: `Left in place (${stayed.length})` }),
          el("ul", { className: "path-list" }, ...stayed.map((s) => el("li", { text: `${s.path}: ${s.reason}` }))),
        );
      }
    }
    $("open-bin").hidden = done.recycled === 0;
    setStatus("Done. Scan again to see what is left.");
    $("result-dialog").showModal();
  }

  async function pickDestination() {
    try {
      const picked = await invoke("pick_move_destination");
      if (picked) {
        state.moveTo = picked;
        $("move-to-label").textContent = `Moves go to: ${picked}`;
      }
    } catch (e) {
      setStatus(`That folder can't be used: ${errorText(e)}`, true);
    }
  }

  // ---- Wiring ------------------------------------------------------------------------------

  $("scan").addEventListener("click", startScan);
  $("cancel").addEventListener("click", () => invoke("cancel_scan"));
  $("preview").addEventListener("click", openPreview);
  $("confirm-clean").addEventListener("click", confirmClean);
  $("pick-dest").addEventListener("click", pickDestination);
  $("open-bin").addEventListener("click", () =>
    invoke("open_recycle_bin").catch((e) => setStatus(errorText(e), true)),
  );
  $("result-dialog").addEventListener("close", () => {
    if ($("result-dialog").returnValue === "scan") startScan();
  });
  let filterTimer = 0;
  $("filter").addEventListener("input", (e) => {
    clearTimeout(filterTimer);
    filterTimer = setTimeout(() => {
      state.filter = e.target.value.trim().toLowerCase();
      render();
    }, 150);
  });
})();
