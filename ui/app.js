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

  /** Show a status line. `quiet` updates only the visible line (a scan's ticking seconds), so a
   * screen reader hears each stage once instead of every half second. */
  function setStatus(text, isError = false, quiet = false) {
    const s = $("status");
    s.textContent = text;
    s.classList.toggle("error", isError);
    if (!quiet) $("announce").textContent = isError ? `Error: ${text}` : text;
  }

  // The lists are redrawn on every tick and scan update. Each control carries a data-focus key,
  // so keyboard focus comes back to the same control on the redrawn list (WCAG 2.4.3).
  function focusKey() {
    const a = document.activeElement;
    return a && a.dataset ? a.dataset.focus : undefined;
  }

  function refocus(k) {
    if (!k) return;
    for (const node of document.querySelectorAll("[data-focus]")) {
      if (node.dataset.focus === k) {
        node.focus({ preventScroll: true });
        return;
      }
    }
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
    // A button that is disabled or hidden while focused drops keyboard focus to the page: hand it
    // to the button that takes its place.
    const from = document.activeElement;
    $("scan").disabled = running;
    $("cancel").hidden = !running;
    if (running && from === $("scan")) $("cancel").focus();
    if (!running && from === $("cancel")) $("scan").focus();
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
    const newStage = v.phase !== state.phase;
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
    setStatus(text, false, !newStage);
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
    const focused = focusKey();
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
    refocus(focused);
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
      attrs: { "aria-label": `Choose every item in ${group.label}`, "data-focus": `cat:${rule}` },
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
        { attrs: { "data-focus": `sum:${rule}` } },
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
              attrs: { "data-focus": `more:${rule}` },
              on: {
                click: () => {
                  state.shown.set(rule, limit + ROWS_PER_PAGE);
                  fill();
                  // The button is redrawn: put focus on the first new row a key can reach.
                  const next = [...rows.children]
                    .slice(limit)
                    .map((r) => r.querySelector("input:not(:disabled), select:not(:disabled), button"))
                    .find(Boolean);
                  if (next) next.focus();
                },
              },
            }),
          ),
        );
      }
    };
    if (details.open) fill();
    details.addEventListener("toggle", () => {
      // A list drawn already open fires a toggle of its own a moment later. Its rows are already
      // drawn: refilling them would drop keyboard focus from the row just ticked, and if two
      // redraws came first, redrawing for a list that is gone would set off the next one's,
      // endlessly. A toggle that changes nothing is that one: ignore it.
      if (details.open === state.open.has(rule)) return;
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
    // The tick also reads out the full path and any tag (why it can't be chosen, a warning), so
    // rows with the same name can be told apart without colour or position.
    const uid = `${f.id.scan}-${f.id.index}`;
    const tags = [];
    if (f.notOffered) tags.push(el("span", { className: "tag off", text: f.notOffered }));
    if (f.note) tags.push(el("span", { className: "tag", text: f.note }));
    if (f.duplicateOf) {
      tags.push(el("span", { className: "tag off", text: `copy of ${f.duplicateOf}` }));
    }
    tags.forEach((t, i) => {
      t.id = `tag-${uid}-${i}`;
    });
    const described = [`path-${uid}`, ...tags.map((t) => t.id)].join(" ");
    const tick = el("input", {
      type: "checkbox",
      checked: c.on && !off,
      disabled: off,
      attrs: { "aria-label": `Choose ${label}`, "aria-describedby": described, "data-focus": `tick:${key(f.id)}` },
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
        attrs: { "aria-label": `Action for ${label}`, "data-focus": `act:${key(f.id)}` },
        on: {
          change: (e) => {
            c.action = e.target.value;
          },
        },
      },
      ...ACTIONS.map(([value, text]) => el("option", { value, text, selected: c.action === value })),
    );
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
        el("span", { className: "item-path", id: `path-${uid}`, text: f.path, title: f.path }),
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

  // ---- Red-tier actions (phase 4) ----------------------------------------------------------
  // The page sends only a fixed action name. Typing the word is the page's own check (decision
  // 7); Rust then asks natively (Windows' dialog, or the UAC prompt) before anything happens.

  let redBusy = false;

  function renderRedActions(actions) {
    const box = $("red-actions");
    box.replaceChildren();
    for (const a of actions) {
      const inputId = `confirm-${a.id}`;
      const helpId = `help-${a.id}`;
      const input = el("input", {
        id: inputId,
        type: "text",
        autocomplete: "off",
        spellcheck: false,
        attrs: { "aria-describedby": helpId, "data-focus": `red-input-${a.id}` },
      });
      const button = el("button", {
        type: "button",
        className: "danger",
        text: a.title,
        disabled: true,
        attrs: { "data-focus": `red-run-${a.id}` },
      });
      const matches = () => input.value.trim().toLowerCase() === a.confirmWord;
      input.addEventListener("input", () => {
        button.disabled = redBusy || !matches();
      });
      button.addEventListener("click", () => {
        if (matches()) runRedAction(a, input, button);
      });
      box.append(
        el(
          "div",
          { className: "red-action", attrs: { role: "group", "aria-labelledby": `title-${a.id}` } },
          el("h4", { id: `title-${a.id}`, text: a.title }),
          // One line each for what it frees, the undo, the restore note and the admin prompt, so
          // none of them is lost in a block of text. The same words as before, all still the
          // input's description.
          el(
            "div",
            { id: helpId, className: "red-action-text" },
            el("p", { text: a.frees }),
            el("p", { className: "red-action-undo", text: a.undo }),
            a.restoreNote ? el("p", { text: a.restoreNote }) : null,
            a.needsAdmin
              ? el("p", { className: "red-action-admin", text: "Windows will ask for administrator rights." })
              : null,
          ),
          el(
            "div",
            { className: "red-action-row" },
            el("label", { htmlFor: inputId, text: `Type "${a.confirmWord}" to confirm` }),
            input,
            button,
          ),
          // The result, visible next to the card (the status line at the top may be scrolled
          // away). Not a live region: setStatus already announces it once.
          el("p", { id: `result-${a.id}`, className: "red-action-result", hidden: true }),
        ),
      );
    }
  }

  async function runRedAction(a, input, button) {
    redBusy = true;
    for (const b of $("red-actions").querySelectorAll("button")) b.disabled = true;
    const shown = $(`result-${a.id}`);
    const show = (text, isError = false) => {
      setStatus(text, isError);
      shown.textContent = text;
      shown.classList.toggle("error", isError);
      shown.hidden = false;
    };
    show(
      a.needsAdmin
        ? `${a.title}: answer the Windows prompt. A restore point comes first; this can take a few minutes.`
        : `${a.title}: answer the Windows dialog.`,
    );
    try {
      const result = await invoke("run_red_action", { action: a.id });
      renderRed(result.red);
      show(`${result.message} Sizes measured again.`);
    } catch (e) {
      show(errorText(e), true);
    } finally {
      redBusy = false;
      input.value = "";
      button.disabled = true;
      input.focus();
    }
  }

  invoke("red_actions")
    .then(renderRedActions)
    .catch((e) => setStatus(errorText(e), true));

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
    if (done.actions.some((a) => a.action === "move" && a.removed > 0)) {
      box.append(el("p", { className: "note", text: "Moved files can be put back from History." }));
    }
    if (done.historyNote) box.append(el("p", { className: "error", text: done.historyNote }));
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

  // ---- History (phase 5) -------------------------------------------------------------------
  // The page sends only the list's number and places in it: never a path. Rust re-reads the
  // journal and checks both ends on disk before putting anything back.

  let history = null;
  let historyBusy = false;

  /** Ask a yes/no question in the page's own dialog (decision 4: no Windows dialog for undo). */
  // `tone` only colours the yes button: red for a loss (clearing), the calm accent for a put back.
  function ask(title, lines, yes, tone = "danger") {
    return new Promise((resolve) => {
      const d = $("ask-dialog");
      $("ask-h").textContent = title;
      $("ask-content").replaceChildren(...lines.map((l) => (typeof l === "string" ? el("p", { text: l }) : l)));
      $("ask-yes").textContent = yes;
      $("ask-yes").className = tone;
      d.returnValue = "";
      d.addEventListener("close", () => resolve(d.returnValue === "yes"), { once: true });
      d.showModal();
    });
  }

  /** Show a result in the History dialog. The main status line is updated quietly (it is outside
   * the modal dialog, so a screen reader can't hear it); `announce` reads it from the dialog's own
   * live region, once. Pass false when focus is about to land on the line itself. */
  function showHistoryResult(text, isError = false, announce = true) {
    const p = $("history-result");
    p.textContent = text;
    p.classList.toggle("error", isError);
    p.hidden = false;
    setStatus(text.split("\n")[0], isError, true);
    if (announce) announceHistory();
  }

  function announceHistory() {
    const p = $("history-result");
    $("history-announce").textContent = p.classList.contains("error") ? `Error: ${p.textContent}` : p.textContent;
  }

  const putBackButtons = () => [...$("history-content").querySelectorAll("button[data-focus^='item-']")];

  async function openHistory() {
    $("history-result").hidden = true;
    $("history-announce").textContent = "";
    try {
      history = await invoke("history");
    } catch (e) {
      setStatus(errorText(e), true);
      return;
    }
    renderHistory();
    $("history-dialog").showModal();
  }

  function renderHistory() {
    const box = $("history-content");
    const back = focusKey();
    box.replaceChildren();
    const h = history;
    box.append(el("h3", { text: "Moved files" }));
    if (h.moves.length === 0) {
      box.append(el("p", { className: "note", text: "Nothing has been moved." }));
    }
    for (const g of h.moves) {
      const still = g.items.filter((m) => m.putBackAt === null);
      const head = el(
        "div",
        { className: "history-group-head" },
        el("h4", {
          text: `${date(g.when)}: ${plural(g.items.length, "file")} moved${
            still.length === 0 ? ", all put back" : still.length < g.items.length ? `, ${still.length} still moved` : ""
          }`,
        }),
      );
      if (g.canPutBack > 1) {
        head.append(
          el("button", {
            type: "button",
            text: `Put back all ${g.canPutBack}…`,
            disabled: historyBusy,
            attrs: { "data-focus": `group-${g.group}` },
            on: { click: () => putBack(g, null) },
          }),
        );
      }
      const list = el("ul", { className: "history-list" });
      for (const m of g.items) {
        let state;
        if (m.putBackAt !== null) {
          state = el("span", { className: "history-state done", text: `Put back ${date(m.putBackAt)}` });
        } else if (m.unavailable) {
          state = el("span", { className: "history-state blocked", text: `Can't put back: ${m.unavailable}` });
        } else {
          state = el("button", {
            type: "button",
            text: "Put back…",
            disabled: historyBusy,
            attrs: { "data-focus": `item-${g.group}-${m.item}`, "aria-label": `Put back ${m.name}` },
            on: { click: () => putBack(g, m) },
          });
        }
        list.append(
          el(
            "li",
            {},
            el(
              "div",
              { className: "history-item" },
              el("strong", { text: m.name }),
              el("span", { className: "num", text: bytes(m.bytes) }),
              state,
            ),
            el("div", { className: "history-paths", text: `From ${m.from}` }),
            el("div", { className: "history-paths", text: `Now in ${m.to}` }),
          ),
        );
      }
      box.append(el("section", { className: "history-group" }, head, list));
    }

    box.append(el("h3", { text: "Sent to the Recycle Bin" }));
    if (h.recycled.length === 0) {
      box.append(el("p", { className: "note", text: "Nothing has been sent to the Recycle Bin." }));
    } else {
      box.append(
        el(
          "p",
          { className: "history-bin" },
          "Restore these from the Recycle Bin itself (select, then Restore). ",
          el("button", {
            type: "button",
            text: "Open the Recycle Bin",
            attrs: { "data-focus": "open-bin-history" },
            on: { click: () => invoke("open_recycle_bin").catch((e) => showHistoryResult(errorText(e), true)) },
          }),
        ),
        el(
          "ul",
          { className: "history-list history-recycled" },
          ...h.recycled.map((r) =>
            el(
              "li",
              {},
              el(
                "div",
                { className: "history-item" },
                el("strong", { text: r.name }),
                el("span", { className: "num", text: bytes(r.bytes) }),
                el("span", { className: "history-state", text: date(r.when) }),
              ),
              el("div", { className: "history-paths", text: `From ${r.original}` }),
            ),
          ),
        ),
      );
    }
    $("clear-history").disabled = historyBusy || (h.moves.length === 0 && h.recycled.length === 0);
    refocus(back);
  }

  async function putBack(group, item) {
    if (historyBusy) return;
    const files = item ? [item] : group.items.filter((m) => m.putBackAt === null && !m.unavailable);
    const ok = await ask(
      item ? `Put back ${item.name}?` : `Put back ${plural(files.length, "file")}?`,
      [
        item
          ? `It goes back to ${item.from}.`
          : "Each goes back to where it was:",
        item ? null : el("ul", { className: "path-list" }, ...files.map((m) => el("li", { text: m.from }))),
        "Each file is copied back and checked; the moved copy is removed only after the copy matches. Nothing already at the original place is replaced.",
      ].filter((l) => l !== null),
      "Put back",
      "primary",
    );
    if (!ok) return;
    // Where the clicked row sat among the Put back buttons, so focus can go to the next one.
    const prefix = item ? `item-${group.group}-${item.item}` : `item-${group.group}-`;
    const at = Math.max(0, putBackButtons().findIndex((b) => b.dataset.focus.startsWith(prefix)));
    historyBusy = true;
    renderHistory();
    // The buttons are disabled while it runs: focus waits on the progress line, which it reads.
    showHistoryResult("Putting back… each file is checked before the moved copy is removed.", false, false);
    $("history-result").focus();
    try {
      const done = await invoke("put_back", {
        which: { list: history.list, group: group.group, item: item ? item.item : null },
      });
      history = done.history;
      showHistoryResult(done.message, done.message.includes("\n") || done.message.includes("was not"), false);
    } catch (e) {
      showHistoryResult(errorText(e), true, false);
    } finally {
      historyBusy = false;
      renderHistory();
      // Focus goes to the next Put back button (or stays on the result line if none is left),
      // then the result is announced once, after the focus move so it isn't cut off.
      const left = putBackButtons();
      if (left.length > 0) left[Math.min(at, left.length - 1)].focus();
      announceHistory();
    }
  }

  async function clearHistory() {
    const ok = await ask(
      "Clear the history?",
      [
        "ByteBroom forgets what it moved and recycled. The files themselves stay exactly where they are.",
        "Moved files can then no longer be put back from ByteBroom; you would move them back by hand. Recycled items stay in the Recycle Bin.",
      ],
      "Clear history",
    );
    if (!ok) return;
    historyBusy = true;
    try {
      history = await invoke("clear_history");
      showHistoryResult("History cleared. No file was touched.", false, false);
    } catch (e) {
      showHistoryResult(errorText(e), true, false);
    } finally {
      historyBusy = false;
      renderHistory();
      // Clear history… is disabled once nothing is left, so focus moves to the result line,
      // which reads it; otherwise focus stays on the button and the result is announced. Once.
      if ($("clear-history").disabled) $("history-result").focus();
      else announceHistory();
    }
  }

  // ---- Browser behaviour this window doesn't have ---------------------------------------------
  // It is an app, not a web page: no browser menu (Back, Refresh, Save as, Print) and no reload,
  // print or find keys, which would wipe the list and ticks mid-task. The filter box keeps its
  // own menu (cut, copy, paste). Owner's real test, phase 3.
  document.addEventListener("contextmenu", (e) => {
    if (!(e.target instanceof HTMLInputElement && e.target.type !== "checkbox")) e.preventDefault();
  });
  document.addEventListener("keydown", (e) => {
    const k = e.key.toLowerCase();
    const ctrl = e.ctrlKey || e.metaKey;
    const blocked =
      k === "f5" ||
      k === "browserrefresh" ||
      (ctrl && ["r", "p", "s", "f", "g", "u", "j"].includes(k)) ||
      (ctrl && e.shiftKey && ["i", "c"].includes(k)) ||
      (e.altKey && (k === "arrowleft" || k === "arrowright")) ||
      k === "browserback" ||
      k === "browserforward";
    if (blocked) e.preventDefault();
  });

  // ---- Wiring ------------------------------------------------------------------------------

  $("scan").addEventListener("click", startScan);
  $("cancel").addEventListener("click", () => invoke("cancel_scan"));
  $("preview").addEventListener("click", openPreview);
  $("confirm-clean").addEventListener("click", confirmClean);
  $("pick-dest").addEventListener("click", pickDestination);
  $("open-history").addEventListener("click", openHistory);
  $("clear-history").addEventListener("click", clearHistory);
  $("history-dialog").addEventListener("close", () => $("open-history").focus());
  $("open-bin").addEventListener("click", () =>
    invoke("open_recycle_bin").catch((e) => setStatus(errorText(e), true)),
  );
  // When a dialog closes, keyboard focus goes back to the button that leads on (WCAG 2.4.3),
  // not to the top of the page. Focus only: what closing does is unchanged.
  $("preview-dialog").addEventListener("close", () => {
    if (!$("preview").disabled) $("preview").focus();
  });
  $("result-dialog").addEventListener("close", () => {
    $("scan").focus();
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
