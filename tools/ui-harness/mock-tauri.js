// A fake `window.__TAURI__` for the UI harness: answers ByteBroom's seven commands with made-up
// findings, in the same shapes the Rust commands return (src-tauri/src/view.rs). Nothing is real:
// every path is invented, and "clean" only pretends.
//
// ?auto=scanning | hashing | done | preview | result   drives the window to that screen.
// ?many=1                                              lists 600 temp items (paging, speed).
"use strict";

(() => {
  const params = new URLSearchParams(location.search);
  const GB = 1024 ** 3;
  const MB = 1024 ** 2;
  const DAY = 86400;
  const now = Math.floor(Date.now() / 1000);
  const P = "C:\\Users\\Sam";
  const L = `${P}\\AppData\\Local`;

  let scan = 0;
  let version = 0;
  let phase = "idle";
  let started = 0;
  let findings = [];
  let moveTo = null;
  let previews = 0;
  let lastPreview = null;
  const hold = params.get("auto") === "scanning" || params.get("auto") === "hashing";

  function f(rule, label, tier, path, bytes, extra = {}) {
    return {
      rule,
      label,
      tier,
      path,
      name: path.split("\\").pop(),
      bytes,
      files: 1,
      newest: now - 40 * DAY,
      isFolder: false,
      cloud: false,
      preTicked: tier === "green",
      duplicateOf: null,
      notOffered: null,
      note: null,
      ...extra,
    };
  }

  function firstStep() {
    const list = [
      f("user-temp", "User temp files", "green", `${L}\\Temp\\setup-logs`, 412 * MB, { isFolder: true, files: 1840 }),
      f("user-temp", "User temp files", "green", `${L}\\Temp\\chrome_installer.log`, 3 * MB),
      f("user-temp", "User temp files", "green", `${L}\\Temp\\{6F2A1C3B-unpacked}`, 1.3 * GB, { isFolder: true, files: 212 }),
      f("crash-dumps", "Crash dumps", "green", `${L}\\CrashDumps\\Explorer.EXE.10432.dmp`, 287 * MB),
      f("thumbnail-cache", "Thumbnail and icon cache", "green", `${L}\\Microsoft\\Windows\\Explorer\\thumbcache_256.db`, 96 * MB),
      f("browser-caches", "Browser caches", "green", `${L}\\Google\\Chrome\\User Data\\Default\\Cache\\Cache_Data`, 640 * MB, { isFolder: true, files: 9120 }),
      f("shader-cache", "DirectX shader cache", "green", `${L}\\D3DSCache\\5b1e2f`, 54 * MB, { isFolder: true, files: 31 }),
      f("large-files", "Large files", "amber", "D:\\VMs\\Ubuntu\\Ubuntu-disk1.vmdk", 38 * GB, {
        note: "virtual machine disk: deleting it removes the VM (moving it is safer)",
      }),
      f("large-files", "Large files", "amber", `${P}\\Videos\\holiday-2019-raw.mov`, 7.4 * GB),
      f("large-files", "Large files", "amber", `${P}\\OneDrive\\Backups\\photos-2021.zip`, 5.1 * GB, {
        cloud: true,
        notOffered: "cloud file (OneDrive): not on this disk, so not offered",
      }),
      f("large-files", "Large files", "amber", "D:\\Video.vkl", 2.2 * GB, { notOffered: "can't be cleaned here" }),
      f("old-installers", "Old installers", "amber", `${P}\\Downloads\\VSCodeUserSetup-x64-1.80.0.exe`, 92 * MB),
      f("old-installers", "Old installers", "amber", `${P}\\Downloads\\node-v18.12.0-x64.msi`, 30 * MB),
      f("developer-caches", "Developer caches", "amber", `${L}\\npm-cache\\_cacache`, 1.9 * GB, { isFolder: true, files: 40211 }),
      f("build-folders", "Build folders in code projects", "amber", `${P}\\Sources\\old-game\\target`, 3.6 * GB, { isFolder: true, files: 18422 }),
    ];
    if (params.get("many")) {
      for (let i = 0; i < 600; i++) {
        list.splice(2, 0, f("user-temp", "User temp files", "green", `${L}\\Temp\\tmp${(1000 + i).toString(16)}.tmp`, (i % 37) * 41 * 1024 + 900));
      }
    }
    return list;
  }

  function duplicates() {
    return [
      f("duplicates", "Duplicates", "amber", `${P}\\Desktop\\IMG_2044 (1).jpg`, 6 * MB, { duplicateOf: `${P}\\Pictures\\2023\\IMG_2044.jpg` }),
      f("duplicates", "Duplicates", "amber", `${P}\\Documents\\tax-2022 copy.pdf`, 2 * MB, { duplicateOf: `${P}\\Documents\\Taxes\\tax-2022.pdf` }),
    ];
  }

  const red = [
    { label: "Recycle Bin", size: "1.2 GB", bytes: 1.2 * GB },
    { label: "Hibernation file", size: "6.4 GB", bytes: 6.4 * GB },
    { label: "Page file", size: "needs admin", bytes: null },
    { label: "Previous Windows installation", size: "not present", bytes: null },
    { label: "Windows Update store", size: "at least 3.1 GB", bytes: 3.1 * GB },
  ];

  function withIds(list) {
    return list.map((x, index) => ({ ...x, id: { scan, index }, bytes: Math.round(x.bytes) }));
  }

  function tick() {
    if (hold) {
      if (params.get("auto") === "hashing" && phase === "scanning" && Date.now() - started > 600) {
        findings = withIds(firstStep());
        version++;
        phase = "hashing";
      }
      return;
    }
    const t = Date.now() - started;
    if (phase === "scanning" && t > 900) {
      findings = withIds(firstStep());
      version++;
      phase = "hashing";
    } else if (phase === "hashing" && t > 2000) {
      findings = withIds([...firstStep(), ...duplicates()]);
      version++;
      phase = "done";
    }
  }

  const ACT = { Delete: "delete", Recycle: "recycle", Move: "move" };

  function preview({ choices }) {
    if (phase === "scanning" || phase === "hashing") throw new Error("wait for the scan to finish, or stop it");
    if (choices.length === 0) throw new Error("nothing is chosen");
    if (choices.some((c) => c.action === "Move") && !moveTo) throw new Error("choose a folder on another drive to move to");
    const groups = new Map();
    const leftOut = [];
    for (const c of choices) {
      if (c.finding.scan !== scan) throw new Error("that item is from an earlier scan; scan again");
      const x = findings[c.finding.index];
      if (!x) throw new Error("that item is not in the scan");
      const item = { id: x.id, path: x.path, bytes: x.bytes, tier: x.tier };
      if (x.notOffered) {
        leftOut.push({ id: x.id, path: x.path, why: x.notOffered });
        continue;
      }
      const a = ACT[c.action];
      if (!groups.has(a)) groups.set(a, []);
      groups.get(a).push(item);
    }
    const actions = ["delete", "move", "recycle"]
      .filter((a) => groups.has(a))
      .map((a) => {
        const items = groups.get(a);
        const sum = items.reduce((s, i) => s + i.bytes, 0);
        return {
          action: a,
          items,
          targets: items.length,
          bytes: sum,
          freedNow: a === "recycle" ? 0 : sum,
          freedAfterEmptyingBin: a === "recycle" ? sum : 0,
        };
      });
    previews++;
    const all = actions.flatMap((a) => a.items);
    lastPreview = {
      id: { scan, number: previews },
      actions,
      confirmGreen: all.some((i) => i.tier === "green"),
      confirmAmber: all.filter((i) => i.tier === "amber"),
      leftOut,
      moveTo,
      freedNow: actions.reduce((s, a) => s + a.freedNow, 0),
      empty: all.length === 0,
    };
    return lastPreview;
  }

  function clean({ previewId }) {
    const pv = lastPreview;
    if (!pv || pv.id.number !== previewId.number || pv.id.scan !== previewId.scan) {
      throw new Error("that preview is out of date; preview again");
    }
    lastPreview = null;
    const actions = pv.actions.map((a, n) => {
      const skipped =
        n === 0 && a.items.length > 1
          ? [{ path: a.items[0].path, reason: "in use by another program" }]
          : [];
      const doneBytes = a.items.slice(skipped.length).reduce((s, i) => s + i.bytes, 0);
      return {
        action: a.action,
        removed: a.items.length - skipped.length,
        // As the engine: a move to another drive counts as freed and as moved.
        bytesFreed: a.action === "delete" || a.action === "move" ? doneBytes : 0,
        bytesRecycled: a.action === "recycle" ? doneBytes : 0,
        bytesMoved: a.action === "move" ? doneBytes : 0,
        skipped,
        warnings: [],
      };
    });
    return {
      actions,
      freedNow: actions.reduce((s, a) => s + a.bytesFreed, 0),
      recycled: actions.reduce((s, a) => s + a.bytesRecycled, 0),
      moveTo: pv.moveTo,
    };
  }

  // Fake history (phase 5): made-up names only.
  const day = DAY;
  const moved = (item, name, bytes, extra = {}) => ({
    item,
    name,
    from: `C:\\Users\\Test\\Downloads\\${name}`,
    to: `E:\\Archive\\${name}`,
    bytes,
    putBackAt: null,
    unavailable: null,
    ...extra,
  });
  let fakeMoves = [
    {
      group: 0,
      when: now - day,
      items: [
        moved(0, "holiday-video-2019.mkv", 4.2 * 1024 ** 3),
        moved(1, "old-backup.zip", 812 * 1024 ** 2),
        moved(2, "a-very-long-file-name-that-goes-on-and-on-to-test-wrapping-in-the-history.iso", 3.1 * 1024 ** 3),
      ],
    },
    {
      group: 1,
      when: now - 9 * day,
      items: [
        moved(0, "installer-2021.exe", 96 * 1024 ** 2, { putBackAt: now - 8 * day }),
        moved(1, "disk-image.vhdx", 20 * 1024 ** 3, { unavailable: "the moved file isn't there (is its drive plugged in?)" }),
      ],
    },
  ];
  let fakeRecycled = [
    { when: now - day, name: "setup-old.msi", original: "C:\\Users\\Test\\Downloads\\setup-old.msi", bytes: 64 * 1024 ** 2 },
    { when: now - 3 * day, name: "notes-copy (2).txt", original: "C:\\Users\\Test\\Documents\\notes-copy (2).txt", bytes: 2048 },
  ];
  let historyList = 0;
  function historyView() {
    historyList++;
    fakeMoves.forEach((g, i) => (g.group = i));
    for (const g of fakeMoves) g.canPutBack = g.items.filter((m) => m.putBackAt === null && !m.unavailable).length;
    return { list: historyList, moves: fakeMoves, recycled: fakeRecycled };
  }

  const commands = {
    start_scan() {
      scan++;
      version++;
      phase = "scanning";
      started = Date.now();
      findings = [];
      lastPreview = null;
      return null;
    },
    cancel_scan() {
      if (phase === "scanning" || phase === "hashing") phase = "cancelled";
      return null;
    },
    scan_state({ seen }) {
      tick();
      const view = {
        scan,
        phase,
        version,
        elapsedMs: phase === "idle" ? 0 : Math.min(Date.now() - started, 2000),
        items: findings.length,
        bytes: findings.reduce((s, x) => s + x.bytes, 0),
        findings: seen !== version ? findings : null,
        red: phase === "scanning" ? null : red,
        skipped: [{ location: "Downloads", why: "it is a link to another folder" }],
      };
      return view;
    },
    preview,
    clean,
    pick_move_destination() {
      moveTo = "E:\\Archive";
      return moveTo;
    },
    open_recycle_bin() {
      return null;
    },
    // Fake history shaped like view::HistoryView; nothing real is read or moved.
    history() {
      return historyView();
    },
    put_back({ which }) {
      if (which.list !== historyList) throw { message: "the history changed: look at it again, then choose" };
      const g = fakeMoves[which.group];
      const items = which.item === null ? g.items.filter((m) => m.putBackAt === null && !m.unavailable) : [g.items[which.item]];
      for (const m of items) m.putBackAt = Math.floor(Date.now() / 1000);
      const message =
        items.length === 1 ? `${items[0].name} is back where it was.` : `Put back ${items.length} of ${items.length} files.`;
      return { message, history: historyView() };
    },
    clear_history() {
      fakeMoves = [];
      fakeRecycled = [];
      return historyView();
    },
    // Fake texts shaped like bytebroom_core::red_actions; nothing real is touched.
    red_actions() {
      const note =
        "A restore point is made first (or one from the last 24 hours is used); without one, nothing is changed.";
      return [
        {
          id: "RecycleBin",
          title: "Empty the Recycle Bin",
          frees: "Frees the space the Recycle Bin uses on every drive.",
          undo: "Can't be undone: the files are gone for good.",
          confirmWord: "recycle bin",
          restoreNote: null,
          needsAdmin: false,
        },
        {
          id: "DeliveryOptimization",
          title: "Clear the Delivery Optimization cache",
          frees: "Frees Windows' cache of update downloads shared with other PCs; pinned files are kept.",
          undo: "Can't be undone; Windows downloads again what it needs.",
          confirmWord: "delivery optimization",
          restoreNote: note,
          needsAdmin: true,
        },
        {
          id: "Hibernation",
          title: "Turn hibernation off",
          frees: "Frees hiberfil.sys. Hibernate and Hybrid Sleep stop working until you turn it back on.",
          undo: "Undo: run powercfg /hibernate on in an administrator PowerShell.",
          confirmWord: "hibernation",
          restoreNote: note,
          needsAdmin: true,
        },
      ];
    },
    run_red_action({ action }) {
      if (action === "Hibernation") throw new Error("Cancelled at the Windows prompt: nothing was changed.");
      return { message: `${action}: done.`, red };
    },
  };

  window.__TAURI__ = {
    core: {
      invoke(cmd, args = {}) {
        return new Promise((resolve, reject) => {
          setTimeout(() => {
            try {
              if (!commands[cmd]) throw new Error(`unknown command ${cmd}`);
              resolve(commands[cmd](args));
            } catch (e) {
              reject(e.message);
            }
          }, 40);
        });
      },
    },
  };

  // ?auto=... : click through to a screen once the page is ready.
  const auto = params.get("auto");
  if (!auto) return;
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  const click = (id) => document.getElementById(id).click();
  window.addEventListener("DOMContentLoaded", async () => {
    await wait(50);
    click("scan");
    if (auto === "scanning" || auto === "hashing") return;
    await wait(2600);
    // Open the first category of each tier, as the owner would.
    for (const d of document.querySelectorAll("details.category")) {
      if (d === d.parentElement.firstElementChild) d.open = true;
    }
    // Rows are drawn when a category opens (the toggle event comes a moment later).
    await wait(200);
    if (auto === "done") return;
    // Choose an amber item too, so both confirmations show.
    const amberBox = document.querySelector("#amber-list .row input[type=checkbox]:not(:disabled)");
    if (amberBox) amberBox.click();
    await wait(100);
    click("preview");
    await wait(300);
    if (auto === "preview") return;
    for (const c of document.querySelectorAll("#preview-content input[type=checkbox]")) c.click();
    click("confirm-clean");
  });
})();
