"use strict";

const CONFIG_DIR = "/data/adb/modules/inline_hook_invalidate";
const CONFIG_FILE = CONFIG_DIR + "/config.txt";
const APP_INDEX_FILE = CONFIG_DIR + "/.appindex.json";
const INDEXER_CLASS = "com.obbedcode.inlinehookinvalidate.pm.AppIndexer";
const DEFAULT_LIBRARY_NAME = "libart.so";
const PROTECTED_PACKAGES = ["com.obbedcode.inlinehookinvalidate", "com.obbedcode.inlinehookinvalidate.webui"];

let callbackSequence = 0;
let pendingConfigWrite = Promise.resolve();

function moduleDir() {
    try {
        if (typeof ksu !== "undefined" && ksu.moduleInfo) {
            const info = JSON.parse(ksu.moduleInfo());
            if (info && info.moduleDir) return info.moduleDir;
        }
    } catch (error) {}
    return CONFIG_DIR;
}

function exec(command, options = {}) {
    return new Promise((resolve) => {
        if (typeof ksu === "undefined" || !ksu.exec) {
            resolve({ errno: -1, stdout: "", stderr: "no root bridge" });
            return;
        }
        const callbackName = "__iahs_cb_" + callbackSequence++;
        window[callbackName] = (errno, stdout, stderr) => {
            delete window[callbackName];
            resolve({ errno, stdout: stdout || "", stderr: stderr || "" });
        };
        try {
            ksu.exec(command, JSON.stringify(options), callbackName);
        } catch (bridgeError) {
            delete window[callbackName];
            try {
                resolve({ errno: 0, stdout: ksu.exec(command), stderr: "" });
            } catch (syncError) {
                resolve({ errno: 1, stdout: "", stderr: String(syncError) });
            }
        }
    });
}

function toast(message) {
    const node = document.getElementById("toast");
    node.textContent = message;
    node.classList.remove("hidden");
    requestAnimationFrame(() => node.classList.add("show"));
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => {
        node.classList.remove("show");
        setTimeout(() => node.classList.add("hidden"), 220);
    }, 2200);
}

const DEFAULT_METHOD = "mmap-once";

const state = {
    enabled: false,
    libraryName: DEFAULT_LIBRARY_NAME,
    method: DEFAULT_METHOD,
    targetPackages: new Set(),
    apps: [],
    search: ""
};

function parseConfig(text) {
    const lines = (text || "").split("\n").map((line) => line.replace(/\r$/, ""));
    const result = { enabled: false, libraryName: DEFAULT_LIBRARY_NAME, method: DEFAULT_METHOD, targetPackages: new Set() };
    if (lines.length > 0 && lines[0].trim().length > 0) {
        const parts = lines[0].split(":");
        result.enabled = (parts[0] || "").trim() === "1";
        if (parts.length >= 2 && parts[1].trim()) result.libraryName = parts[1].trim();
        const savedMethod = parts[2] || "mmap";
        if (["mmap", "mmap-once", "pread"].includes(savedMethod)) result.method = savedMethod;
    }
    for (let index = 1; index < lines.length; index++) {
        const packageName = lines[index].trim();
        if (packageName) result.targetPackages.add(packageName);
    }
    return result;
}

function serializeConfig() {
    const lines = [(state.enabled ? "1" : "0") + ":" + state.libraryName + ":" + state.method];
    for (const packageName of state.targetPackages) lines.push(packageName);
    return lines.join("\n") + "\n";
}

function setActiveMethodSegment(method) {
    const segments = document.querySelectorAll("#settingsMethodSegment .segment");
    segments.forEach((segment) => segment.classList.toggle("is-active", segment.dataset.method === method));
}

async function persistConfig() {
    const encoded = btoa(serializeConfig());
    const command = "umask 077; tmp=$(mktemp " + CONFIG_DIR + "/.config.XXXXXX) || exit 1; "
        + "trap 'rm -f \"$tmp\"' EXIT; "
        + "printf '%s' '" + encoded + "' | base64 -d > \"$tmp\" && mv -f \"$tmp\" " + CONFIG_FILE;
    const write = pendingConfigWrite.then(() => exec(command));
    pendingConfigWrite = write.catch(() => {});
    const result = await write;
    if (result.errno !== 0) {
        toast("Failed to write config: " + (result.stderr || "errno " + result.errno));
        return false;
    }
    return true;
}

function updateStatusSubtitle() {
    const subtitle = document.getElementById("statusSubtitle");
    subtitle.classList.toggle("is-enabled", state.enabled);
    subtitle.textContent = state.enabled
        ? "Enabled · " + state.libraryName + " · " + state.method + " · " + state.targetPackages.size + " target(s)"
        : "Disabled";
}

async function ensureAppIndex(force) {
    if (!force) {
        const check = await exec("[ -f " + APP_INDEX_FILE + " ] && echo 1 || echo 0");
        if (check.stdout.trim() === "1") return;
    }
    const apkPath = moduleDir() + "/service.apk";
    const command = "app_process -Djava.class.path=" + apkPath + " / " + INDEXER_CLASS + " --icons --out " + APP_INDEX_FILE;
    await exec("mkdir -p " + CONFIG_DIR);
    await exec(command);
}

async function loadEverything(forceReindex) {
    if (typeof ksu === "undefined" || !ksu.exec) {
        setEmpty("Open this page from your root manager (WebUI) — the root bridge is unavailable here.");
        return;
    }

    await ensureAppIndex(!!forceReindex);

    const [indexResult, configResult] = await Promise.all([
        exec("cat " + APP_INDEX_FILE + " 2>/dev/null"),
        exec("cat " + CONFIG_FILE + " 2>/dev/null")
    ]);

    let index = [];
    try {
        index = JSON.parse(indexResult.stdout || "[]");
    } catch (error) {
        index = [];
    }

    const parsed = parseConfig(configResult.stdout);
    state.enabled = parsed.enabled;
    state.libraryName = parsed.libraryName;
    state.method = parsed.method;
    state.targetPackages = parsed.targetPackages;

    state.apps = index
        .filter((item) => PROTECTED_PACKAGES.indexOf(item.pkg) === -1)
        .map((item) => ({
            packageName: item.pkg,
            label: item.label || item.pkg,
            system: !!item.system,
            icon: item.icon || null
        }));

    document.getElementById("settingsEnabledToggle").checked = state.enabled;
    document.getElementById("settingsLibraryInput").value = state.libraryName;
    setActiveMethodSegment(state.method);
    updateStatusSubtitle();
    render();
}

function setEmpty(text) {
    const list = document.getElementById("appList");
    const empty = document.getElementById("emptyState");
    list.innerHTML = "";
    document.getElementById("emptyStateText").textContent = text;
    empty.classList.remove("hidden");
}

function matchesSearch(app) {
    if (!state.search) return true;
    return app.packageName.toLowerCase().includes(state.search) || app.label.toLowerCase().includes(state.search);
}

function setAppIcon(iconElement, app) {
    if (app.icon) {
        const image = document.createElement("img");
        image.src = "data:image/webp;base64," + app.icon;
        image.alt = "";
        iconElement.appendChild(image);
    } else {
        iconElement.textContent = app.label.charAt(0).toUpperCase();
    }
}

function buildCard(app) {
    const template = document.getElementById("appCardTemplate");
    const card = template.content.firstElementChild.cloneNode(true);
    card.dataset.pkg = app.packageName;

    const targeted = state.targetPackages.has(app.packageName);
    card.classList.toggle("is-targeted", targeted);

    const iconElement = card.querySelector(".app-icon");
    setAppIcon(iconElement, app);
    if (app.system) iconElement.classList.add("system-icon");
    card.querySelector(".app-name").textContent = app.label;
    card.querySelector(".app-meta").textContent = app.packageName;

    const toggle = card.querySelector(".target-toggle");
    toggle.checked = targeted;
    toggle.addEventListener("change", async () => {
        if (toggle.checked) state.targetPackages.add(app.packageName);
        else state.targetPackages.delete(app.packageName);
        card.classList.toggle("is-targeted", toggle.checked);
        updateStatusSubtitle();
        if (await persistConfig()) {
            toast(toggle.checked ? "Added " + app.label : "Removed " + app.label);
        }
    });

    return card;
}

function render() {
    const list = document.getElementById("appList");
    const empty = document.getElementById("emptyState");
    list.innerHTML = "";

    const targeted = [];
    const others = [];
    for (const app of state.apps) {
        if (!matchesSearch(app)) continue;
        if (state.targetPackages.has(app.packageName)) targeted.push(app);
        else others.push(app);
    }

    const byName = (a, b) => a.label.localeCompare(b.label);
    targeted.sort(byName);
    others.sort(byName);

    if (targeted.length === 0 && others.length === 0) {
        setEmpty(state.search ? "No apps match your search." : "No apps found.");
        return;
    }
    empty.classList.add("hidden");

    if (targeted.length > 0) {
        const header = document.createElement("div");
        header.className = "section-label";
        header.textContent = "Targeted (" + targeted.length + ")";
        list.appendChild(header);
        for (const app of targeted) list.appendChild(buildCard(app));
    }

    const othersHeader = document.createElement("div");
    othersHeader.className = "section-label";
    othersHeader.textContent = "All apps (" + others.length + ")";
    list.appendChild(othersHeader);
    for (const app of others) list.appendChild(buildCard(app));

    if (window.FastScroll) window.FastScroll.update();
}

function openSettings() {
    document.getElementById("settingsEnabledToggle").checked = state.enabled;
    document.getElementById("settingsLibraryInput").value = state.libraryName;
    setActiveMethodSegment(state.method);
    document.getElementById("settingsOverlay").classList.remove("hidden");
}

function closeSettings() {
    document.getElementById("settingsOverlay").classList.add("hidden");
}

async function saveSettings() {
    const libraryValue = document.getElementById("settingsLibraryInput").value.trim();
    if (libraryValue && !/^[A-Za-z0-9_.+-]+$/.test(libraryValue)) {
        toast("Enter a library basename such as libart.so");
        return;
    }
    state.enabled = document.getElementById("settingsEnabledToggle").checked;
    state.libraryName = libraryValue || DEFAULT_LIBRARY_NAME;
    const activeSegment = document.querySelector("#settingsMethodSegment .segment.is-active");
    state.method = activeSegment ? activeSegment.dataset.method : DEFAULT_METHOD;
    updateStatusSubtitle();
    closeSettings();
    if (await persistConfig()) toast("Settings saved");
}

function bindFab(button, scroller, target) {
    let lastClick = 0;
    button.addEventListener("click", () => {
        const now = Date.now();
        const instant = (now - lastClick) < 300;
        lastClick = now;
        scroller.scrollTo({ top: target(), behavior: instant ? "auto" : "smooth" });
    });
}

function bindControls() {
    const scroller = document.getElementById("scroller");
    document.getElementById("refreshButton").addEventListener("click", () => {
        toast("Refreshing app list…");
        loadEverything(true);
    });
    document.getElementById("settingsButton").addEventListener("click", openSettings);
    document.getElementById("settingsCancel").addEventListener("click", closeSettings);
    document.getElementById("settingsSave").addEventListener("click", saveSettings);
    document.querySelectorAll("#settingsMethodSegment .segment").forEach((segment) => {
        segment.addEventListener("click", () => setActiveMethodSegment(segment.dataset.method));
    });
    document.getElementById("settingsOverlay").addEventListener("click", (event) => {
        if (event.target.id === "settingsOverlay") closeSettings();
    });

    const fabs = document.getElementById("scrollFabs");
    let fabTimer;
    const showFabs = () => {
        fabs.classList.add("visible");
        clearTimeout(fabTimer);
        fabTimer = setTimeout(() => fabs.classList.remove("visible"), 2500);
    };
    scroller.addEventListener("scroll", showFabs, { passive: true });
    bindFab(document.getElementById("scrollTopFab"), scroller, () => 0);
    bindFab(document.getElementById("scrollBottomFab"), scroller, () => scroller.scrollHeight);

    let searchTimer;
    document.getElementById("searchInput").addEventListener("input", (event) => {
        clearTimeout(searchTimer);
        const value = event.target.value.trim().toLowerCase();
        searchTimer = setTimeout(() => {
            state.search = value;
            render();
        }, 120);
    });
}

bindControls();
loadEverything(false);
