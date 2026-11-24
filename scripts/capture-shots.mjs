// Capture docs/screenshots/*.png from a running `ntod serve` instance.
//
//   ntod serve --port 7878                 # terminal 1
//   npm i --prefix .shots puppeteer-core   # once
//   node scripts/capture-shots.mjs         # all shots
//   node scripts/capture-shots.mjs wifi    # subset
//
// Uses the locally installed Edge (no browser download). Screenshots land
// in docs/screenshots/ at 2x for retina crispness.
import { createRequire } from "node:module";
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";

const require = createRequire(resolve(".shots/package.json"));
const puppeteer = require("puppeteer-core");

const BASE = process.env.NTOD_URL ?? "http://127.0.0.1:7878";
const OUT = "docs/screenshots";
const EDGE =
  "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const only = new Set(process.argv.slice(2));
const want = (n) => only.size === 0 || only.has(n);

mkdirSync(OUT, { recursive: true });

const browser = await puppeteer.launch({
  executablePath: EDGE,
  headless: "shell",
  args: ["--headless=new", "--hide-scrollbars"],
});

async function open(path, w = 1440, h = 900) {
  const p = await browser.newPage();
  await p.setViewport({ width: w, height: h, deviceScaleFactor: 2 });
  await p.goto(`${BASE}/${path}`, { waitUntil: "networkidle0" });
  return p;
}
async function shot(p, name, settle = 800) {
  await sleep(settle);
  await p.screenshot({ path: `${OUT}/${name}.png` });
  console.log(`  ${name}.png`);
}

// /scan — click Scan, let SSE populate hosts, wait until enrichment
// (MAC/vendor/ports columns) lands instead of the "…" placeholders.
if (want("scan")) {
  const p = await open("scan");
  await p.click("button.btn");
  try {
    await p.waitForFunction(
      () =>
        [...document.querySelectorAll("#rows tr")].filter(
          (r) => (r.children[2]?.textContent ?? "").trim() !== "…"
        ).length >= 3,
      { timeout: 60000, polling: 1000 }
    );
    await sleep(6000);
  } catch {}
  await shot(p, "scan", 0);
  await p.close();
}

// /sniff — capture form + packet-rate island (privilege state is honest UI).
if (want("sniff")) {
  const p = await open("sniff");
  await p.click("#go").catch(() => {});
  await shot(p, "sniff", 3500);
  await p.close();
}

// /wifi — Survey fills #table-panel; SSIDs/BSSIDs are masked for the README.
if (want("wifi")) {
  const p = await open("wifi");
  await p.click("button.btn").catch(() => {});
  await sleep(5000);
  await p.evaluate(() => {
    const fake = [
      ["HomeNet_5G", 84, 157],
      ["HomeNet", 72, 6],
      ["CoffeeShop_Guest", 51, 11],
      ["TP-Link_9F2A", 38, 1],
      ["Printer-WiFi", 26, 44],
    ];
    const tbody = document.querySelector("#table-panel tbody");
    const row = tbody?.querySelector("tr");
    if (!tbody || !row) return;
    // One real network usually isn't enough for a pretty shot — clone it.
    while (tbody.children.length < fake.length)
      tbody.appendChild(row.cloneNode(true));
    [...tbody.querySelectorAll("tr")].forEach((r, i) => {
      const f = fake[i % fake.length];
      if (r.children[0]) r.children[0].textContent = f[0];
      if (r.children[1])
        r.children[1].textContent = `02:11:22:33:44:${(i + 1)
          .toString(16)
          .padStart(2, "0")}`;
      const sig = r.querySelector("td:nth-child(3)");
      if (sig) {
        sig.lastChild.textContent = ` ${f[1]}%`;
        const bars = sig.querySelectorAll("i");
        const lit = Math.round((f[1] / 100) * bars.length);
        bars.forEach((b, j) => (b.style.opacity = j < lit ? "1" : "0.25"));
      }
      if (r.children[3]) r.children[3].textContent = String(f[2]);
    });
    // Keep the count pill honest with the padded table.
    const pill = [...document.querySelectorAll("*")].find((e) =>
      /^\d+ networks?$/.test(e.textContent.trim()) && e.children.length <= 2
    );
    if (pill) pill.textContent = `${fake.length} networks`;
  });
  await shot(p, "wifi", 400);
  await p.close();
}

// /analyze — upload the synthetic pcap, wait for the full report.
if (want("analyze")) {
  const p = await open("analyze", 1440, 1600);
  const input = await p.$("input[type=file]");
  await input.uploadFile(resolve("examples/demo.pcap"));
  await p.waitForSelector("#report-workspace", { timeout: 30000 });
  await shot(p, "analyze", 2500);
  await p.evaluate(() => {
    document.querySelector("#report-workspace")?.scrollIntoView();
    window.scrollBy(0, 760);
  });
  await shot(p, "analyze-detail", 800);
  await p.close();
}

// /tools — probe tile loads on page open.
if (want("tools")) {
  const p = await open("tools");
  await shot(p, "tools", 2500);
  await p.close();
}

// /devices — Refresh fills the remembered-device table + alert feed.
if (want("devices")) {
  const p = await open("devices");
  await p.click("button.btn").catch(() => {});
  try {
    await p.waitForSelector("#table-panel tbody tr", { timeout: 10000 });
  } catch {}
  await shot(p, "devices", 1200);
  await p.close();
}

await browser.close();
console.log("done → docs/screenshots/");
