// Island loader — mounts Svelte components onto [data-island] elements.
// Re-mounts after htmx swaps (htmx:load) and unmounts before a swap
// destroys the DOM (htmx:beforeSwap) so sockets/timers clean up.
import { mount, unmount } from "svelte";
import Sniff from "./Sniff.svelte";

const ISLANDS = { sniff: Sniff };
const KEY = "_ntodIsland";

function mountAll(root) {
  if (!root.querySelectorAll) return;
  root.querySelectorAll("[data-island]").forEach(function (el) {
    if (el[KEY]) return;
    var C = ISLANDS[el.getAttribute("data-island")];
    if (C) {
      // Server-rendered fallback owns the region until the bundle lands —
      // the island replaces it (Svelte mount appends, so clear first).
      el.innerHTML = "";
      el[KEY] = mount(C, { target: el });
    }
  });
}

function unmountAll(root) {
  if (!root.querySelectorAll) return;
  root.querySelectorAll("[data-island]").forEach(function (el) {
    if (el[KEY]) {
      unmount(el[KEY]);
      el[KEY] = null;
    }
  });
}

document.addEventListener("DOMContentLoaded", function () {
  mountAll(document.body);
});
document.body.addEventListener("htmx:load", function (e) {
  mountAll(e.detail && e.detail.elt ? e.detail.elt : e.target);
});
document.body.addEventListener("htmx:beforeSwap", function (e) {
  var t = e.detail && e.detail.target ? e.detail.target : e.target;
  unmountAll(t);
});
