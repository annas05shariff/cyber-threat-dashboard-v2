/**
 * dropdown_fix.js
 * Forcibly applies dark styles to Dash dcc.Dropdown menus.
 * CSS alone can't override Dash's inline styles — JS is needed.
 */
(function () {
  "use strict";

  const DARK   = "#0a1928";
  const BORDER = "#1a4a6a";
  const TEXT   = "#c8e6f5";
  const CYAN   = "#00d4ff";
  const HOVER  = "#0f2d45";

  function styleMenuOuter(el) {
    el.style.setProperty("background-color", DARK,    "important");
    el.style.setProperty("border",           `1px solid ${BORDER}`, "important");
    el.style.setProperty("border-top",       "none",  "important");
    el.style.setProperty("box-shadow",       "0 8px 24px rgba(0,0,0,0.85)", "important");
    el.style.setProperty("z-index",          "9999",  "important");
  }

  function styleOption(el) {
    el.style.setProperty("background-color", DARK,  "important");
    el.style.setProperty("color",            TEXT,  "important");

    el.onmouseenter = function () {
      el.style.setProperty("background-color", HOVER, "important");
      el.style.setProperty("color",            CYAN,  "important");
    };
    el.onmouseleave = function () {
      const isSel = el.classList.contains("is-selected");
      el.style.setProperty("background-color", isSel ? "rgba(0,212,255,0.1)" : DARK, "important");
      el.style.setProperty("color",            isSel ? CYAN : TEXT, "important");
    };
  }

  function fixAllMenus() {
    document.querySelectorAll(".Select-menu-outer").forEach(styleMenuOuter);
    document.querySelectorAll(".Select-menu").forEach(el => {
      el.style.setProperty("background-color", DARK, "important");
    });
    document.querySelectorAll(".Select-option").forEach(styleOption);
    document.querySelectorAll(".Select-noresults").forEach(el => {
      el.style.setProperty("background-color", DARK, "important");
      el.style.setProperty("color", "#4a7090",       "important");
    });
  }

  // Observe DOM mutations so we catch menus as they open
  const observer = new MutationObserver(function (mutations) {
    let needsFix = false;
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (node.nodeType === 1 &&
            (node.classList.contains("Select-menu-outer") ||
             node.querySelector && node.querySelector(".Select-menu-outer"))) {
          needsFix = true;
          break;
        }
      }
      if (needsFix) break;
    }
    if (needsFix) fixAllMenus();
  });

  function init() {
    observer.observe(document.body, { childList: true, subtree: true });
    fixAllMenus();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
