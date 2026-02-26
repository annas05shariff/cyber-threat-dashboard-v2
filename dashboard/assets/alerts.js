/**
 * alerts.js — Real-time WebSocket alert toasts for the Cyber Threat Dashboard
 * Connects to the ML service WebSocket and displays incoming alerts as
 * dark-themed popup notifications in the bottom-right corner.
 */

(function () {
  "use strict";

  // Use injected URL from Dash (works on Render), fallback to localhost for dev
  const WS_URL = window.CYBER_WS_URL || "ws://localhost:8001/ws/alerts";
  const MAX_TOASTS = 5;        // max visible toasts at once
  const TOAST_DURATION = 8000; // ms before auto-dismiss

  const SEVERITY_META = {
    Critical: { color: "#ff2d55", icon: "🔴", border: "#ff2d55" },
    High:     { color: "#ff9500", icon: "🟠", border: "#ff9500" },
    Medium:   { color: "#ffcc00", icon: "🟡", border: "#ffcc00" },
    Low:      { color: "#30d158", icon: "🟢", border: "#30d158" },
  };

  let ws = null;
  let reconnectTimer = null;
  let container = null;

  /* ── Container ──────────────────────────────────────────────── */

  function ensureContainer() {
    if (container && document.body.contains(container)) return container;
    container = document.createElement("div");
    container.id = "alert-toast-container";
    document.body.appendChild(container);
    return container;
  }

  /* ── Toast ──────────────────────────────────────────────────── */

  function showToast(data) {
    const c = ensureContainer();

    // Enforce max visible limit — remove oldest
    const existing = c.querySelectorAll(".alert-toast");
    if (existing.length >= MAX_TOASTS) {
      existing[0].remove();
    }

    const severity = data.severity || "High";
    const meta     = SEVERITY_META[severity] || SEVERITY_META.High;
    const time     = data.created_at
      ? new Date(data.created_at).toLocaleTimeString()
      : new Date().toLocaleTimeString();

    const toast = document.createElement("div");
    toast.className = "alert-toast";
    toast.style.borderLeftColor = meta.border;

    toast.innerHTML = `
      <div class="alert-toast-header">
        <span class="alert-toast-icon">${meta.icon}</span>
        <span class="alert-toast-title">${escapeHtml(data.title || "Threat Alert")}</span>
        <span class="alert-toast-badge" style="background:${meta.color}">${severity}</span>
        <button class="alert-toast-close" aria-label="Close">×</button>
      </div>
      <div class="alert-toast-body">${escapeHtml(data.message || "")}</div>
      <div class="alert-toast-time">${time}</div>
      <div class="alert-toast-progress"></div>
    `;

    // Close button
    toast.querySelector(".alert-toast-close").addEventListener("click", () => {
      dismissToast(toast);
    });

    c.appendChild(toast);

    // Animate in
    requestAnimationFrame(() => {
      requestAnimationFrame(() => toast.classList.add("alert-toast--visible"));
    });

    // Progress bar + auto-dismiss
    const progress = toast.querySelector(".alert-toast-progress");
    progress.style.transition = `width ${TOAST_DURATION}ms linear`;
    requestAnimationFrame(() => {
      requestAnimationFrame(() => { progress.style.width = "0%"; });
    });

    const timer = setTimeout(() => dismissToast(toast), TOAST_DURATION);
    toast._dismissTimer = timer;
  }

  function dismissToast(toast) {
    clearTimeout(toast._dismissTimer);
    toast.classList.remove("alert-toast--visible");
    toast.classList.add("alert-toast--hiding");
    toast.addEventListener("transitionend", () => toast.remove(), { once: true });
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  /* ── WebSocket ──────────────────────────────────────────────── */

  function connect() {
    if (ws && (ws.readyState === WebSocket.CONNECTING || ws.readyState === WebSocket.OPEN)) {
      return;
    }

    try {
      ws = new WebSocket(WS_URL);
    } catch (e) {
      scheduleReconnect();
      return;
    }

    ws.onopen = function () {
      console.info("[CyberThreat] WebSocket connected — live alerts active");
      clearTimeout(reconnectTimer);
    };

    ws.onmessage = function (event) {
      try {
        const data = JSON.parse(event.data);
        if (data.type === "alert") {
          showToast(data);
        }
      } catch (e) {
        console.warn("[CyberThreat] Unreadable WS message:", event.data);
      }
    };

    ws.onclose = function () {
      console.warn("[CyberThreat] WebSocket closed — reconnecting in 15s");
      scheduleReconnect();
    };

    ws.onerror = function () {
      // onclose fires after onerror — reconnect handled there
    };
  }

  function scheduleReconnect() {
    clearTimeout(reconnectTimer);
    reconnectTimer = setTimeout(connect, 15000);
  }

  /* ── Init ───────────────────────────────────────────────────── */

  // Wait for the DOM + Dash to be ready before connecting
  function init() {
    ensureContainer();
    connect();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
