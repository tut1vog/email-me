// Conveniences only: copy buttons, confirmations, the policy editor's
// Custom switches, audit filters that apply on change, dismissable flashes
// and the mobile navigation drawer. Every form and link still works without
// JavaScript; CSS alone reveals policy fields (:has) and opens the drawer
// (the #nav-toggle checkbox). Served from /static/ under script-src 'self':
// no inline scripts or handlers anywhere, so everything is delegated here.
"use strict";

document.documentElement.classList.add("js");

// Copy the text of the element named by data-copy; the button reads
// "Copied" for a moment.
document.addEventListener("click", (ev) => {
  const btn = ev.target.closest("[data-copy]");
  if (!btn) return;
  const el = document.getElementById(btn.dataset.copy);
  if (!el || !navigator.clipboard) return;
  const text = el.tagName === "INPUT" || el.tagName === "TEXTAREA" ? el.value : el.textContent;
  navigator.clipboard.writeText(text).then(() => {
    const label = btn.querySelector(".copy-label") || btn;
    if (btn.dataset.copyBusy) return;
    btn.dataset.copyBusy = "1";
    const old = label.textContent;
    label.textContent = "Copied";
    setTimeout(() => {
      label.textContent = old;
      delete btn.dataset.copyBusy;
    }, 1500);
  });
});

// Dismiss a flash message.
document.addEventListener("click", (ev) => {
  const btn = ev.target.closest("[data-dismiss]");
  if (!btn) return;
  const flash = btn.closest(".flash");
  if (flash) flash.remove();
});

// Ask before destructive submits.
document.addEventListener("submit", (ev) => {
  const msg = ev.target.dataset && ev.target.dataset.confirm;
  if (msg && !window.confirm(msg)) ev.preventDefault();
});

// Forms marked data-autosubmit (audit filters) apply on every change.
document.addEventListener("change", (ev) => {
  const form = ev.target.closest && ev.target.closest("form[data-autosubmit]");
  if (!form) return;
  if (form.requestSubmit) form.requestSubmit();
  else form.submit();
});

// Policy editor: a row's input shows only while its Custom switch is on.
// CSS does the same with :has(); this covers browsers without it.
function syncPolicyRow(row, focus) {
  const sw = row.querySelector(".switch input");
  const field = row.querySelector(".policy-field");
  if (!sw || !field) return;
  field.hidden = !sw.checked;
  if (focus && sw.checked) {
    const first = field.querySelector("input:not([type=hidden]), select, textarea");
    if (first) first.focus();
  }
}

document.addEventListener("change", (ev) => {
  if (!ev.target.matches(".policy-row .switch input")) return;
  syncPolicyRow(ev.target.closest(".policy-row"), true);
});

// Mobile navigation drawer, driven by the #nav-toggle checkbox.
function navToggle() {
  return document.getElementById("nav-toggle");
}

function syncBurger() {
  const toggle = navToggle();
  const burger = document.querySelector(".nav-burger");
  if (toggle && burger) burger.setAttribute("aria-expanded", toggle.checked ? "true" : "false");
}

function closeNav() {
  const toggle = navToggle();
  if (toggle && toggle.checked) {
    toggle.checked = false;
    syncBurger();
  }
}

document.addEventListener("change", (ev) => {
  if (ev.target.id === "nav-toggle") syncBurger();
});

document.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape") closeNav();
});

document.addEventListener("click", (ev) => {
  if (ev.target.closest(".sidebar a")) closeNav();
});

// Initial pass (the script is deferred, so the DOM is parsed).
document.querySelectorAll(".policy-row").forEach((row) => syncPolicyRow(row, false));
syncBurger();
