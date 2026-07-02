'use strict';
// services/david-notify.js — notify the David WhatsApp agent about décaissements.
// Fire-and-forget: never blocks or fails the caller. No-op unless env is configured.

function notifyDavidDecaissement(payload) {
  const url = process.env.DAVID_NOTIFY_URL;
  const token = process.env.DAVID_NOTIFY_TOKEN;
  if (!url || !token) return; // integration disabled

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 4000);
  fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-notify-token': token },
    body: JSON.stringify(payload),
    signal: controller.signal,
  })
    .catch((err) => console.warn('[david-notify] failed:', err.message))
    .finally(() => clearTimeout(timer));
}

module.exports = { notifyDavidDecaissement };
