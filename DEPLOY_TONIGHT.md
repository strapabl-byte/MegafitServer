# 🚀 Deploy Runbook — Security Lockdown of `/public/*` + CIN-scan fixes

**Goal:** stop the open internet from harvesting member PII, fix the CIN scanner echoing a
fake identity, and ship the scanner redesign — with **zero downtime** for tablets/dashboard.

**Golden rule:** the **tablet must be live (Firebase) BEFORE the backend gate goes live (Render).**
Firebase deploys in ~1 min; Render takes several to build — so start the tablet first.

---

## 0. What ships (state 2026-07-15)

| Unit | Deploy target | Pending |
|---|---|---|
| **Backend** `megafit-api` | Render (`MegafitServer`) | `c6c951a` (CIN-scan echo fix) + `ac6ecaa` (gate `/public/*`) — **pushed to GitHub**; awaiting your **Render deploy**. Earlier `66f366c`, `899429b` already live-on-GitHub. |
| **Tablet** `megafit-inscription` | Firebase | `5dcf241` (`X-Inject-Secret` on search/detail/multiclub) + `994e595` (CIN-scanner redesign) — committed locally, ship on the Firebase build. Note: repo has uncommitted WIP (`main.jsx`, `pdfGenerator.js`, `index.html`) that will also bundle. |
| **Dashboard** `megafit-dashboard3` | Firebase `megafitauth` | Deploys from the working tree (activity panel, schedule, etc.). Independent of `/public/*`. |

### The changes
- **Gate:** `GET /public/members/search`, `GET /public/members/:id/detail`,
  `POST /public/multiclub` now require `requireDebtorAccess` (`X-Inject-Secret` **or** Azure token).
- **Tablet:** sends `X-Inject-Secret` on all 4 call sites (uses `VITE_INJECT_SECRET`, already in build).
- **CIN scan:** prompt no longer hands the model a filled-in sample, so a blurry photo returns
  empty instead of echoing "BELLALA/OMAR"; server backstop nulls any residual echo.
- **CIN scanner UI:** theme-aware, animated scan frame, editable result fields.
- **Only the tablet calls the gated endpoints** — dashboard/MegaEye unaffected.

---

## 1. Pre-flight (no deploy needed)

- [ ] **Secret match test (the one real risk).** On any tablet, open **PayReste** and let the
      debtors list load. If it loads → Render's `INJECT_SECRET` == the tablet's build secret →
      the gated endpoints will work too.
- [ ] On Render: `TENANT_ID` + `CLIENT_ID` set (they are). **Do NOT** add `ALLOW_DEMO_TOKEN`.
- [ ] `OPENAI_API_KEY` set on Render (already used by CIN scan).

---

## 2. Deploy order

### Step 1 — Tablet → Firebase (FIRST)
- [ ] Review/commit the tablet WIP (`main.jsx`, `pdfGenerator.js`, `index.html`) — or accept as-is.
- [ ] Build + deploy tablet to Firebase.
- [ ] On a tablet: confirm **member search** still works (backend still ignores the header here).

### Step 2 — Dashboard → Firebase `megafitauth` (anytime)
- [ ] Build + deploy. Independent — doesn't touch `/public/*`.

### Step 3 — Backend → Render (LAST)
- [ ] Deploy on Render (commits already on GitHub).
- [ ] On a tablet: re-test **member search + a multiclub activation** — both pass through the gate.
- [ ] Scan a blurry ID → fields come back **empty** (not "Bellala Omar"). ✅

---

## 3. Post-deploy smoke (30 sec)

- [ ] Tablet: search member → detail fills → multiclub submit works. ✅
- [ ] Logged-out browser: `…/public/members/search?q=test` → **401/403**, not a member list. ✅
- [ ] Dashboard: login → members / payments / MegaEye load normally. ✅

---

## 4. Rollback (if the secret ever mismatches → tablet 403s)

```
# in megafit-api
git revert ac6ecaa
# redeploy on Render
```
Endpoints go back to open instantly; the tablet's extra header is harmless either way.

---

## Notes
- Backend commits are on GitHub — **deploy Render only after the tablet is on Firebase** (order above).
- The tablet has no git remote; it ships via the Firebase build from the working tree.
- No `Co-Authored-By` trailers (per repo policy).
