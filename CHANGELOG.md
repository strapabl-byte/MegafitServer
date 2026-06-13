# Changelog — MegaFit API Server

All notable changes to the MegaFit API are documented in this file.

---

## [2026-06-13] — AI Assessment & CIN Scanner Fix

### 🤖 NEW: Server-Side AI Assessment on Inscription Submit
- **What**: When a new inscription is submitted via `/public/inscriptions`, the server now automatically runs an AI quality check (Groq Llama 3.3 70B) in the background.
- **Checks performed**:
  - 💰 **Payment coherence** — compares paid amount against official subscription prices loaded from the gym's Firestore config (`inscription-{gymId}`)
  - 📱 **Phone format** — validates Moroccan format (06/07/05 + 8 digits = 10 total)
  - ✉️ **Email** — checks presence and format validity
  - 🪪 **CIN format** — validates Moroccan national ID format (1-2 letters + 5-7 digits)
  - 📋 **Missing fields** — flags missing name, birthday, subscription period
  - 💵 **Price vs official catalog** — cross-references with the prices configured in Inscription Controller
- **Result stored** as `aiAssessment` field on the `pending_members` Firestore document:
  ```json
  {
    "status": "ok | warning | error",
    "message": "Human-readable summary in French",
    "issues": ["List of specific problems"],
    "checkedAt": "ISO timestamp",
    "model": "llama-3.3-70b"
  }
  ```
- **Non-blocking** — runs AFTER the HTTP response is sent, so the PWA is never slowed down.
- **File**: `routes/inscriptions.public.js`

### 🐛 FIX: CIN Scanner returning "Barcelona" as city
- **Problem**: The CIN verso scan prompt (`/public/scan-cin`) contained `"ville":"Barcelone"` as the JSON example. GPT-4o-mini was copying this example instead of extracting the real city from the card.
- **Fix**: Replaced the example with a Moroccan city (`Fès`) and Moroccan address. Added explicit instruction: "Do NOT copy the example — extract the REAL city from the actual card image." Listed common Moroccan cities (Fès, Casablanca, Rabat, Meknès, etc.) to guide the AI.
- **File**: `routes/scan.js`

---
