# MegaFit — Coach data for the mobile app

How the mobile app gets **all** the info entered in the coach form (including the **photo**).

- **Backend base URL:** `https://megafitserverii.onrender.com`
- **Firebase project:** `megafitauth`
- **Firestore collection:** `coaches` (one document per coach)

---

## TL;DR — recommended flow (coach app)

1. Coach scans their **QR card** → you get a `token` from the QR URL.
2. Call the **public** endpoint `GET /public/coach-pass/{token}` → it returns a **Firebase custom token**.
3. Sign into **Firebase Auth** with that custom token (`signInWithCustomToken`).
4. Read the coach's **full profile straight from Firestore**: `coaches/{coachId}` — this document contains **every field, including the photo**.

> Why Firestore and not the REST API? The `/api/coaches` REST endpoints are protected by the **dashboard's Azure AD** login, which the mobile app doesn't have. The QR flow hands you a **Firebase** identity instead, and the coach document (with all fields + photo) lives in Firestore — so reading it directly is the natural path.

---

## 1. The coach document — every field

`coaches/{coachId}`:

```jsonc
{
  "name":            "Youssef",                 // prénom
  "surname":         "Bennani",                 // nom
  "specialty":       "Boxing",                  // spécialité principale
  "expertise":       "Boxe anglaise, perte de poids, préparation physique",
  "personality":     "Motivant, rigoureux, patient",
  "experienceYears": 8,                          // number (peut être null)
  "certifications":  "BPJEPS, Coach certifié CrossFit L1",
  "phone":           "0645350555",
  "email":           "coach@megafit.ma",
  "instagram":       "@coach.megafit",
  "hireDate":        "2024-01-01",               // ISO date string
  "bio":             "Quelques lignes de présentation…",
  "photo":           "data:image/jpeg;base64,/9j/4AAQ…",  // ← voir §3
  "gymId":           "dokarat",                  // dokarat | marjane | casa1 | casa2
  "qrToken":         "…",                         // présent tant que le QR n'a pas été scanné (sinon absent)
  "createdAt":       "<Firestore Timestamp>",
  "createdBy":       "…"
}
```

Any field can be `null`/absent if it wasn't filled in — handle missing values.

`gymId` → club name mapping:

| gymId | Club |
|---|---|
| `dokarat` | Fès Dokkarat |
| `marjane` | Fès Saïss |
| `casa1` | Casa Anfa |
| `casa2` | Casa Lady |

---

## 2. QR login → Firebase → profile

**QR content** is a URL like `https://megafit.app/coach-pass?token=ABC123`. Parse out `token`.

**Step 1 — exchange the token (public, no auth):**

```
GET https://megafitserverii.onrender.com/public/coach-pass/ABC123
```

Response:
```json
{
  "ok": true,
  "firebaseCustomToken": "eyJhbGciOi…",
  "coach": { "id": "COACH_ID", "name": "Youssef", "surname": "Bennani", "specialty": "Boxing" }
}
```

> ⚠️ **Single use:** scanning consumes the QR (`qrToken` is deleted). Store the Firebase session afterwards; don't rely on re-scanning. If a coach needs a new QR, the dashboard regenerates one.

**Step 2 — sign into Firebase with the custom token** (project `megafitauth`):

```js
// Firebase Web SDK example
import { getAuth, signInWithCustomToken } from 'firebase/auth'
await signInWithCustomToken(getAuth(), firebaseCustomToken)
// now authenticated as uid = "coach_<COACH_ID>", custom claim role = "coach"
```
(Android/iOS SDKs: `signInWithCustomToken(...)` — same idea.)

**Step 3 — read the full profile from Firestore:**

```js
import { getFirestore, doc, getDoc } from 'firebase/firestore'
const snap = await getDoc(doc(getFirestore(), 'coaches', COACH_ID))
const coach = snap.data()   // ← all fields, including coach.photo
```

You now have the complete profile the dashboard entered.

---

## 3. The photo

`photo` is stored **inline** on the document — no separate download call.

- Usually a **base64 data URI**: `data:image/jpeg;base64,…` (already resized ~512 px, JPEG). Render it directly in an `<Image>`/`ImageView` (most SDKs accept data URIs; otherwise strip the `data:image/jpeg;base64,` prefix and decode the base64 to bytes).
- Some older coaches may have an **https URL** instead. So:

```js
const src = coach.photo
if (!src) { /* show initials placeholder */ }
else if (src.startsWith('data:')) { /* render as data URI / decode base64 */ }
else { /* it's an https URL → load normally */ }
```

That's it — the picture comes back in the same read as the rest of the profile.

---

## 4. Ratings (optional — members' reviews of a coach)

Members' star ratings + comments live in Firestore `coach_ratings` (and are exposed on the dashboard). Fields per rating: `coachId`/`coachName`, `rating` (1–5), `comment`, `memberName`, `courseTitle`, `createdAt`. Read the collection filtered by `coachId` if you want to show reviews in the app.

---

## 5. Admin/list use (dashboard-style, needs Azure token)

If a mobile screen must list **all** coaches of a club (not the coach's own profile), two options:

- **Firestore query** (recommended, same auth as above): `coaches` where `gymId == <club>`.
- **REST** `GET /api/coaches?gymId=<club>` — returns the same objects, **but requires an `Authorization: Bearer <Azure-AD-token>`** (the dashboard login). A coach's Firebase token is **not** accepted here.

---

## Notes for the backend team

- Make sure **Firestore security rules** let an authenticated coach read their own `coaches/{id}` document (and `coach_ratings` if used). The custom claim `role: "coach"` and uid `coach_<id>` are available in rules.
- The Firebase Web/Native **config** for project `megafitauth` (apiKey, appId, etc.) is needed in the app — grab it from the Firebase console → Project settings.
