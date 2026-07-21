# 📣 Plan — Attribution Marketing → Revenus (+ Instagram)

> Statut : **futur** (non commencé). Objectif : mesurer si le marketing (posts, stories,
> campagnes) génère réellement du chiffre d'affaires, et arrêter de dépenser à l'aveugle.
> S'inscrit dans le levier « Nouveaux membres » du Playbook Croissance.

---

## 1. Le principe

On superpose une **timeline marketing** (quand on poste / quelle campagne) sur la
**timeline des inscriptions & du CA** qu'on a déjà (`register_cache` par date), et on
mesure la **hausse** (« lift ») après chaque action.

Résultat visé : *« La story Black Friday a généré 40 inscriptions en 5 jours ; le post
générique en a généré 3. »* → on investit sur ce qui convertit, on coupe le reste.

---

## 2. Deux méthodes d'attribution (de la plus faible à la plus forte)

| Méthode | Ce qu'il faut | Précision |
|---|---|---|
| **Lift par fenêtre temporelle** | juste un journal daté des actions marketing | Corrélation (bonne sur campagnes courtes/promos) |
| **Attribution directe** | un **code campagne / promo** capturé à l'inscription (champ `source` existe déjà) | Exacte — DH par campagne, sans deviner |

⚠️ Corrélation ≠ causalité : tenir compte de la saisonnalité (déjà suivie : Ramadan, Eid,
creux d'été, pic septembre), du bouche-à-oreille et des walk-ins. Le tag campagne à
l'inscription lève l'ambiguïté — c'est la cible idéale.

---

## 3. À construire

**A. Journal Marketing (Marketing Log)**
- Table SQLite `marketing_log` : `id, date, type (post|story|campagne|promo), channel
  (instagram|facebook|whatsapp|affiche|sms), titre, offre, budget?, gym_id?, created_by`.
- UI : petit formulaire (ou saisie rapide) pour logger une action. Idéalement mobile
  (le community manager logge en 5s après avoir posté).

**B. Outil AI `get_marketing_impact(period)`** (dans `services/ai-tools.js`)
- Superpose le journal sur le CA/inscriptions par jour ; calcule le lift J+1..J+7 vs
  baseline (moyenne des 14 j précédents, ajustée saison).
- Retourne par action : inscriptions attribuées, CA estimé, lift %, ROI si budget saisi.
- → Auralix répond « quelle campagne a le plus rapporté ce mois ? ».

**C. Attribution directe (optionnelle, plus forte)**
- Ajouter un champ **code campagne** au formulaire d'inscription (tablette PWA) → écrit
  dans `register_cache.source` (ou nouveau champ `campaign`).
- L'impact devient exact : CA réel par campagne, pas une estimation.

**D. Panel MegaEye** « IMPACT MARKETING » — top campagnes par CA/lift (comme le Churn Radar).

---

## 4. Instagram — ce qui est possible (et ce qui ne l'est pas)

| Cas | Possible ? | Comment |
|---|---|---|
| **Notre PROPRE compte IG** (Business/Creator) | ✅ Oui, officiel | **Meta Instagram Graph API** : récupère nos posts + stories avec leurs vraies stats (reach, impressions, engagement). Setup côté client : app développeur Meta + compte IG business lié à une Page Facebook + access token. Puis corrélation auto avec le CA. |
| **Compte tiers / concurrent** | ❌ Non | Pas d'API officielle pour les comptes tiers. Le scraping viole les CGU d'Instagram (surtout les stories, éphémères 24h), casse en permanence, et pose un risque juridique. **Ne pas construire de scraper.** Seules options propres : journal manuel, ou outil de social-listening payant. |

**Décision :** commencer par le **Journal Marketing manuel** (marche tout de suite, sans
API). Ensuite, si souhaité, brancher l'API Meta pour automatiser **notre** compte IG.

---

## 5. Phasage recommandé

1. **Phase 1 (rapide, aucune API)** — Journal Marketing + `get_marketing_impact` + panel.
   Le CM logge, Auralix mesure le lift. Valeur immédiate.
2. **Phase 2** — champ code campagne à l'inscription → attribution directe (exacte).
3. **Phase 3 (optionnel)** — intégration Meta Graph API pour auto-importer les posts +
   stats de **notre** compte IG et les corréler au CA.

---

## Notes
- Réutilise l'architecture Auralix : outil dans `services/ai-tools.js`, endpoint dans
  `routes/ai-agent.js`, panel dans `Auralix.jsx`. Mode privacy s'applique si des noms
  apparaissent (ici surtout des agrégats — peu de PII).
- Aucun emoji dans l'UI (préférence propriétaire) — pastilles/SVG.
- Voir aussi : Churn Radar (déjà livré), Playbook Croissance & Revenus.
