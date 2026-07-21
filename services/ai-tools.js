'use strict';
// services/ai-tools.js — AURALIX Retrieval Tool Engine
// ─────────────────────────────────────────────────────────────────────────────
// OpenAI function-calling tools that let the AI query the REAL data on demand,
// instead of receiving a truncated snapshot. This is what makes Auralix able to
// answer "revenus de Casa Anfa le mois dernier", "meilleur décaissement de Mai",
// "info sur ce membre" — the model picks a tool, we run the SQL, it reasons.
//
// Pure data layer: no LLM here. Every executor is deterministic, guarded, and
// returns a plain object (the caller JSON-stringifies it back to the model).
// Advisor-only: strictly READ-ONLY — no tool mutates anything.

const GYM_NAMES = { dokarat: 'Fès Doukkarate', marjane: 'Fès Saïss', casa1: 'Casa Anfa', casa2: 'Casa Lady' };
const VALID_GYMS = ['dokarat', 'marjane', 'casa1', 'casa2'];
const GYM_ALIASES = {
  dokarat: 'dokarat', dokkarat: 'dokarat', doukkarate: 'dokarat', fes: 'dokarat', 'fès doukkarate': 'dokarat',
  marjane: 'marjane', saiss: 'marjane', 'saïss': 'marjane', 'fès saïss': 'marjane', 'fes saiss': 'marjane',
  casa1: 'casa1', anfa: 'casa1', 'casa anfa': 'casa1',
  casa2: 'casa2', lady: 'casa2', 'casa lady': 'casa2',
};

// Reste (debt) expression reused from buildSnapshot so numbers reconcile exactly.
const RESTE_EXPR = `(CASE WHEN CAST(r.prix AS REAL)>0 THEN CAST(r.prix AS REAL)-(COALESCE(CAST(r.tpe AS REAL),0)+COALESCE(CAST(r.espece AS REAL),0)+COALESCE(CAST(r.virement AS REAL),0)+COALESCE(CAST(r.cheque AS REAL),0)) ELSE CAST(r.reste AS REAL) END)`;
const NOT_SETTLED = `COALESCE(r.source,'')!='reste_settlement' AND NOT EXISTS (SELECT 1 FROM register_cache s WHERE s.source='reste_settlement' AND CAST(s.reste AS REAL)=0 AND s.gym_id=r.gym_id AND ((s.contrat=r.contrat AND s.contrat IS NOT NULL AND s.contrat!='' AND s.contrat!='-') OR (s.nom=r.nom AND s.nom IS NOT NULL AND s.nom!='')))`;

// ── Décaissement auto-categorization (deterministic, same spirit as the RH filter) ──
const EXPENSE_CATEGORIES = [
  { key: 'salaires',    label: 'Salaires & Staff',   re: /salaire|avance|prime|paie|coach|moniteur|monitrice|instruct|prof|animat|personnel|employ|vacataire|honoraire|femme de m[eé]nage|agent|gardien|s[eé]curit/i },
  { key: 'loyer',       label: 'Loyer & Charges',    re: /loyer|rent|bail|charge|syndic|taxe|imp[oô]t|patente/i },
  { key: 'energie',     label: 'Énergie & Eau',      re: /electric|électric|lydec|redal|amendis|eau|water|onee|facture eau|facture electr/i },
  { key: 'materiel',    label: 'Matériel & Équip.',  re: /materiel|matériel|equip|équip|machine|haltere|haltère|poids|tapis|velo|vélo|banc|barre|r[eé]paration|maintenance|pi[eè]ce/i },
  { key: 'marketing',   label: 'Marketing & Pub',    re: /pub|marketing|flyer|affiche|banderole|sponsor|influenc|facebook|insta|ads|campagne|photograph|design|impression/i },
  { key: 'produits',    label: 'Produits & Boutique',re: /produit|boutique|complement|complément|prote|whey|creatin|créatin|barre|boisson|eau min|snack|caf[eé]|the|thé|stock/i },
  { key: 'entretien',   label: 'Entretien & Nettoy.',re: /nettoy|menage|ménage|produit entretien|javel|serpill|hygiene|hygiène|savon|papier|consommable/i },
  { key: 'internet',    label: 'Internet & Télécom', re: /internet|wifi|iam|inwi|orange|telecom|téléphone|telephone|abonnement net|fibre/i },
];
function categorizeExpense(reason) {
  const r = (reason || '').toString();
  for (const c of EXPENSE_CATEGORIES) if (c.re.test(r)) return c;
  return { key: 'autre', label: 'Autre / Divers' };
}

// ── helpers ──────────────────────────────────────────────────────────────────
const FR_MONTHS = { janvier: 1, fevrier: 2, 'février': 2, mars: 3, avril: 4, mai: 5, juin: 6, juillet: 7, aout: 8, 'août': 8, septembre: 9, octobre: 10, novembre: 11, decembre: 12, 'décembre': 12 };
const EN_MONTHS = { january: 1, february: 2, march: 3, april: 4, may: 5, june: 6, july: 7, august: 8, september: 9, october: 10, november: 11, december: 12 };

function nowMorocco() { return new Date(Date.now() + 3600000); }
function currentYm() { return nowMorocco().toISOString().slice(0, 10).slice(0, 7); }
function shiftYm(ym, delta) {
  let [y, m] = ym.split('-').map(Number);
  m += delta;
  while (m < 1) { m += 12; y -= 1; }
  while (m > 12) { m -= 12; y += 1; }
  return `${y}-${String(m).padStart(2, '0')}`;
}

// Accept 'YYYY-MM', a French/English month name ("Mai", "may"), a RELATIVE phrase
// ("mois dernier", "ce mois", "last month", "il y a 2 mois"), or empty → current
// month. Robust so the model can pass natural language and still hit the right month.
function resolveMonth(input) {
  const cur = currentYm();
  if (!input) return cur;
  const s = String(input).trim().toLowerCase();
  if (/^\d{4}-\d{2}$/.test(s)) return s;
  if (/^\d{4}$/.test(s)) return null; // whole-year handled separately by caller
  // ── relative phrases ──
  if (/\b(ce mois|mois courant|mois[- ]ci|mois en cours|this month|current month|actuel)\b/.test(s)) return cur;
  if (/\b(mois dernier|mois pass[eé]|mois pr[eé]c[eé]dent|last month|previous month|le mois d'avant)\b/.test(s)) return shiftYm(cur, -1);
  if (/\b(avant[- ]dernier mois|il y a 2 mois|deux mois|two months ago)\b/.test(s)) return shiftYm(cur, -2);
  if (/\b(il y a 3 mois|trois mois|three months ago)\b/.test(s)) return shiftYm(cur, -3);
  // ── month names (assume current year, or last year if that month is still ahead) ──
  const m = FR_MONTHS[s] ?? EN_MONTHS[s];
  if (m) {
    const now = nowMorocco();
    let year = now.getFullYear();
    if (m > now.getMonth() + 1) year -= 1;
    return `${year}-${String(m).padStart(2, '0')}`;
  }
  return cur;
}

function resolveGym(input) {
  if (!input || input === 'all') return 'all';
  const s = String(input).trim().toLowerCase();
  if (VALID_GYMS.includes(s)) return s;
  return GYM_ALIASES[s] || null; // null = unrecognised → caller reports error
}

function makeQ(db) {
  return {
    all: (sql, ...a) => { try { return db.prepare(sql).all(...a); } catch (e) { return { __err: e.message }; } },
    get: (sql, ...a) => { try { return db.prepare(sql).get(...a); } catch (e) { return { __err: e.message }; } },
  };
}

// ── Privacy engine ────────────────────────────────────────────────────────────
// When strict mode is on, member PII (name / phone / CIN) is swapped for a stable
// per-request pseudonym BEFORE anything reaches OpenAI; `restore()` swaps them back
// in the model's reply so the director still sees the real value. OpenAI never sees
// a real member identity. When disabled, every method is a no-op passthrough.
function makePrivacy(enabled) {
  const fwd = new Map();  // `${kind}::${real}` → pseudonym
  const rev = [];         // { pseudo, real }
  let n = 0;
  const LABEL = { member: 'Membre', tel: 'Tel', cin: 'CIN' };
  const tok = (real, kind) => {
    if (real == null || real === '' || typeof real === 'number') return real;
    const s = String(real);
    const key = `${kind}::${s}`;
    if (fwd.has(key)) return fwd.get(key);
    n += 1;
    const pseudo = `${LABEL[kind] || 'X'}-${String(n).padStart(3, '0')}`;
    fwd.set(key, pseudo); rev.push({ pseudo, real: s });
    return pseudo;
  };
  return {
    enabled: !!enabled,
    name: (v) => enabled ? tok(v, 'member') : v,
    tel:  (v) => enabled ? tok(v, 'tel') : v,
    cin:  (v) => enabled ? tok(v, 'cin') : v,
    // swap pseudonyms → real in outgoing text (longest pseudonym first to avoid prefix collisions)
    restore: (text) => {
      if (!enabled || !text) return text;
      let out = String(text);
      rev.slice().sort((a, b) => b.pseudo.length - a.pseudo.length).forEach(({ pseudo, real }) => { out = out.split(pseudo).join(real); });
      return out;
    },
  };
}

// ── OpenAI function-tool schemas ──────────────────────────────────────────────
const TOOL_SCHEMAS = [
  {
    type: 'function',
    function: {
      name: 'get_kpi_overview',
      description: "Vue d'ensemble instantanée de toute l'entreprise (les 4 clubs ou un club): CA du mois, objectif, dette totale, décaissements, membres actifs/expirants, incidents, et CA+croissance par club. À utiliser en premier pour comprendre la situation globale.",
      parameters: { type: 'object', properties: { gym: { type: 'string', description: "Club: 'all' (défaut), 'dokarat', 'marjane', 'casa1', 'casa2'" } } },
    },
  },
  {
    type: 'function',
    function: {
      name: 'get_member',
      description: "Cherche un membre par nom, téléphone ou CIN. Retourne son profil (club, plan, expiration) et son historique de paiements + reste à payer (dette).",
      parameters: { type: 'object', properties: { query: { type: 'string', description: 'Nom, prénom, téléphone ou CIN du membre' } }, required: ['query'] },
    },
  },
  {
    type: 'function',
    function: {
      name: 'get_club_revenue',
      description: "Chiffre d'affaires d'un club (ou tous) pour un mois donné: total, répartition par mode de paiement, inscriptions, top formules, comparaison au mois précédent. Si club='all', retourne AUSSI 'par_club' (le CA de chacun des 4 clubs) — utilise CE champ pour répondre à 'quel club a le plus/le moins de CA', jamais le total.",
      parameters: { type: 'object', properties: {
        club: { type: 'string', description: "Club: 'all', 'dokarat', 'marjane', 'casa1', 'casa2', ou un nom (Casa Anfa...)" },
        month: { type: 'string', description: "Mois: 'YYYY-MM', nom (Mai), ou relatif ('mois dernier', 'ce mois'). Défaut = mois courant." },
      } },
    },
  },
  {
    type: 'function',
    function: {
      name: 'list_decaissements',
      description: "Liste les décaissements (dépenses/sorties de caisse) d'un mois, triés par montant ou date. Utile pour 'le plus gros décaissement de Mai', 'les dépenses de ce mois', etc. Retourne chaque dépense avec montant, raison, catégorie, club, date, statut.",
      parameters: { type: 'object', properties: {
        month: { type: 'string', description: "Mois: 'YYYY-MM', nom (Mai), ou relatif ('mois dernier', 'ce mois'). Défaut = mois courant." },
        gym: { type: 'string', description: "Club ou 'all'" },
        sort: { type: 'string', enum: ['amount', 'date'], description: "Tri: 'amount' (plus gros d'abord, défaut) ou 'date'" },
        limit: { type: 'integer', description: 'Nombre max (défaut 15)' },
      } },
    },
  },
  {
    type: 'function',
    function: {
      name: 'get_expense_breakdown',
      description: "Répartition des décaissements par catégorie (Salaires, Loyer, Énergie, Matériel, Marketing, Produits, Entretien, Internet, Autre) pour un mois, avec le ratio dépenses/CA. Utile pour analyser où part l'argent et la marge.",
      parameters: { type: 'object', properties: {
        month: { type: 'string', description: "Mois 'YYYY-MM' ou nom. Défaut = mois courant." },
        gym: { type: 'string', description: "Club ou 'all'" },
      } },
    },
  },
  {
    type: 'function',
    function: {
      name: 'get_debtors',
      description: "Liste des membres avec un reste à payer (dette), triés du plus gros au plus petit, avec le total de la dette.",
      parameters: { type: 'object', properties: {
        gym: { type: 'string', description: "Club ou 'all'" },
        limit: { type: 'integer', description: 'Nombre max (défaut 15)' },
      } },
    },
  },
  {
    type: 'function',
    function: {
      name: 'get_commercial_performance',
      description: "Performance des commerciaux pour un mois: inscriptions, CA généré, ticket moyen, par commercial et par club.",
      parameters: { type: 'object', properties: {
        month: { type: 'string', description: "Mois 'YYYY-MM' ou nom. Défaut = mois courant." },
        gym: { type: 'string', description: "Club ou 'all'" },
      } },
    },
  },
  {
    type: 'function',
    function: {
      name: 'get_churn_risk',
      description: "Membres à RISQUE de non-renouvellement (churn), classés du plus risqué au moins risqué, avec un score, le niveau (CRITIQUE/ÉLEVÉ/MODÉRÉ) et les raisons (expiration proche/dépassée, dette, formule courte). Utile pour 'qui risque de partir', 'qui appeler en priorité pour la relance'.",
      parameters: { type: 'object', properties: {
        gym: { type: 'string', description: "Club ou 'all'" },
        limit: { type: 'integer', description: 'Nombre max (défaut 20)' },
      } },
    },
  },
  {
    type: 'function',
    function: {
      name: 'search_activity_log',
      description: "Journal d'activité des managers/staff (audit): qui a fait quoi, quelle page, quand — y compris l'usage du CODE responsable dans le registre. Utile pour surveiller l'activité ('qu'a fait tel manager', 'qui a utilisé le code', 'activité de Casa Anfa cette semaine').",
      parameters: { type: 'object', properties: {
        query: { type: 'string', description: "Mot-clé à filtrer (action, nom, page). Optionnel." },
        gym: { type: 'string', description: "Club ou 'all'" },
        days: { type: 'integer', description: 'Fenêtre en jours (défaut 30)' },
        limit: { type: 'integer', description: 'Nombre max (défaut 25)' },
      } },
    },
  },
];

// ── executors ─────────────────────────────────────────────────────────────────
function execute(db, name, args = {}, priv) {
  if (!db) return { error: 'DB indisponible' };
  const q = makeQ(db);
  const P = priv || makePrivacy(false); // no-op passthrough when privacy off
  try {
    switch (name) {
      case 'get_kpi_overview':      return toolKpiOverview(q, args);
      case 'get_member':            return toolGetMember(q, args, P);
      case 'get_club_revenue':      return toolClubRevenue(q, args);
      case 'list_decaissements':    return toolListDecaissements(q, args);
      case 'get_expense_breakdown': return toolExpenseBreakdown(q, args);
      case 'get_debtors':           return toolGetDebtors(q, args, P);
      case 'get_churn_risk':        return toolChurnRisk(q, args, P);
      case 'get_commercial_performance': return toolCommercialPerf(q, args);
      case 'search_activity_log':   return toolSearchActivity(q, args);
      default: return { error: `Outil inconnu: ${name}` };
    }
  } catch (e) {
    return { error: e.message };
  }
}

function gymScopeSql(gym) {
  const g = resolveGym(gym);
  if (g === null) return { bad: true };
  if (g === 'all') return { where: `gym_id IN ('${VALID_GYMS.join("','")}')`, gyms: VALID_GYMS, scope: 'all' };
  return { where: `gym_id='${g}'`, gyms: [g], scope: g };
}

function toolKpiOverview(q, { gym }) {
  const sc = gymScopeSql(gym); if (sc.bad) return { error: 'Club non reconnu' };
  const ym = currentYm();
  const today = nowMorocco().toISOString().slice(0, 10);
  const revExpr = 'CAST(tpe AS REAL)+CAST(espece AS REAL)+CAST(virement AS REAL)+CAST(cheque AS REAL)';
  const month = q.get(`SELECT COALESCE(SUM(${revExpr}),0) v, COUNT(*) c FROM register_cache WHERE strftime('%Y-%m',date)=? AND ${sc.where}`, ym);
  const day = q.get(`SELECT COALESCE(SUM(${revExpr}),0) v FROM register_cache WHERE date=? AND ${sc.where}`, today);
  const dec = q.get(`SELECT COALESCE(SUM(montant),0) v, COUNT(*) c FROM decaissements_cache WHERE strftime('%Y-%m',date)=? AND ${sc.where.replace(/gym_id/g,'gym_id')}`, ym);
  const debt = q.get(`SELECT COALESCE(SUM(${RESTE_EXPR}),0) total, COUNT(*) cnt FROM register_cache r WHERE ${NOT_SETTLED} AND ${RESTE_EXPR}>0 AND r.${sc.where}`);
  const active = q.get(`SELECT COUNT(*) c FROM members_cache WHERE is_archive=0 AND ${sc.where}`);
  const expiring = q.get(`SELECT COUNT(*) c FROM members_cache WHERE is_archive=0 AND ${sc.where} AND expires_on IS NOT NULL AND expires_on<date('now','+30 days') AND expires_on>date('now')`);
  const incidents = q.get(`SELECT COUNT(*) c FROM incidents_cache WHERE status!='Resolved' AND ${sc.where}`);
  const perGym = q.all(`SELECT gym_id, ROUND(SUM(${revExpr}),0) rev, COUNT(*) inc FROM register_cache WHERE strftime('%Y-%m',date)=? AND ${sc.where} GROUP BY gym_id`, ym);
  return {
    period: ym, scope: sc.scope === 'all' ? 'ALL EMPIRE' : GYM_NAMES[sc.scope],
    ca_mois_dh: Math.round(month?.v || 0), inscriptions_mois: month?.c || 0, ca_aujourdhui_dh: Math.round(day?.v || 0),
    decaissements_mois_dh: Math.round(dec?.v || 0), decaissements_count: dec?.c || 0,
    dette_totale_dh: Math.round(debt?.total || 0), membres_en_dette: debt?.cnt || 0,
    membres_actifs: active?.c || 0, expirent_30j: expiring?.c || 0, incidents_ouverts: incidents?.c || 0,
    par_club: perGym.map(g => ({ club: GYM_NAMES[g.gym_id] || g.gym_id, ca_dh: Math.round(g.rev || 0), inscriptions: g.inc })),
  };
}

function toolGetMember(q, { query }, P) {
  if (!query || String(query).trim().length < 2) return { error: 'Requête trop courte' };
  const like = `%${String(query).trim().toLowerCase()}%`;
  const matches = q.all(
    `SELECT id, full_name, phone, cin, gym_id, plan, expires_on, is_archive FROM members_cache
     WHERE (LOWER(full_name) LIKE ? OR REPLACE(phone,' ','') LIKE ? OR LOWER(cin) LIKE ?)
     ORDER BY is_archive ASC LIMIT 6`, like, like.replace(/\s/g, ''), like);
  if (!Array.isArray(matches) || matches.length === 0) return { found: false, message: 'Aucun membre trouvé' };
  // PII (name/phone/cin) is pseudonymized here when privacy is strict; restored in the reply.
  const list = matches.map(m => ({ name: P.name(m.full_name), club: GYM_NAMES[m.gym_id] || m.gym_id, phone: P.tel(m.phone), cin: P.cin(m.cin), plan: m.plan, expires_on: m.expires_on, archived: m.is_archive === 1 }));
  const top = matches[0];
  const nameLike = `%${(top.full_name || '').toLowerCase()}%`;
  const tx = q.all(
    `SELECT r.date, r.gym_id, r.abonnement, ROUND(CAST(r.prix AS REAL),0) prix,
            ROUND(COALESCE(CAST(r.tpe AS REAL),0)+COALESCE(CAST(r.espece AS REAL),0)+COALESCE(CAST(r.virement AS REAL),0)+COALESCE(CAST(r.cheque AS REAL),0),0) paye,
            ROUND(${RESTE_EXPR},0) reste, r.commercial
     FROM register_cache r WHERE LOWER(r.nom) LIKE ? ORDER BY r.date DESC LIMIT 12`, nameLike);
  const txArr = Array.isArray(tx) ? tx : [];
  const debt = txArr.reduce((s, t) => s + Math.max(0, t.reste || 0), 0);
  return {
    found: true, matches: list,
    detail_pour: P.name(top.full_name),
    dette_dh: Math.round(debt),
    transactions: txArr.map(t => ({ date: t.date, club: GYM_NAMES[t.gym_id] || t.gym_id, formule: t.abonnement, prix_dh: t.prix, paye_dh: t.paye, reste_dh: Math.max(0, t.reste || 0), commercial: t.commercial })),
  };
}

function toolClubRevenue(q, { club, month }) {
  const sc = gymScopeSql(club); if (sc.bad) return { error: 'Club non reconnu' };
  const ym = resolveMonth(month); if (!ym) return { error: "Mois invalide (utilise 'YYYY-MM' ou un nom de mois)" };
  const row = q.get(`SELECT COALESCE(SUM(CAST(espece AS REAL)),0) es, COALESCE(SUM(CAST(virement AS REAL)),0) vi, COALESCE(SUM(CAST(cheque AS REAL)),0) ch, COALESCE(SUM(CAST(tpe AS REAL)),0) tp, COUNT(*) c FROM register_cache WHERE strftime('%Y-%m',date)=? AND ${sc.where}`, ym);
  const total = Math.round((row?.es || 0) + (row?.vi || 0) + (row?.ch || 0) + (row?.tp || 0));
  // previous month for comparison
  const [y, mo] = ym.split('-').map(Number);
  const prevYm = mo === 1 ? `${y - 1}-12` : `${y}-${String(mo - 1).padStart(2, '0')}`;
  const prev = q.get(`SELECT COALESCE(SUM(CAST(tpe AS REAL)+CAST(espece AS REAL)+CAST(virement AS REAL)+CAST(cheque AS REAL)),0) v FROM register_cache WHERE strftime('%Y-%m',date)=? AND ${sc.where}`, prevYm);
  const prevTotal = Math.round(prev?.v || 0);
  const formulas = q.all(`SELECT abonnement name, COUNT(*) cnt, ROUND(SUM(CAST(prix AS REAL)),0) rev FROM register_cache WHERE strftime('%Y-%m',date)=? AND ${sc.where} AND abonnement IS NOT NULL AND abonnement!='' GROUP BY abonnement ORDER BY rev DESC LIMIT 6`, ym);
  // When scope is 'all', break out each club so the model attributes CA correctly
  // ("quel club a le plus") instead of mislabeling the empire total as one club.
  let par_club;
  if (sc.scope === 'all') {
    const perGym = q.all(`SELECT gym_id, ROUND(SUM(CAST(tpe AS REAL)+CAST(espece AS REAL)+CAST(virement AS REAL)+CAST(cheque AS REAL)),0) rev, COUNT(*) inc FROM register_cache WHERE strftime('%Y-%m',date)=? AND ${sc.where} GROUP BY gym_id ORDER BY rev DESC`, ym);
    par_club = (Array.isArray(perGym) ? perGym : []).map(g => ({ club: GYM_NAMES[g.gym_id] || g.gym_id, ca_dh: Math.round(g.rev || 0), inscriptions: g.inc }));
  }
  return {
    club: sc.scope === 'all' ? 'ALL EMPIRE' : GYM_NAMES[sc.scope], mois: ym,
    ca_total_dh: total, inscriptions: row?.c || 0,
    ...(par_club ? { note: "ca_total_dh = total des 4 clubs. Pour le CA par club, utilise par_club.", par_club } : {}),
    modes_paiement: { especes_dh: Math.round(row?.es || 0), carte_tpe_dh: Math.round(row?.tp || 0), virement_dh: Math.round(row?.vi || 0), cheque_dh: Math.round(row?.ch || 0) },
    mois_precedent_dh: prevTotal, variation_pct: prevTotal > 0 ? parseFloat(((total - prevTotal) / prevTotal * 100).toFixed(1)) : null,
    top_formules: (Array.isArray(formulas) ? formulas : []).map(f => ({ formule: f.name, vendus: f.cnt, ca_dh: Math.round(f.rev || 0) })),
  };
}

function toolListDecaissements(q, { month, gym, sort, limit }) {
  const sc = gymScopeSql(gym); if (sc.bad) return { error: 'Club non reconnu' };
  const ym = resolveMonth(month); if (!ym) return { error: 'Mois invalide' };
  const order = sort === 'date' ? 'date DESC' : 'montant DESC';
  const lim = Math.min(Math.max(parseInt(limit) || 15, 1), 40);
  const rows = q.all(`SELECT gym_id, date, ROUND(montant,0) montant, raison, status, requested_by FROM decaissements_cache WHERE strftime('%Y-%m',date)=? AND ${sc.where} ORDER BY ${order} LIMIT ?`, ym, lim);
  const totalRow = q.get(`SELECT COALESCE(SUM(montant),0) v, COUNT(*) c FROM decaissements_cache WHERE strftime('%Y-%m',date)=? AND ${sc.where}`, ym);
  const arr = Array.isArray(rows) ? rows : [];
  return {
    mois: ym, club: sc.scope === 'all' ? 'ALL EMPIRE' : GYM_NAMES[sc.scope],
    total_dh: Math.round(totalRow?.v || 0), nombre: totalRow?.c || 0,
    decaissements: arr.map(d => ({ montant_dh: Math.round(d.montant || 0), raison: d.raison, categorie: categorizeExpense(d.raison).label, club: GYM_NAMES[d.gym_id] || d.gym_id, date: d.date, statut: d.status, demande_par: d.requested_by })),
  };
}

function toolExpenseBreakdown(q, { month, gym }) {
  const sc = gymScopeSql(gym); if (sc.bad) return { error: 'Club non reconnu' };
  const ym = resolveMonth(month); if (!ym) return { error: 'Mois invalide' };
  const rows = q.all(`SELECT montant, raison FROM decaissements_cache WHERE strftime('%Y-%m',date)=? AND ${sc.where}`, ym);
  const arr = Array.isArray(rows) ? rows : [];
  const buckets = {};
  let total = 0;
  for (const d of arr) {
    const c = categorizeExpense(d.raison);
    const amt = Number(d.montant) || 0;
    total += amt;
    if (!buckets[c.key]) buckets[c.key] = { categorie: c.label, total_dh: 0, count: 0 };
    buckets[c.key].total_dh += amt; buckets[c.key].count += 1;
  }
  const revRow = q.get(`SELECT COALESCE(SUM(CAST(tpe AS REAL)+CAST(espece AS REAL)+CAST(virement AS REAL)+CAST(cheque AS REAL)),0) v FROM register_cache WHERE strftime('%Y-%m',date)=? AND ${sc.where}`, ym);
  const ca = Math.round(revRow?.v || 0);
  const list = Object.values(buckets).map(b => ({ ...b, total_dh: Math.round(b.total_dh), pct_des_depenses: total > 0 ? Math.round(b.total_dh / total * 100) : 0 })).sort((a, b) => b.total_dh - a.total_dh);
  return {
    mois: ym, club: sc.scope === 'all' ? 'ALL EMPIRE' : GYM_NAMES[sc.scope],
    depenses_totales_dh: Math.round(total), ca_dh: ca,
    ratio_depenses_sur_ca_pct: ca > 0 ? parseFloat((total / ca * 100).toFixed(1)) : null,
    par_categorie: list,
  };
}

function toolGetDebtors(q, { gym, limit }, P) {
  const sc = gymScopeSql(gym); if (sc.bad) return { error: 'Club non reconnu' };
  const lim = Math.min(Math.max(parseInt(limit) || 15, 1), 40);
  const rows = q.all(`SELECT r.nom, r.gym_id, ROUND(${RESTE_EXPR},0) reste, r.date, r.note_reste FROM register_cache r WHERE ${NOT_SETTLED} AND ${RESTE_EXPR}>0 AND r.${sc.where} ORDER BY reste DESC LIMIT ?`, lim);
  const tot = q.get(`SELECT COALESCE(SUM(${RESTE_EXPR}),0) total, COUNT(*) cnt FROM register_cache r WHERE ${NOT_SETTLED} AND ${RESTE_EXPR}>0 AND r.${sc.where}`);
  const arr = Array.isArray(rows) ? rows : [];
  return {
    club: sc.scope === 'all' ? 'ALL EMPIRE' : GYM_NAMES[sc.scope],
    dette_totale_dh: Math.round(tot?.total || 0), nombre_debiteurs: tot?.cnt || 0,
    debiteurs: arr.map(d => ({ nom: P.name(d.nom), club: GYM_NAMES[d.gym_id] || d.gym_id, reste_dh: Math.round(d.reste || 0), date: d.date, note: d.note_reste })),
  };
}

// ── Churn risk: deterministic, explainable scoring (expiry + debt + plan) ──────
// Reusable core (real names); the tool wrapper pseudonymizes under privacy mode,
// the /api/ai/churn-risk endpoint uses it directly (real names to the dashboard).
function computeChurn(q, { gym, limit } = {}) {
  const sc = gymScopeSql(gym); if (sc.bad) return { error: 'Club non reconnu' };
  const lim = Math.min(Math.max(parseInt(limit) || 20, 1), 60);
  // Actionable window only: expiring within 45 days (save them) or expired within
  // the last 45 days (recoverable win-back). Excludes members long gone (8 months+).
  const rows = q.all(`SELECT id, full_name, gym_id, plan, expires_on,
      CAST(julianday(expires_on) - julianday('now') AS INTEGER) AS dte
    FROM members_cache
    WHERE is_archive=0 AND ${sc.where} AND expires_on IS NOT NULL AND expires_on!=''
      AND date(expires_on) < date('now','+45 days')
      AND date(expires_on) > date('now','-45 days')
    ORDER BY expires_on ASC LIMIT 400`);
  const arr = Array.isArray(rows) ? rows : [];
  // best-effort debt-by-name map (extra risk signal; not critical if unmatched)
  const debtRows = q.all(`SELECT LOWER(r.nom) nom, ROUND(SUM(${RESTE_EXPR}),0) reste FROM register_cache r WHERE ${NOT_SETTLED} AND ${RESTE_EXPR}>0 AND r.${sc.where} GROUP BY LOWER(r.nom)`);
  const debtMap = {};
  (Array.isArray(debtRows) ? debtRows : []).forEach(d => { if (d.nom) debtMap[d.nom] = d.reste || 0; });
  const findDebt = (name) => {
    const n = (name || '').toLowerCase().trim(); if (!n) return 0;
    if (debtMap[n]) return debtMap[n];
    for (const k in debtMap) { if (k.length > 3 && (n.includes(k) || k.includes(n))) return debtMap[k]; }
    return 0;
  };
  const scored = arr.map(m => {
    const dte = m.dte; let score = 0; const reasons = [];
    if (dte >= 0 && dte <= 7) { score += 48; reasons.push(`Expire dans ${dte}j — à sauver maintenant`); }
    else if (dte < 0) { score += 44; reasons.push(`Expiré depuis ${Math.abs(dte)}j — à récupérer`); }
    else if (dte <= 30) { score += 28; reasons.push(`Expire dans ${dte}j`); }
    else { score += 12; reasons.push(`Expire dans ${dte}j`); }
    const debt = findDebt(m.full_name);
    if (debt > 0) { score += Math.min(22, 12 + Math.round(debt / 1000)); reasons.push(`Dette ${Math.round(debt)} DH`); }
    if (/(^|\D)1\s*mois|mensuel|hebdo|semaine|jour/i.test(m.plan || '')) { score += 14; reasons.push('Formule courte'); }
    score = Math.max(0, Math.min(100, score));
    const level = score >= 60 ? 'CRITIQUE' : score >= 40 ? 'ÉLEVÉ' : score >= 25 ? 'MODÉRÉ' : 'FAIBLE';
    return { name: m.full_name, club: GYM_NAMES[m.gym_id] || m.gym_id, plan: m.plan, expires_on: m.expires_on, days_to_expiry: dte, debt_dh: Math.round(debt), score, level, reasons };
  }).sort((a, b) => b.score - a.score).slice(0, lim);
  return {
    club: sc.scope === 'all' ? 'ALL EMPIRE' : GYM_NAMES[sc.scope],
    summary: {
      total_candidates: arr.length,
      critique: scored.filter(x => x.level === 'CRITIQUE').length,
      eleve: scored.filter(x => x.level === 'ÉLEVÉ').length,
      modere: scored.filter(x => x.level === 'MODÉRÉ').length,
    },
    at_risk: scored,
  };
}
function toolChurnRisk(q, args, P) {
  const r = computeChurn(q, args);
  if (r.error) return r;
  return { ...r, at_risk: r.at_risk.map(x => ({ ...x, name: P.name(x.name) })) };
}
// db-level wrapper for the direct dashboard endpoint (always real names)
function churnRisk(db, args = {}) { return computeChurn(makeQ(db), args); }

function toolCommercialPerf(q, { month, gym }) {
  const sc = gymScopeSql(gym); if (sc.bad) return { error: 'Club non reconnu' };
  const ym = resolveMonth(month); if (!ym) return { error: 'Mois invalide' };
  const rows = q.all(`SELECT commercial name, gym_id, COUNT(*) inscriptions, ROUND(SUM(CAST(prix AS REAL)),0) ca, ROUND(AVG(CAST(prix AS REAL)),0) ticket_moyen FROM register_cache WHERE strftime('%Y-%m',date)=? AND ${sc.where} AND commercial IS NOT NULL AND commercial!='' GROUP BY commercial, gym_id ORDER BY ca DESC LIMIT 15`, ym);
  const arr = Array.isArray(rows) ? rows : [];
  return {
    mois: ym, club: sc.scope === 'all' ? 'ALL EMPIRE' : GYM_NAMES[sc.scope],
    commerciaux: arr.map(c => ({ commercial: c.name, club: GYM_NAMES[c.gym_id] || c.gym_id, inscriptions: c.inscriptions, ca_dh: Math.round(c.ca || 0), ticket_moyen_dh: Math.round(c.ticket_moyen || 0) })),
  };
}

function toolSearchActivity(q, { query, gym, days, limit }) {
  const sc = gymScopeSql(gym); if (sc.bad) return { error: 'Club non reconnu' };
  const win = Math.min(Math.max(parseInt(days) || 30, 1), 180);
  const lim = Math.min(Math.max(parseInt(limit) || 25, 1), 60);
  const clauses = [`date >= date('now','-${win} days')`, sc.where];
  const params = [];
  if (query && String(query).trim()) {
    clauses.push('(LOWER(action) LIKE ? OR LOWER(user_name) LIKE ? OR LOWER(page) LIKE ?)');
    const like = `%${String(query).trim().toLowerCase()}%`;
    params.push(like, like, like);
  }
  const rows = q.all(`SELECT date, created_at, user_name, user_role, action, page, method, source, club_name FROM activity_logs_cache WHERE ${clauses.join(' AND ')} ORDER BY created_at DESC LIMIT ?`, ...params, lim);
  const arr = Array.isArray(rows) ? rows : [];
  const pinUse = arr.filter(a => (a.source || '').includes('pin')).length;
  return {
    club: sc.scope === 'all' ? 'ALL EMPIRE' : GYM_NAMES[sc.scope], fenetre_jours: win, nombre: arr.length, usages_code_responsable: pinUse,
    activites: arr.map(a => ({ date: a.date, heure: (a.created_at || '').slice(11, 16), utilisateur: a.user_name, role: a.user_role, action: a.action, page: a.page, club: a.club_name, via: a.source })),
  };
}

module.exports = { TOOL_SCHEMAS, execute, makePrivacy, churnRisk, categorizeExpense, EXPENSE_CATEGORIES, resolveMonth, resolveGym, GYM_NAMES };
