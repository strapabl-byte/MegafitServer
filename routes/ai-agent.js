'use strict';
// routes/ai-agent.js — AURALIX 24/7 AI Business Intelligence Agent
// Full Snapshot Builder + Rules Engine + Actions + Memory + Alerts

const { Router } = require('express');
const { verifyAzureToken, requireAdmin } = require('../middleware/auth');

// ─── Groq caller ──────────────────────────────────────────────────────────────
const GROQ_KEY      = process.env.GROQ_API_KEY || '';
const GROQ_LARGE    = 'llama-3.3-70b-versatile';
const GROQ_SMALL    = 'llama-3.1-8b-instant';

async function callGroq(messages, model = GROQ_LARGE, maxTokens = 1800) {
  if (!GROQ_KEY) throw new Error('GROQ_API_KEY not configured');
  const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${GROQ_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ model, messages, temperature: 0.35, max_tokens: maxTokens })
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Groq HTTP ${res.status}: ${err.slice(0, 300)}`);
  }
  const j = await res.json();
  return j.choices?.[0]?.message?.content?.trim() || '';
}

async function groq(messages, useLarge = true) {
  try {
    return await callGroq(messages, useLarge ? GROQ_LARGE : GROQ_SMALL, useLarge ? 2000 : 1000);
  } catch(e) {
    if (e.message.includes('429') || e.message.includes('rate')) {
      try { return await callGroq(messages, GROQ_SMALL, 800); } catch {}
    }
    throw e;
  }
}

// ─── DB Tables ────────────────────────────────────────────────────────────────
function initAiTables(db) {
  if (!db) return;
  db.exec(`
    CREATE TABLE IF NOT EXISTS ai_actions (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT,
      gym TEXT DEFAULT 'all',
      assigned_to TEXT DEFAULT 'Manager',
      priority TEXT DEFAULT 'MEDIUM',
      expected_impact TEXT,
      status TEXT DEFAULT 'OPEN',
      deadline TEXT,
      source TEXT DEFAULT 'manual',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      completed_at DATETIME
    );
    CREATE TABLE IF NOT EXISTS ai_memory (
      id TEXT PRIMARY KEY,
      type TEXT DEFAULT 'STRATEGY',
      scope TEXT DEFAULT 'ALL_EMPIRE',
      gym TEXT DEFAULT 'all',
      note TEXT NOT NULL,
      importance TEXT DEFAULT 'HIGH',
      created_by TEXT DEFAULT 'owner',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME
    );
    CREATE TABLE IF NOT EXISTS ai_alerts (
      id TEXT PRIMARY KEY,
      alert_type TEXT,
      priority TEXT DEFAULT 'WATCH',
      title TEXT NOT NULL,
      message TEXT,
      gym TEXT DEFAULT 'all',
      status TEXT DEFAULT 'OPEN',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      resolved_at DATETIME
    );
  `);
}

// ─── FULL SNAPSHOT BUILDER — All data AURALIX needs ──────────────────────────
function buildSnapshot(db, getMeta, gymScope = 'all') {
  if (!db) return { error: 'DB not available', meta: { gym_scope: gymScope } };

  const GYMS      = ['dokarat', 'marjane', 'casa1', 'casa2'];
  const GYM_NAMES = { dokarat: 'Fès Doukkarate', marjane: 'Fès Saiss', casa1: 'Casa Anfa', casa2: 'Lady Anfa' };
  // Gyms where door sensor hardware is NOT yet installed — traffic = 0 is a hardware gap, NOT a business signal
  const GYMS_NO_DOOR_SENSOR = ['casa1', 'casa2'];
  const targetGyms = gymScope === 'all' ? GYMS : [gymScope];
  // Only include gyms WITH sensor in traffic-related queries
  const trafficGyms = targetGyms.filter(g => !GYMS_NO_DOOR_SENSOR.includes(g));
  const trafficGymIn = trafficGyms.length > 0 ? trafficGyms.map(() => '?').join(',') : "'__none__'";
  const gymIn     = targetGyms.map(() => '?').join(',');

  const now      = new Date(Date.now() + 3600000); // Morocco +1h
  const today    = now.toISOString().slice(0, 10);
  const ym       = today.slice(0, 7);
  const curMonth = String(now.getMonth() + 1).padStart(2, '0');
  const daysInMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate();
  const dayOfMonth  = now.getDate();

  const prevDate = new Date(now.getFullYear(), now.getMonth() - 1, 1);
  const prevYm   = `${prevDate.getFullYear()}-${String(prevDate.getMonth()+1).padStart(2,'0')}`;
  const weekAgo  = new Date(now.getTime() - 7 * 86400000).toISOString().slice(0, 10);

  // helper — safe query
  const q = (sql, ...args) => { try { return db.prepare(sql).all(...args); } catch { return []; } };
  const q1 = (sql, ...args) => { try { return db.prepare(sql).get(...args); } catch { return null; } };

  // ── Revenue ────────────────────────────────────────────────────────────────
  const revSum = (period_filter, args) => {
    const r = q1(`SELECT COALESCE(SUM(CAST(tpe AS REAL)+CAST(espece AS REAL)+CAST(virement AS REAL)+CAST(cheque AS REAL)),0) v, COUNT(*) c FROM register_cache WHERE ${period_filter} AND gym_id IN (${gymIn})`, ...args, ...targetGyms);
    return { total: Math.round(r?.v || 0), count: r?.c || 0 };
  };
  const monthRev  = revSum("strftime('%Y-%m', date)=?", [ym]);
  const todayRev  = revSum("date=?", [today]);
  const weekRev   = revSum("date>=?", [weekAgo]);
  const yearRev   = revSum("strftime('%Y', date)=?", [String(now.getFullYear())]);
  const prevRev   = revSum("strftime('%Y-%m', date)=?", [prevYm]);

  const monthlyGoal = parseInt(getMeta?.('auralix_revenue_goal') || 0) || 0;
  const vsPrev = prevRev.total > 0 ? parseFloat(((monthRev.total - prevRev.total) / prevRev.total * 100).toFixed(1)) : 0;

  // ── Payment method breakdown ───────────────────────────────────────────────
  const payRow = q1(`SELECT COALESCE(SUM(CAST(espece AS REAL)),0) es, COALESCE(SUM(CAST(virement AS REAL)),0) vi, COALESCE(SUM(CAST(cheque AS REAL)),0) ch, COALESCE(SUM(CAST(tpe AS REAL)),0) tp FROM register_cache WHERE strftime('%Y-%m', date)=? AND gym_id IN (${gymIn})`, ym, ...targetGyms);
  const payTotal = Math.round((payRow?.es||0)+(payRow?.vi||0)+(payRow?.ch||0)+(payRow?.tp||0)) || 1;
  const payments = {
    espece:   { amount: Math.round(payRow?.es||0), pct: Math.round((payRow?.es||0)/payTotal*100) },
    virement: { amount: Math.round(payRow?.vi||0), pct: Math.round((payRow?.vi||0)/payTotal*100) },
    cheque:   { amount: Math.round(payRow?.ch||0), pct: Math.round((payRow?.ch||0)/payTotal*100) },
    tpe:      { amount: Math.round(payRow?.tp||0), pct: Math.round((payRow?.tp||0)/payTotal*100) },
  };

  // ── Subscription formula velocity ─────────────────────────────────────────
  const pkgs = q(`SELECT abonnement name, COUNT(*) cnt, SUM(prix) rev FROM register_cache WHERE strftime('%Y-%m', date)=? AND gym_id IN (${gymIn}) AND abonnement IS NOT NULL AND abonnement!='' GROUP BY abonnement ORDER BY cnt DESC LIMIT 8`, ym, ...targetGyms);
  const bestPackage = pkgs[0]?.name || '';

  // ── Commercial performance (from register_cache.commercial) ────────────────
  const commRows = q(`SELECT commercial name, gym_id gym, COUNT(*) inscriptions, ROUND(SUM(CAST(prix AS REAL)),0) revenue, ROUND(AVG(CAST(prix AS REAL)),0) avg_ticket FROM register_cache WHERE strftime('%Y-%m', date)=? AND commercial IS NOT NULL AND commercial!='' AND gym_id IN (${gymIn}) GROUP BY commercial, gym_id ORDER BY revenue DESC LIMIT 12`, ym, ...targetGyms);

  const prevCommRows = q(`SELECT commercial name, gym_id gym, ROUND(SUM(CAST(prix AS REAL)),0) revenue FROM register_cache WHERE strftime('%Y-%m', date)=? AND commercial IS NOT NULL AND commercial!='' AND gym_id IN (${gymIn}) GROUP BY commercial, gym_id`, prevYm, ...targetGyms);
  const prevCommMap = {};
  prevCommRows.forEach(r => { prevCommMap[`${r.name}|${r.gym}`] = r.revenue || 0; });

  const commercials = commRows.map(c => {
    const goalKey = `auralix_goal_commercial_${c.name.toLowerCase().replace(/\s+/g,'_')}`;
    const goal = parseInt(getMeta?.(goalKey) || 0) || 0;
    const prevRev = prevCommMap[`${c.name}|${c.gym}`] || 0;
    const trend = prevRev > 0 ? (c.revenue > prevRev ? 'up' : c.revenue < prevRev * 0.9 ? 'down' : 'stable') : 'new';
    return { name: c.name, gym: c.gym, gym_name: GYM_NAMES[c.gym] || c.gym, inscriptions: c.inscriptions, revenue: Math.round(c.revenue||0), avg_ticket: Math.round(c.avg_ticket||0), goal, goal_pct: goal > 0 ? Math.round(c.revenue/goal*100) : null, trend, prev_month_revenue: Math.round(prevRev) };
  });

  // ── Per-gym breakdown ──────────────────────────────────────────────────────
  const gyms = targetGyms.map(gid => {
    const sensorInstalled = !GYMS_NO_DOOR_SENSOR.includes(gid);
    const cur  = q1(`SELECT COALESCE(SUM(CAST(tpe AS REAL)+CAST(espece AS REAL)+CAST(virement AS REAL)+CAST(cheque AS REAL)),0) revenue, COUNT(*) members FROM register_cache WHERE strftime('%Y-%m', date)=? AND gym_id=?`, ym, gid);
    const prev = q1(`SELECT COALESCE(SUM(CAST(tpe AS REAL)+CAST(espece AS REAL)+CAST(virement AS REAL)+CAST(cheque AS REAL)),0) revenue FROM register_cache WHERE strftime('%Y-%m', date)=? AND gym_id=?`, prevYm, gid);
    const rev    = Math.round(cur?.revenue || 0);
    const prevR  = Math.round(prev?.revenue || 0);
    const growth = prevR > 0 ? parseFloat(((rev - prevR) / prevR * 100).toFixed(1)) : 0;
    // Only query traffic if sensor is installed — otherwise mark as N/A
    const traffic = sensorInstalled ? q1(`SELECT COALESCE(SUM(count),0) v FROM daily_stats WHERE strftime('%Y-%m', date)=? AND gym_id=?`, ym, gid) : null;
    const todayT  = sensorInstalled ? q1(`SELECT COALESCE(SUM(count),0) v FROM daily_stats WHERE date=? AND gym_id=?`, today, gid) : null;
    const openInc = q1(`SELECT COUNT(*) cnt FROM incidents_cache WHERE gym_id=? AND status!='Resolved'`, gid);
    const debt    = q1(`SELECT COALESCE(SUM(reste),0) total, COUNT(*) cnt FROM register_cache WHERE gym_id=? AND reste>0`, gid);
    const activeM = q1(`SELECT COUNT(*) cnt FROM members_cache WHERE gym_id=? AND is_archive=0`, gid);
    const expiringM = q1(`SELECT COUNT(*) cnt FROM members_cache WHERE gym_id=? AND is_archive=0 AND expires_on IS NOT NULL AND expires_on < date('now','+30 days') AND expires_on > date('now')`, gid);
    const expiredM  = q1(`SELECT COUNT(*) cnt FROM members_cache WHERE gym_id=? AND is_archive=0 AND expires_on IS NOT NULL AND expires_on < date('now')`, gid);
    return {
      id: gid, name: GYM_NAMES[gid],
      door_sensor_installed: sensorInstalled,
      revenue: rev, prev_revenue: prevR, growth_pct: growth,
      new_members_month: cur?.members || 0,
      active_members: activeM?.cnt || 0,
      expiring_30d: expiringM?.cnt || 0,
      expired_not_renewed: expiredM?.cnt || 0,
      // null = sensor not installed; 0 = sensor installed but no entries
      traffic_month: sensorInstalled ? Math.round(traffic?.v || 0) : null,
      traffic_today: sensorInstalled ? Math.round(todayT?.v || 0) : null,
      open_incidents: openInc?.cnt || 0,
      total_debt: Math.round(debt?.total || 0),
      debt_members: debt?.cnt || 0,
      status: growth >= 5 ? 'HEALTHY' : growth >= -5 ? 'WATCH' : 'WARNING',
    };
  });

  // ── Debt analysis ──────────────────────────────────────────────────────────
  const debtRow  = q1(`SELECT COALESCE(SUM(reste),0) total, COUNT(*) cnt FROM register_cache WHERE reste>0 AND gym_id IN (${gymIn})`, ...targetGyms);
  const topDebtors = q(`SELECT nom, gym_id, reste, note_reste, date FROM register_cache WHERE reste>0 AND gym_id IN (${gymIn}) ORDER BY reste DESC LIMIT 10`, ...targetGyms);

  // ── Members lifecycle ──────────────────────────────────────────────────────
  const activeMem   = q1(`SELECT COUNT(*) cnt FROM members_cache WHERE is_archive=0 AND gym_id IN (${gymIn})`, ...targetGyms);
  const expiringMem = q(`SELECT gym_id, full_name, expires_on, plan FROM members_cache WHERE is_archive=0 AND gym_id IN (${gymIn}) AND expires_on IS NOT NULL AND expires_on < date('now','+30 days') AND expires_on > date('now') ORDER BY expires_on ASC LIMIT 20`, ...targetGyms);
  const expiredMem  = q1(`SELECT COUNT(*) cnt FROM members_cache WHERE is_archive=0 AND gym_id IN (${gymIn}) AND expires_on IS NOT NULL AND expires_on < date('now')`, ...targetGyms);

  // ── Pending inscriptions ───────────────────────────────────────────────────
  const pendingRows = q(`SELECT gym_id, nom, prenom, subscriptionName, total, status, date FROM pending_cache WHERE status='pending' AND gym_id IN (${gymIn}) ORDER BY date DESC LIMIT 10`, ...targetGyms);

  // ── Décaissements (cash outflows) ──────────────────────────────────────────
  const decaisMonth = q1(`SELECT COALESCE(SUM(montant),0) total, COUNT(*) cnt FROM decaissements_cache WHERE strftime('%Y-%m', date)=? AND gym_id IN (${gymIn})`, ym, ...targetGyms);
  const decaisTop   = q(`SELECT gym_id, date, montant, raison, status FROM decaissements_cache WHERE strftime('%Y-%m', date)=? AND gym_id IN (${gymIn}) ORDER BY montant DESC LIMIT 10`, ym, ...targetGyms);
  const decaisByGym = q(`SELECT gym_id, ROUND(SUM(montant),0) total FROM decaissements_cache WHERE strftime('%Y-%m', date)=? AND gym_id IN (${gymIn}) GROUP BY gym_id`, ym, ...targetGyms);

  // ── Incidents ──────────────────────────────────────────────────────────────
  const openInc = q(`SELECT gym_id, title, cause, emergency, status, date FROM incidents_cache WHERE status!='Resolved' AND gym_id IN (${gymIn}) ORDER BY created_at DESC`, ...targetGyms);
  const incSummary = { open_total: openInc.length, critical: openInc.filter(r=>r.emergency==='Critique').length, high: openInc.filter(r=>r.emergency==='Elevée').length, normal: openInc.filter(r=>r.emergency==='Normale').length, list: openInc.slice(0,8) };

  // ── Courses / Schedule ─────────────────────────────────────────────────────
  const courseRows = q(`SELECT title, coach, days, time, reserved, capacity, gym_id FROM courses_cache WHERE gym_id IN (${gymIn}) ORDER BY reserved DESC`, ...targetGyms);
  const courseStats = {
    total: courseRows.length,
    avg_fill_pct: courseRows.length > 0 ? Math.round(courseRows.reduce((s, c) => s + (c.capacity > 0 ? c.reserved/c.capacity : 0), 0) / courseRows.length * 100) : 0,
    full_courses: courseRows.filter(c => c.capacity > 0 && c.reserved >= c.capacity).length,
    popular: courseRows.slice(0, 5).map(c => ({ title: c.title, coach: c.coach, gym: c.gym_id, reserved: c.reserved, capacity: c.capacity, fill_pct: c.capacity > 0 ? Math.round(c.reserved/c.capacity*100) : 0 })),
  };

  // ── Resub intelligence ─────────────────────────────────────────────────────
  let resubData = { possible_count: 0, resub_count: 0, new_count: 0, top_possible: [] };
  try {
    const vCol = db.prepare("PRAGMA table_info(resub_intelligence_cache)").all().map(c=>c.name);
    const hasVerdict = vCol.includes('verdict');
    const hasType    = vCol.includes('type');
    if (hasVerdict) {
      const rv = q(`SELECT verdict, COUNT(*) cnt FROM resub_intelligence_cache WHERE gym_id IN (${gymIn}) GROUP BY verdict`, ...targetGyms);
      rv.forEach(r => {
        if (r.verdict === 'POSSIBLE_RESUB') resubData.possible_count = r.cnt;
        if (r.verdict === 'RESUB') resubData.resub_count = r.cnt;
        if (r.verdict === 'NEW') resubData.new_count = r.cnt;
      });
      resubData.top_possible = q(`SELECT nom_key name, gym_id gym FROM resub_intelligence_cache WHERE verdict='POSSIBLE_RESUB' AND gym_id IN (${gymIn}) LIMIT 10`, ...targetGyms);
    } else if (hasType) {
      const rv = q(`SELECT type, COUNT(*) cnt FROM resub_intelligence_cache WHERE gym_id IN (${gymIn}) GROUP BY type`, ...targetGyms);
      rv.forEach(r => {
        if (r.type?.includes('RESUB') || r.type?.includes('resub')) resubData.resub_count += r.cnt;
        else resubData.new_count += r.cnt;
      });
    }
  } catch {}

  // ── Door traffic — only gyms WITH sensor installed ────────────────────────
  // casa1 (Casa Anfa) and casa2 (Lady Anfa) have no door sensor yet — excluded
  const trafficToday  = trafficGyms.length > 0 ? q1(`SELECT COALESCE(SUM(count),0) v FROM daily_stats WHERE date=? AND gym_id IN (${trafficGymIn})`, today, ...trafficGyms) : { v: 0 };
  const trafficMonth  = trafficGyms.length > 0 ? q1(`SELECT COALESCE(SUM(count),0) v FROM daily_stats WHERE strftime('%Y-%m',date)=? AND gym_id IN (${trafficGymIn})`, ym, ...trafficGyms) : { v: 0 };
  const trafficAvg30  = trafficGyms.length > 0 ? q1(`SELECT AVG(daily) avg FROM (SELECT date, SUM(count) daily FROM daily_stats WHERE date >= date(?,' -30 days') AND gym_id IN (${trafficGymIn}) GROUP BY date)`, today, ...trafficGyms) : { avg: 0 };

  // ── Birthdays this month (engagement opportunity) ─────────────────────────
  const birthdayCount = q1(`SELECT COUNT(*) cnt FROM relance_birthdays WHERE birth_month=? AND gym_id IN (${gymIn})`, curMonth, ...targetGyms);
  const birthdaySample = q(`SELECT full_name, gym_id, birth_day FROM relance_birthdays WHERE birth_month=? AND gym_id IN (${gymIn}) AND birth_day >= ? ORDER BY birth_day ASC LIMIT 10`, curMonth, String(dayOfMonth).padStart(2,'0'), ...targetGyms);

  // ── Historical monthly CA (last 18 months) ────────────────────────────────
  const historical = q(`SELECT strftime('%Y-%m', date) ym, ROUND(SUM(CAST(tpe AS REAL)+CAST(espece AS REAL)+CAST(virement AS REAL)+CAST(cheque AS REAL)),0) revenue, COUNT(*) inscriptions FROM register_cache WHERE date >= date('now','-18 months') AND gym_id IN (${gymIn}) GROUP BY ym ORDER BY ym ASC`, ...targetGyms);

  // ── Saved memory / owner context ──────────────────────────────────────────
  const memory = q(`SELECT type, scope, gym, note, importance FROM ai_memory WHERE (expires_at IS NULL OR expires_at > datetime('now')) ORDER BY importance DESC LIMIT 15`);

  // ── Open action cards ──────────────────────────────────────────────────────
  const openActions = q(`SELECT title, gym, assigned_to, priority, deadline FROM ai_actions WHERE status='OPEN' ORDER BY created_at DESC LIMIT 10`);

  // ── Today's sales count ───────────────────────────────────────────────────
  const todaySales = q1(`SELECT COUNT(*) cnt FROM register_cache WHERE date=? AND gym_id IN (${gymIn})`, today, ...targetGyms);

  return {
    meta: { generated_at: new Date().toISOString(), period: ym, today, gym_scope: gymScope === 'all' ? 'ALL EMPIRE' : GYM_NAMES[gymScope] || gymScope, day_of_month: dayOfMonth, days_in_month: daysInMonth },
    revenue: {
      today: todayRev.total, week: weekRev.total, month: monthRev.total, year: yearRev.total,
      prev_month: prevRev.total, vs_prev_month_pct: vsPrev,
      monthly_goal: monthlyGoal,
      new_members_month: monthRev.count,
      payments,
      packages: pkgs.map(p => ({ name: p.name, count: p.cnt, revenue: Math.round(p.rev||0) })),
      best_package: bestPackage,
    },
    members: {
      active_total: activeMem?.cnt || 0,
      expiring_30d: expiringMem.length,
      expiring_list: expiringMem.slice(0, 10),
      expired_not_renewed: expiredMem?.cnt || 0,
      resub: resubData,
      birthdays_this_month: birthdayCount?.cnt || 0,
      birthday_upcoming: birthdaySample,
      pending_inscriptions: pendingRows.length,
      pending_list: pendingRows,
    },
    door_traffic: {
      today: Math.round(trafficToday?.v || 0),
      month_total: Math.round(trafficMonth?.v || 0),
      avg_daily_30d: Math.round(trafficAvg30?.avg || 0),
      today_sales: todaySales?.cnt || 0,
      // Conversion only calculated for gyms with sensors (Fès Doukkarate + Fès Saiss)
      conversion_rate_today: trafficToday?.v > 0 ? parseFloat(((todaySales?.cnt||0) / trafficToday.v * 100).toFixed(1)) : 0,
      sensor_coverage: `${trafficGyms.length}/${targetGyms.length} clubs équipés`,
      gyms_without_sensor: GYMS_NO_DOOR_SENSOR.filter(g => targetGyms.includes(g)).map(g => GYM_NAMES[g]),
    },
    debts: {
      total_open: Math.round(debtRow?.total || 0),
      members_count: debtRow?.cnt || 0,
      top_debtors: topDebtors.map(d => ({ name: d.nom, gym: d.gym_id, amount: d.reste, note: d.note_reste, date: d.date })),
    },
    decaissements: {
      month_total: Math.round(decaisMonth?.total || 0),
      month_count: decaisMonth?.cnt || 0,
      by_gym: decaisByGym.map(r => ({ gym: r.gym_id, name: GYM_NAMES[r.gym_id], total: Math.round(r.total||0) })),
      top_items: decaisTop.map(d => ({ gym: d.gym_id, date: d.date, amount: Math.round(d.montant||0), reason: d.raison, status: d.status })),
    },
    incidents: incSummary,
    courses: courseStats,
    commercials,
    gyms,
    historical_revenue: historical,
    memory: memory.map(m => `[${m.importance}][${m.type}] ${m.gym !== 'all' ? `(${GYM_NAMES[m.gym]||m.gym}) ` : ''}${m.note}`),
    open_actions: openActions,
  };
}

// ─── RULES ENGINE ─────────────────────────────────────────────────────────────
function runRules(snap) {
  const alerts = [];
  const sig    = {};

  const { meta, revenue, members, door_traffic, debts, decaissements, incidents, commercials } = snap;
  const dayPct = meta.day_of_month / meta.days_in_month;
  sig.month_progress_pct = parseFloat((dayPct * 100).toFixed(1));
  sig.days_left = meta.days_in_month - meta.day_of_month;

  // 1. Revenue Velocity
  if (revenue.month > 0 && revenue.monthly_goal > 0) {
    const goalPct = revenue.month / revenue.monthly_goal;
    sig.goal_progress_pct    = parseFloat((goalPct * 100).toFixed(1));
    sig.velocity_gap         = parseFloat((goalPct - dayPct).toFixed(3));
    sig.projected_month_end  = Math.round(revenue.month / meta.day_of_month * meta.days_in_month);
    sig.gap_to_goal          = revenue.monthly_goal - sig.projected_month_end;
    sig.required_daily       = sig.days_left > 0 ? Math.round(Math.max(0, sig.gap_to_goal) / sig.days_left) : 0;

    if      (sig.velocity_gap < -0.20) { sig.revenue_status = 'CRITICAL'; alerts.push({ priority:'CRITICAL', type:'REVENUE_VELOCITY', gym:'all', title:'Retard critique sur objectif', message:`Empire à ${sig.goal_progress_pct}% de l'objectif, mois avancé à ${sig.month_progress_pct}%. Prévision fin mois: ${sig.projected_month_end.toLocaleString()} DH (écart: ${sig.gap_to_goal.toLocaleString()} DH).` }); }
    else if (sig.velocity_gap < -0.10) { sig.revenue_status = 'WARNING'; alerts.push({ priority:'WARNING', type:'REVENUE_VELOCITY', gym:'all', title:'Retard sur objectif mensuel', message:`Vitesse CA insuffisante. Besoin de ${sig.required_daily.toLocaleString()} DH/jour pour récupérer.` }); }
    else if (sig.velocity_gap < 0)     sig.revenue_status = 'WATCH';
    else sig.revenue_status = 'HEALTHY';
  } else {
    sig.revenue_status = revenue.month > 0 ? 'WATCH' : 'UNKNOWN';
  }

  // 2. Month vs previous
  if (revenue.vs_prev_month_pct < -15) alerts.push({ priority:'WARNING', type:'REVENUE_DROP', gym:'all', title:`CA en baisse de ${Math.abs(revenue.vs_prev_month_pct)}% vs mois précédent`, message:`${revenue.month.toLocaleString()} DH ce mois vs ${revenue.prev_month.toLocaleString()} DH le mois dernier.` });

  // 3. Debt risk
  if (debts.total_open > 0 && revenue.month > 0) {
    const dr = debts.total_open / revenue.month;
    sig.debt_ratio = parseFloat((dr * 100).toFixed(1));
    if      (dr > 0.15) { sig.debt_status = 'CRITICAL'; alerts.push({ priority:'CRITICAL', type:'DEBT_RISK', gym:'all', title:`Créances critiques: ${debts.total_open.toLocaleString()} DH`, message:`${sig.debt_ratio}% du CA mensuel en impayés (${debts.members_count} membres). Risque liquidité.` }); }
    else if (dr > 0.08) { sig.debt_status = 'HIGH'; alerts.push({ priority:'WARNING', type:'DEBT_RISK', gym:'all', title:`Niveau créances élevé: ${debts.total_open.toLocaleString()} DH`, message:`${debts.members_count} membres avec solde impayé. Campagne recouvrement recommandée.` }); }
    else sig.debt_status = 'NORMAL';
  }

  // 4. Cash outflows vs revenue (décaissements)
  if (decaissements.month_total > 0 && revenue.month > 0) {
    const decRatio = decaissements.month_total / revenue.month;
    sig.decais_ratio_pct = parseFloat((decRatio * 100).toFixed(1));
    if (decRatio > 0.25) alerts.push({ priority:'WARNING', type:'HIGH_OUTFLOW', gym:'all', title:`Sorties espèces élevées: ${decaissements.month_total.toLocaleString()} DH`, message:`${sig.decais_ratio_pct}% du CA en sorties ce mois. Vérifier dépenses opérationnelles.` });
  }

  // 5. Members expiring
  if (members.expiring_30d > 10) alerts.push({ priority:'WATCH', type:'MEMBER_EXPIRY', gym:'all', title:`${members.expiring_30d} abonnements expirent dans 30j`, message:'Lancer campagne renouvellement proactive pour limiter la perte membres.' });
  if (members.expired_not_renewed > 5) alerts.push({ priority:'WARNING', type:'MEMBER_CHURN', gym:'all', title:`${members.expired_not_renewed} membres expirés non renouvelés`, message:'Ces membres sont partis. Campagne réactivation urgente.' });

  // 6. Incidents
  if (incidents.critical > 0) alerts.push({ priority:'CRITICAL', type:'INCIDENT', gym:'all', title:`${incidents.critical} incident(s) critique(s) non résolus`, message: incidents.list.filter(i=>i.emergency==='Critique').map(i=>`${i.gym_id}: ${i.title}`).join(' | ') });
  if (incidents.high > 2) alerts.push({ priority:'WARNING', type:'INCIDENT', gym:'all', title:`${incidents.high} incidents élevés ouverts`, message:'Accumulation incidents peut affecter satisfaction membres et renouvellements.' });

  // 7. Commercial underperformance (mid-month check)
  if (dayPct > 0.45) {
    commercials.forEach(c => {
      if (c.goal > 0 && (c.revenue / c.goal) < 0.50) {
        alerts.push({ priority:'WARNING', type:'COMMERCIAL_UNDERPERFORM', gym: c.gym, title:`${c.name} sous-performe: ${c.goal_pct}% objectif`, message:`${c.name} (${c.gym_name}) à ${c.revenue.toLocaleString()} DH / objectif ${c.goal.toLocaleString()} DH. Coaching immédiat nécessaire.` });
      }
    });
  }

  // 8. Door-to-sales conversion (only when sensor-equipped gyms have data)
  const tr = door_traffic;
  const hasSensorData = tr.today > 0; // 0 means no data from equipped gyms either
  if (hasSensorData && tr.today > 60 && tr.conversion_rate_today < 3) {
    sig.conversion_alert = true;
    alerts.push({ priority:'WATCH', type:'LOW_CONVERSION', gym:'all', title:`Trafic ${tr.today} entrées mais conversion ${tr.conversion_rate_today}%`, message:`Fort trafic présent (${tr.sensor_coverage || 'capteurs Fès'}) mais conversion vente faible. Activer protocole upsell en réception.` });
  }


  // 9. Renewal opportunity
  if ((members.resub?.possible_count || 0) > 15) sig.renewal_opportunity = true;

  // 10. Birthday engagement opportunity
  if (members.birthdays_this_month > 50) sig.birthday_opportunity = members.birthdays_this_month;

  // Overall status
  const critCount = alerts.filter(a=>a.priority==='CRITICAL').length;
  const warnCount = alerts.filter(a=>a.priority==='WARNING').length;
  sig.empire_status = critCount >= 2 ? 'CRITICAL' : critCount >= 1 ? 'WARNING' : warnCount >= 2 ? 'WARNING' : warnCount >= 1 ? 'WATCH' : 'HEALTHY';

  return { alerts, signals: sig };
}

// ─── SYSTEM PROMPT ────────────────────────────────────────────────────────────
function buildSysPrompt(snap, sig) {
  const mem = snap.memory?.length ? `\n\n=== CONTEXTE STRATÉGIQUE (MÉMOIRE) ===\n${snap.memory.join('\n')}` : '';
  const rev = snap.revenue;
  const dec = snap.decaissements;

  const sensorNote = snap.door_traffic?.gyms_without_sensor?.length > 0
    ? `\n\n⚠️ CAPTEURS PORTES NON INSTALLÉS: ${snap.door_traffic.gyms_without_sensor.join(', ')} — leurs données de trafic valent NULL (matériel absent, pas un problème business). NE JAMAIS commenter ni alerter sur zéro entrées pour ces clubs. Couverture capteurs: ${snap.door_traffic.sensor_coverage}.`
    : '';

  return `Tu es AURALIX, directeur opérationnel IA 24/7 de l'empire MegaFit — 4 clubs Maroc (Fès Doukkarate, Fès Saiss, Casa Anfa, Lady Anfa).
Tu analyses des données RÉELLES et tu penses comme un senior operator: 20+ ans vente, finance, multi-sites.

ÉTAT EMPIRE: ${sig.empire_status || 'INCONNU'}
CA MOIS: ${rev.month.toLocaleString()} DH | OBJECTIF: ${rev.monthly_goal.toLocaleString()} DH | AVANCEMENT: ${sig.goal_progress_pct||0}%
PRÉVISION FIN MOIS: ${(sig.projected_month_end||0).toLocaleString()} DH | ÉCART: ${(sig.gap_to_goal||0).toLocaleString()} DH | REQUIS/JOUR: ${(sig.required_daily||0).toLocaleString()} DH
CA VS MOIS PRÉCÉDENT: ${rev.vs_prev_month_pct > 0 ? '+' : ''}${rev.vs_prev_month_pct}%
SORTIES ESPÈCES MOIS: ${dec.month_total.toLocaleString()} DH (${sig.decais_ratio_pct||0}% du CA)
DETTE TOTALE: ${snap.debts.total_open.toLocaleString()} DH | ${snap.debts.members_count} membres | Ratio: ${sig.debt_ratio||0}%
INCIDENTS OUVERTS: ${snap.incidents.open_total} (${snap.incidents.critical} critiques)
MEMBRES ACTIFS: ${snap.members.active_total} | Expirent 30j: ${snap.members.expiring_30d} | Expirés non renouvelés: ${snap.members.expired_not_renewed}
RÉABONNEMENTS POSSIBLES: ${snap.members.resub?.possible_count || 0}
ANNIVERSAIRES CE MOIS: ${snap.members.birthdays_this_month} (opportunité engagement)

CALENDRIER MAROCAIN — avant de qualifier une baisse, vérifier:
- Ramadan 2026: 18 fév–18 mars | Eid Fitr 2026: 20 mars | Eid Kbir 2026: 27 mai
- Janv = pic résolutions ★★★★★ | Sept = pic rentrée ★★★★★ | Juil-Août = creux ★★ | Juin = Eid+BAC ★★

RÈGLES ABSOLUES:
1. Français professionnel, direct, tactique — zéro bavardage.
2. Jamais de chiffres inventés — données réelles uniquement.
3. Expliquer la signification business derrière chaque chiffre.
4. Terminer par des ACTIONS CONCRÈTES (qui, quoi, quand).
5. Classifier: HEALTHY / WATCH / WARNING / CRITICAL.${sensorNote}${mem}`;
}

// ─── ROUTER ───────────────────────────────────────────────────────────────────
module.exports = function aiAgentRouter({ lc }) {
  const router = Router();
  const db = lc?.db;

  try { initAiTables(db); console.log('[AURALIX-AGENT] Tables initialized'); } catch(e) { console.error('[AURALIX-AGENT] Table init error:', e.message); }

  const getMeta = (key) => { try { return lc.getMeta?.(key); } catch { return null; } };
  const snap = (gym) => buildSnapshot(db, getMeta, gym);

  // ── Save alert to DB ───────────────────────────────────────────────────────
  function saveAlerts(alerts, gym = 'all') {
    if (!db || !alerts?.length) return;
    const ins = db.prepare(`INSERT OR IGNORE INTO ai_alerts (id, alert_type, priority, title, message, gym, status) VALUES (?,?,?,?,?,?,'OPEN')`);
    const ym = new Date().toISOString().slice(0, 7);
    alerts.forEach(a => {
      try { ins.run(`alert_${a.type}_${gym}_${ym}`, a.type, a.priority, a.title, a.message || '', a.gym || gym); } catch {}
    });
  }

  // ── GET /api/ai/snapshot ───────────────────────────────────────────────────
  router.get('/api/ai/snapshot', verifyAzureToken, (req, res) => {
    try {
      const s = snap(req.query.gym || 'all');
      const { signals, alerts } = runRules(s);
      saveAlerts(alerts, req.query.gym || 'all');
      res.json({ snapshot: s, signals, alerts });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  // ── POST /api/ai/ask ───────────────────────────────────────────────────────
  router.post('/api/ai/ask', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { question, gym = 'all' } = req.body;
      if (!question?.trim()) return res.status(400).json({ error: 'Question required' });
      const s = snap(gym);
      const { signals, alerts } = runRules(s);
      saveAlerts(alerts, gym);

      // Compact snapshot for prompt (avoid token overflow)
      const ctxJson = JSON.stringify({
        revenue: s.revenue, members: { active_total: s.members.active_total, expiring_30d: s.members.expiring_30d, expired_not_renewed: s.members.expired_not_renewed, resub: s.members.resub, birthdays_this_month: s.members.birthdays_this_month },
        door_traffic: s.door_traffic, debts: s.debts, decaissements: { month_total: s.decaissements.month_total, by_gym: s.decaissements.by_gym },
        incidents: { open_total: s.incidents.open_total, critical: s.incidents.critical, list: s.incidents.list?.slice(0,4) },
        courses: s.courses, gyms: s.gyms, commercials: s.commercials.slice(0, 6),
        historical_revenue: s.historical_revenue.slice(-6),
      });

      const messages = [
        { role: 'system', content: buildSysPrompt(s, signals) + `\n\n=== DONNÉES COMPLÈTES ===\n${ctxJson.slice(0, 4500)}` },
        { role: 'user', content: question }
      ];
      const reply = await groq(messages, true);
      res.json({ reply, signals, alerts, empire_status: signals.empire_status });
    } catch(e) { console.error('[AI/ask]', e.message); res.status(500).json({ error: e.message }); }
  });

  // ── POST /api/ai/scan ──────────────────────────────────────────────────────
  router.post('/api/ai/scan', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { gym = 'all' } = req.body;
      const s = snap(gym);
      const { signals, alerts } = runRules(s);
      saveAlerts(alerts, gym);

      const ctxJson = JSON.stringify({
        revenue: s.revenue, members: { active_total: s.members.active_total, expiring_30d: s.members.expiring_30d, expired_not_renewed: s.members.expired_not_renewed, resub: s.members.resub },
        door_traffic: s.door_traffic, debts: s.debts, decaissements: s.decaissements,
        incidents: s.incidents, commercials: s.commercials.slice(0,6), gyms: s.gyms, courses: s.courses,
      });

      const messages = [
        { role: 'system', content: buildSysPrompt(s, signals) + `\n\n=== SNAPSHOT COMPLET ===\n${ctxJson.slice(0, 4000)}\n\nRéponds UNIQUEMENT en JSON valide (aucun texte avant ou après):\n{"empire_status":"HEALTHY|WATCH|WARNING|CRITICAL","mood":"healthy|watch|warning|critical","executive_summary":"string","critical_alerts":[{"level":"critical","title":"string","detail":"string","gym":"string"}],"watch_points":[{"title":"string","detail":"string"}],"growth_opportunities":[{"title":"string","detail":"string","impact":"string"}],"priority_actions":[{"title":"string","owner":"string","deadline":"string","impact":"HIGH|MEDIUM","gym":"string","description":"string"}]}` },
        { role: 'user', content: `Scanne l'empire ${s.meta.gym_scope} et génère le JSON d'analyse tactique.` }
      ];

      const raw = await groq(messages, true);
      let parsed;
      try {
        const m = raw.match(/\{[\s\S]*\}/);
        parsed = m ? JSON.parse(m[0]) : null;
      } catch { parsed = null; }

      if (!parsed) {
        parsed = { empire_status: signals.empire_status, mood: signals.empire_status.toLowerCase(), executive_summary: raw.slice(0, 400), critical_alerts: alerts.filter(a=>a.priority==='CRITICAL').map(a=>({level:'critical',title:a.title,detail:a.message,gym:a.gym})), watch_points: [], growth_opportunities: [], priority_actions: [] };
      }

      // Auto-create action cards
      if (db && parsed.priority_actions?.length) {
        const ins = db.prepare(`INSERT OR IGNORE INTO ai_actions (id,title,description,gym,assigned_to,priority,status,deadline,source) VALUES (?,?,?,?,?,?,'OPEN',?,'scan')`);
        parsed.priority_actions.forEach(a => {
          const id = `scan_action_${Date.now()}_${Math.random().toString(36).slice(2,5)}`;
          try { ins.run(id, a.title, a.description||'', a.gym||gym, a.owner||'Manager', a.impact||'MEDIUM', a.deadline||''); } catch {}
        });
      }

      res.json({ ...parsed, signals, rules_alerts: alerts });
    } catch(e) { console.error('[AI/scan]', e.message); res.status(500).json({ error: e.message }); }
  });

  // ── POST /api/ai/startup-brief ─────────────────────────────────────────────
  router.post('/api/ai/startup-brief', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const s = snap(req.body?.gym || 'all');
      const { signals, alerts } = runRules(s);
      const critCount = alerts.filter(a=>a.priority==='CRITICAL').length;
      const messages = [
        { role: 'system', content: buildSysPrompt(s, signals) },
        { role: 'user', content: `Génère le brief CEO matinal en 5 sections numérotées:\n1. STATUT EMPIRE (${signals.empire_status})\n2. CHIFFRES CLÉS (CA, objectif, prévision)\n3. ALERTES CRITIQUES (${critCount} détectée(s))\n4. OPPORTUNITÉ DU JOUR\n5. DIRECTIVE PRIORITAIRE\n\nSois direct et actionnable. Termine par une seule instruction pour l'équipe aujourd'hui.` }
      ];
      const brief = await groq(messages, false);
      saveAlerts(alerts, 'all');
      res.json({ brief, signals, alerts, empire_status: signals.empire_status });
    } catch(e) { console.error('[AI/startup-brief]', e.message); res.status(500).json({ error: e.message }); }
  });

  // ── POST /api/ai/quick/:mode ───────────────────────────────────────────────
  const QUICK_PROMPTS = {
    'find-money':       'Analyse toutes les sources d\'argent non collecté: dettes impayées, réabonnements possibles, formules sous-vendues, membres expirés non relancés. Donne un plan chiffré pour les 7 prochains jours avec responsable.',
    'recover-debt':     'Analyse les créances ouvertes. Classe les débiteurs par priorité (montant + probabilité paiement). Génère un script d\'appel et propose une stratégie de recouvrement avec délais.',
    'coach-commercial': 'Analyse chaque commercial ce mois: inscriptions, CA, ticket moyen, trend. Identifie les points faibles. Donne des directives de coaching précises et personnalisées pour chacun.',
    'renewals':         'Génère une campagne renouvellement pour les membres qui expirent dans 30 jours et les possibles RESUB. Script d\'appel, formule à pousser, timing optimal, offre de relance.',
    'forecast':         'Analyse la vitesse CA actuelle. Projette la fin du mois. Si objectif en danger, calcule ce qu\'il faut faire PAR JOUR et PAR COMMERCIAL pour récupérer.',
    'incidents':        'Analyse tous les incidents ouverts. Priorise par impact business. Suggère des actions correctives immédiates et préventives.',
    'courses':          'Analyse les cours: taux de remplissage, cours populaires vs sous-fréquentés. Suggère des optimisations planning et marketing.',
    'birthdays':        'Stratégie d\'engagement anniversaires: script WhatsApp, offre spéciale, timing optimal pour convertir ces contacts en renouvellements.',
  };

  router.post('/api/ai/quick/:mode', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { mode } = req.params;
      const prompt = QUICK_PROMPTS[mode];
      if (!prompt) return res.status(400).json({ error: `Unknown mode: ${mode}` });
      const s = snap(req.body?.gym || 'all');
      const { signals } = runRules(s);
      const ctxJson = JSON.stringify({ revenue: s.revenue, debts: s.debts, members: s.members, commercials: s.commercials, gyms: s.gyms, courses: s.courses, decaissements: s.decaissements, incidents: s.incidents }, null, 0).slice(0, 3500);
      const messages = [
        { role: 'system', content: buildSysPrompt(s, signals) + `\n\n=== DONNÉES ===\n${ctxJson}` },
        { role: 'user', content: prompt }
      ];
      const reply = await groq(messages, true);
      res.json({ reply, mode, signals, empire_status: signals.empire_status });
    } catch(e) { console.error('[AI/quick]', e.message); res.status(500).json({ error: e.message }); }
  });

  // ── Health check (rules only, no LLM) ─────────────────────────────────────
  router.get('/api/ai/health-check', verifyAzureToken, (req, res) => {
    try {
      const s = snap(req.query.gym || 'all');
      const { signals, alerts } = runRules(s);
      saveAlerts(alerts, req.query.gym || 'all');
      const openActCount = db ? db.prepare(`SELECT COUNT(*) cnt FROM ai_actions WHERE status='OPEN'`).get()?.cnt || 0 : 0;
      const openAlertCount = db ? db.prepare(`SELECT COUNT(*) cnt FROM ai_alerts WHERE status='OPEN'`).get()?.cnt || 0 : 0;
      res.json({ empire_status: signals.empire_status, signals, alerts, open_actions: openActCount, open_alerts: openAlertCount });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  // ── Actions CRUD ───────────────────────────────────────────────────────────
  router.get('/api/ai/actions', verifyAzureToken, (req, res) => {
    try {
      if (!db) return res.json([]);
      const status = req.query.status;
      const rows = status ? db.prepare(`SELECT * FROM ai_actions WHERE status=? ORDER BY created_at DESC LIMIT 50`).all(status) : db.prepare(`SELECT * FROM ai_actions ORDER BY created_at DESC LIMIT 50`).all();
      res.json(rows);
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  router.post('/api/ai/action', verifyAzureToken, requireAdmin, (req, res) => {
    try {
      if (!db) return res.status(503).json({ error: 'DB unavailable' });
      const { title, description, gym='all', assigned_to='Manager', priority='MEDIUM', expected_impact, deadline } = req.body;
      if (!title) return res.status(400).json({ error: 'title required' });
      const id = `action_${Date.now()}_${Math.random().toString(36).slice(2,5)}`;
      db.prepare(`INSERT INTO ai_actions (id,title,description,gym,assigned_to,priority,expected_impact,deadline,source) VALUES (?,?,?,?,?,?,?,?,'manual')`).run(id, title, description||'', gym, assigned_to, priority, expected_impact||'', deadline||'');
      res.json({ id, title, status:'OPEN' });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  router.patch('/api/ai/actions/:id', verifyAzureToken, requireAdmin, (req, res) => {
    try {
      if (!db) return res.status(503).json({ error: 'DB unavailable' });
      const { status } = req.body;
      if (!['OPEN','IN_PROGRESS','DONE','IGNORED','ESCALATED'].includes(status)) return res.status(400).json({ error: 'Invalid status' });
      const done = status === 'DONE' ? new Date().toISOString() : null;
      db.prepare(`UPDATE ai_actions SET status=?, completed_at=? WHERE id=?`).run(status, done, req.params.id);
      res.json({ id: req.params.id, status });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  // ── Memory CRUD ────────────────────────────────────────────────────────────
  router.get('/api/ai/memory', verifyAzureToken, (req, res) => {
    try {
      if (!db) return res.json([]);
      res.json(db.prepare(`SELECT * FROM ai_memory WHERE (expires_at IS NULL OR expires_at > datetime('now')) ORDER BY importance DESC, created_at DESC LIMIT 30`).all());
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  router.post('/api/ai/memory', verifyAzureToken, requireAdmin, (req, res) => {
    try {
      if (!db) return res.status(503).json({ error: 'DB unavailable' });
      const { note, type='STRATEGY', scope='ALL_EMPIRE', gym='all', importance='HIGH', expires_days } = req.body;
      if (!note?.trim()) return res.status(400).json({ error: 'note required' });
      const id = `mem_${Date.now()}_${Math.random().toString(36).slice(2,5)}`;
      const expires = expires_days ? new Date(Date.now() + expires_days * 86400000).toISOString() : null;
      db.prepare(`INSERT INTO ai_memory (id,type,scope,gym,note,importance,expires_at) VALUES (?,?,?,?,?,?,?)`).run(id, type, scope, gym, note.trim(), importance, expires);
      res.json({ id, note, type, importance });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  router.delete('/api/ai/memory/:id', verifyAzureToken, requireAdmin, (req, res) => {
    try {
      if (!db) return res.status(503).json({ error: 'DB unavailable' });
      db.prepare(`DELETE FROM ai_memory WHERE id=?`).run(req.params.id);
      res.json({ deleted: req.params.id });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  // ── Alerts ─────────────────────────────────────────────────────────────────
  router.get('/api/ai/alerts', verifyAzureToken, (req, res) => {
    try {
      if (!db) return res.json([]);
      res.json(db.prepare(`SELECT * FROM ai_alerts WHERE status='OPEN' ORDER BY created_at DESC LIMIT 30`).all());
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  router.patch('/api/ai/alerts/:id/resolve', verifyAzureToken, requireAdmin, (req, res) => {
    try {
      if (!db) return res.status(503).json({ error: 'DB unavailable' });
      db.prepare(`UPDATE ai_alerts SET status='RESOLVED', resolved_at=datetime('now') WHERE id=?`).run(req.params.id);
      res.json({ id: req.params.id, status: 'RESOLVED' });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  return router;
};
