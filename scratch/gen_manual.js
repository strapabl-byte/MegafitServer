const fs = require('fs');
const out = 'C:/Users/Thatsme/.gemini/antigravity/brain/a34e79db-7aaa-496f-a731-1c0637e57e53/MegaFit_Manuel_2026.html';

const css = `*{margin:0;padding:0;box-sizing:border-box}body{font-family:Arial,sans-serif;color:#111;background:#fff}
@media print{.pb{page-break-after:always}}
.cover{background:#0A0F1C;color:#fff;height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:40px}
.logo{font-size:80px}.brand{font-size:52px;font-weight:900;color:#a3ff12;letter-spacing:4px}
.sub{font-size:20px;color:#94a3b8;margin:10px 0}.ver{margin-top:30px;font-size:12px;color:#334155;border:1px solid #1e293b;padding:8px 24px;border-radius:20px}
.toc{padding:60px 80px}.toc h2{font-size:26px;color:#0A0F1C;border-bottom:3px solid #a3ff12;padding-bottom:10px;margin-bottom:24px}
.ti{display:flex;justify-content:space-between;padding:11px 0;border-bottom:1px solid #f1f5f9;font-size:14px}
.tn{background:#0A0F1C;color:#a3ff12;padding:2px 10px;border-radius:4px;font-weight:700;font-size:11px;margin-right:10px}
.ch{padding:50px 80px}.hd{background:#0A0F1C;color:#a3ff12;padding:18px 28px;border-radius:10px;margin-bottom:28px;display:flex;align-items:center;gap:18px}
.hn{font-size:38px;font-weight:900;opacity:.25}.ht{font-size:22px;font-weight:700}
h3{color:#0A0F1C;margin:22px 0 10px;font-size:15px;border-left:4px solid #a3ff12;padding-left:12px}
p,li{font-size:13px;line-height:1.8;color:#374151;margin-bottom:6px}ul{padding-left:20px;margin-bottom:12px}
table{width:100%;border-collapse:collapse;margin:16px 0;font-size:12px}th{background:#0A0F1C;color:#a3ff12;padding:9px 13px;text-align:left}
td{padding:9px 13px;border-bottom:1px solid #f1f5f9}tr:nth-child(even) td{background:#f8fafc}
.tip{background:#f0fdf4;border-left:4px solid #22c55e;padding:12px 16px;border-radius:6px;margin:14px 0;font-size:12px}
.warn{background:#fff7ed;border-left:4px solid #f97316;padding:12px 16px;border-radius:6px;margin:14px 0;font-size:12px}
.ft{background:#0A0F1C;color:#64748b;text-align:center;padding:28px;font-size:11px;margin-top:40px}`;

const toc = [
  ['01','Introduction au Système'],['02','Connexion et Authentification'],
  ['03','Navigation Générale'],['04','Tableau de Bord AURALIX'],
  ['05','Entrées en Direct (Live Door Feed)'],['06','Registre Journalier'],
  ['07','Gestion des Membres'],['08','Planning des Cours'],
  ['09','Décaissements'],['10','Rapports Commerciaux'],
  ['11','Archive des Entrées'],['12','Formulaire d\'Inscription en Ligne'],
  ['13','Questions Fréquentes']
];

function ch(num,title,body){
  return `<div class="ch pb"><div class="hd"><div class="hn">${num}</div><div class="ht">${title}</div></div>${body}</div>`;
}
function t(heads,rows){
  return `<table><tr>${heads.map(h=>`<th>${h}</th>`).join('')}</tr>${rows.map(r=>`<tr>${r.map(c=>`<td>${c}</td>`).join('')}</tr>`).join('')}</table>`;
}

const chapters = [
  ch('01','Introduction au Système',`
    <h3>Qu'est-ce que MegaFit ?</h3>
    <p>MegaFit est un système de gestion de salles de sport avec intelligence artificielle (AURALIX) capable d'identifier les membres depuis le scanner biométrique en temps réel.</p>
    ${t(['Composant','Description'],[['Tableau de bord','Interface web pour responsables et commerciaux'],['Formulaire inscription','Page web pour nouveaux membres'],['API SQLite-first','Serveur haute performance, coût Firebase zéro']])}
    <h3>Rôles Utilisateurs</h3>
    ${t(['Rôle','Accès'],[['Super Admin','Accès total — suppression, rapports, configuration'],['Manager','Membres, registre, cours, décaissements'],['Commercial','Saisie du registre journalier uniquement']])}
  `),
  ch('02','Connexion et Authentification',`
    <h3>URL d'accès</h3><p><strong>https://megafitauth.web.app</strong></p>
    <p>Authentification via <strong>Microsoft Azure</strong> — utilisez votre compte Microsoft professionnel MegaFit.</p>
    <h3>Étapes</h3>
    <ul><li>Ouvrez Chrome → accédez à l'URL</li><li>Cliquez <strong>« Se connecter »</strong></li><li>Email pro MegaFit + mot de passe Microsoft</li><li>Redirection automatique vers votre tableau de bord</li></ul>
    <div class="warn">⚠️ Message « Accès refusé » → contactez votre administrateur pour activer votre compte.</div>
    <div class="tip">💡 Sur ordinateur partagé : déconnectez-vous toujours après utilisation.</div>
  `),
  ch('03','Navigation Générale',`
    <h3>Barre Latérale</h3>
    ${t(['Icône','Section','Description'],[['👁️','AURALIX','Tableau de bord principal'],['👥','Membres','Base de données adhérents'],['📋','Registre','Paiements journaliers'],['📅','Cours','Planning hebdomadaire'],['📊','Rapports','Statistiques commerciales']])}
    <h3>Sélecteur de Salle</h3>
    <ul><li>🏟️ Fès Doukkarate</li><li>🏢 Fès Saïss (Marjane)</li><li>🌆 Casa 1 — Anfa</li><li>👑 Casa 2 — Lady Anfa</li></ul>
    <h3>Indicateur LIVE SYNC</h3><p>🟢 Vert pulsant = données à jour &nbsp;|&nbsp; 🔴 Rouge = hors ligne (données locales affichées)</p>
  `),
  ch('04','Tableau de Bord AURALIX',`
    <h3>KPIs (Chiffres Clés)</h3>
    ${t(['Indicateur','Signification'],[['CA du Jour','Chiffre d\'affaires encaissé aujourd\'hui (DH)'],['CA Semaine','Revenu de la semaine en cours'],['CA Mois','Revenu du mois en cours'],['Membres Actifs','Abonnements valides en cours']])}
    <h3>Compteur d'Entrées</h3><p>Grand chiffre central — entrées du jour depuis le scanner biométrique. Actualisé toutes les 30 secondes.</p>
    <h3>Bouton AURALIX BRAIN</h3><p>Voyant bleu lumineux pulsant = IA active et analyse les entrées en temps réel.</p>
    <h3>Graphique 30 Jours</h3><p>Évolution des entrées et du CA sur 30 jours. Passez la souris sur une barre pour le détail journalier.</p>
  `),
  ch('05','Entrées en Direct (Live Door Feed)',`
    <h3>Codes Couleurs</h3>
    ${t(['Couleur','Statut','Signification'],[['🟢 Vert','Confirmé','Membre actif, abonnement valide'],['🟡 Jaune','Probable','Correspondance probable, à vérifier'],['🔴 Rouge','Expiré','Abonnement expiré — proposer renouvellement'],['🔵 Bleu','Staff','Employé de la salle'],['⚪ Gris','Inconnu','Non trouvé dans la base'],['🟣 Violet','Autre salle','Inscrit dans une autre salle MegaFit']])}
    <h3>AURALIX SMART-ID</h3><p>L'IA identifie les membres même si le scanner envoie un nom sans espace, avec des caractères spéciaux ou une orthographe approximative.</p>
    <div class="tip">Exemple : <strong>rajaebouzoubaa</strong> → identifié automatiquement comme <strong>RAJAE BOUZOUBAA</strong> ✅</div>
  `),
  ch('06','Registre Journalier',`
    <h3>Champs de Saisie</h3>
    ${t(['Champ','Description','Requis'],[['N° Contrat','Numéro de contrat membre','Non'],['Commercial','Nom du commercial','✅ Oui'],['Nom et Prénom','Nom complet','✅ Oui'],['CIN','Carte d\'Identité Nationale','Recommandé'],['Téléphone','Numéro de contact','Recommandé'],['Prix','Montant total abonnement','✅ Oui'],['TPE','Paiement carte bancaire','Si applicable'],['Espèce','Paiement liquide','Si applicable'],['Virement','Paiement virement','Si applicable'],['Chèque','Paiement chèque','Si applicable'],['Reste','Solde dû (auto-calculé)','Auto'],['Abonnement','Durée (1 An, 2 Ans…)','✅ Oui']])}
    <div class="tip">💡 TPE + Espèce + Virement + Chèque = Prix total. Le Reste est calculé automatiquement.</div>
    <h3>Actions</h3>
    <ul><li><strong>Ajouter :</strong> Ligne du bas → remplir → Entrée</li><li><strong>Modifier :</strong> Cliquer sur la cellule → sauvegarde auto</li><li><strong>Supprimer :</strong> Icône 🗑️ — Super Admin uniquement</li><li><strong>Imprimer :</strong> Bouton 🖨️ → PDF A4 avec récapitulatif commercial</li></ul>
    <div class="warn">⚠️ Ne fermez pas la page pendant la sauvegarde (indicateur visible).</div>
    <h3>Encaissement des Restes</h3><p>Cliquez sur 💳 sur la ligne du membre → historique des paiements → confirmer l'encaissement.</p>
  `),
  ch('07','Gestion des Membres',`
    <h3>Recherche</h3><p>Par : Nom · Prénom · Téléphone · CIN · Numéro de contrat</p>
    <h3>Filtres</h3><ul><li>Statut : Actif / Expiré / En attente / Tous</li><li>Salle · Tri par nom / date / expiration</li></ul>
    <h3>Fiche Membre</h3><ul><li>Informations personnelles, abonnement, photo</li><li>QR Code unique · Lien contrat PDF</li></ul>
    <h3>Ajouter</h3><ul><li>Cliquer <strong>« + Nouveau Membre »</strong></li><li>Remplir le formulaire → photo (optionnel) → <strong>« Créer »</strong></li></ul>
    <h3>Modifier</h3>
    <div class="tip">✅ Modification via ID unique — fonctionne même avec filtres et recherches actifs.</div>
    <ul><li>Trouver le membre → <strong>« Modifier »</strong> → Mettre à jour → <strong>« Sauvegarder »</strong></li></ul>
    <h3>QR Code</h3><p>Bouton <strong>QR</strong> sur la ligne → affichage, photo ou impression.</p>
    <div class="warn">⚠️ Suppression réservée Super Admins — action définitive et irréversible.</div>
  `),
  ch('08','Planning des Cours',`
    <p>Planning hebdomadaire par salle. Pour Doukkarate : interrupteur <strong>Mixte / Lady</strong>.</p>
    <h3>Ajouter un Cours</h3>
    <ul><li>Cliquer <strong>« + Nouveau Cours »</strong></li><li>Renseigner : Nom · Coach · Jour · Heure début/fin · Salle</li><li>Cliquer <strong>« Créer »</strong></li></ul>
    <h3>Modifier / Supprimer</h3><p>Cliquer sur le cours dans le planning → boutons Modifier ou Supprimer.</p>
  `),
  ch('09','Décaissements',`
    <p>Sortie d'argent de la caisse pour dépenses de la salle (matériel, réparations, fournitures…).</p>
    <h3>Créer un Décaissement</h3>
    <ul><li>Registre → section Décaissements → <strong>« + Nouveau »</strong></li><li>Montant · Raison · Responsable · Signature</li></ul>
    <h3>Workflow d'Approbation</h3>
    ${t(['Statut','Couleur','Signification'],[['En attente','🟠 Orange','Créé, en attente validation manager'],['Approuvé','🟢 Vert','Validé par le manager'],['Refusé','🔴 Rouge','Rejeté par le manager']])}
  `),
  ch('10','Rapports Commerciaux',`
    <p>Suivi des performances individuelles de chaque commercial du mois.</p>
    <h3>Statistiques</h3><ul><li>Nombre d'inscriptions · CA généré</li><li>Répartition par mode de paiement</li><li>Objectifs vs Réalisé (barre de progression)</li></ul>
    <h3>Définir un Objectif</h3>
    <ul><li>Rapports Commerciaux → <strong>« Définir Objectif »</strong> → montant cible en DH</li></ul>
  `),
  ch('11','Archive des Entrées (Door History)',`
    <p>Historique complet des passages au scanner biométrique, pour toute période.</p>
    <h3>Sélection de la Salle</h3>
    ${t(['Salle','Disponibilité'],[['🏟️ Fès Doukkarate','✅ Disponible'],['🏢 Fès Saïss','✅ Disponible'],['🌆 Casa Anfa','⏳ Bientôt'],['👑 Casa Lady Anfa','⏳ Bientôt']])}
    <h3>Filtres</h3><ul><li>Date début · Date fin · Recherche par nom → 🔍 SEARCH</li></ul>
    <h3>Export CSV</h3><p>Bouton <strong>EXPORT CSV</strong> actif dès que des résultats sont affichés. Contient : date/heure, salle, nom, méthode, statut.</p>
  `),
  ch('12','Formulaire d\'Inscription en Ligne',`
    <h3>Liens par Salle</h3>
    ${t(['Salle','Lien'],[['Fès Doukkarate','megafitauth.web.app/inscription/?gym=dokarat'],['Fès Saïss','megafitauth.web.app/inscription/?gym=marjane'],['Casa Anfa','megafitauth.web.app/inscription/?gym=casa1'],['Casa Lady Anfa','megafitauth.web.app/inscription/?gym=casa2']])}
    <div class="tip">💡 Créez un QR Code pour chaque lien et affichez-le à l'accueil — inscription directe depuis le téléphone.</div>
    <h3>Informations Demandées</h3>
    <ul><li>Nom complet · Date de naissance · CIN</li><li>Téléphone · Email</li><li>Type d'abonnement · Objectif sportif</li></ul>
    <h3>Processus</h3>
    ${t(['Pour le Membre','Pour le Commercial'],[['Remplit et soumet le formulaire','Reçoit la demande dans « En attente »'],['Reçoit email de confirmation','Contacte le membre pour RDV'],['Vient à la salle finaliser','Confirme l\'inscription → statut Actif']])}
    <h3>Confirmer une Inscription</h3>
    <ul><li>Membres → Filtrer <strong>« En attente »</strong> → ouvrir → <strong>« Confirmer »</strong></li></ul>
  `),
  ch('13','Questions Fréquentes',`
    <h3>FAQ</h3>
    ${t(['Question','Réponse'],[
      ['Je ne vois pas les données de ma salle','Vérifiez le sélecteur de salle en haut. Rechargez si besoin.'],
      ['Un membre valide affiché en rouge','Vérifiez la date d\'expiration dans sa fiche. Si valide → signalez à l\'admin.'],
      ['Erreur de saisie dans le registre','Cliquez sur la cellule et corrigez directement — sauvegarde auto.'],
      ['Nom mal reconnu par le scanner','L\'IA s\'améliore. Signalez le nom incorrect à l\'administrateur.'],
      ['Dashboard affiche « Quota dépassé »','Données locales disponibles. Reconnexion automatique sous peu.'],
      ['Ajouter un nouveau commercial','Réservé Super Admin. Contactez l\'équipe technique MegaFit.']
    ])}
    <h3>Glossaire</h3>
    ${t(['Terme','Définition'],[['TPE','Terminal de Paiement Électronique (carte bancaire)'],['Espèce','Paiement en liquide'],['Reste','Solde non encore payé par le membre'],['Décaissement','Sortie d\'argent de la caisse (dépense)'],['AURALIX','Intelligence artificielle d\'identification MegaFit'],['CA','Chiffre d\'Affaires'],['CIN','Carte d\'Identité Nationale marocaine']])}
  `)
];

const html = `<!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8"><title>MegaFit — Manuel Utilisateur 2026</title>
<style>${css}</style></head><body>
<div class="cover pb">
  <div class="logo">👁️</div>
  <div class="brand">MEGAFIT</div>
  <div class="sub">AURALIX Intelligence System</div>
  <div style="font-size:16px;color:#fff;margin-top:4px">Manuel Utilisateur Complet</div>
  <div class="ver">VERSION 2026 &nbsp;·&nbsp; USAGE INTERNE &nbsp;·&nbsp; CONFIDENTIEL</div>
</div>
<div class="toc pb">
  <h2>TABLE DES MATIÈRES</h2>
  ${toc.map(([n,t])=>`<div class="ti"><span><span class="tn">${n}</span> ${t}</span></div>`).join('')}
</div>
${chapters.join('\n')}
<div class="ft">
  <p style="font-size:16px;color:#a3ff12;font-weight:700">👁️ MEGAFIT · AURALIX Intelligence System</p>
  <p style="margin-top:8px">Document confidentiel · Usage interne exclusif · © 2026 MegaFit — Tous droits réservés</p>
  <p style="margin-top:4px">Support : support@megafit.ma</p>
</div>
</body></html>`;

fs.writeFileSync(out, html, 'utf8');
console.log('✅ Manuel HTML créé :', out);
