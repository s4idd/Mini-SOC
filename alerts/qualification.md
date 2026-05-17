# Qualification des alertes — Tableau de triage

**Période analysée** : 2026-04-11 10:00 — 12:00 UTC  
**Analyste** : Said  
**Total alertes** : 9

---

## Tableau de triage

| # | Timestamp (UTC) | IP Source | Port | Règle Wazuh | Niveau | Description | Verdict | Action |
|---|-----------------|-----------|------|-------------|--------|-------------|---------|--------|
| 1 | 10:12:05 | 192.168.64.30 | — | 1002 | 2 | Unknown problem in system | Faux positif | Ignoré — bruit NSE |
| 2 | 10:12:18 | 192.168.64.30 | 22 | 5706 | 6 | SSH insecure connection attempt | Vrai positif | Documenté |
| 3 | 10:35:02 | 192.168.64.30 | 22 | 5710 | 8 | Multiple SSH auth failures | Vrai positif | Alerté |
| 4 | 10:35:04 | 192.168.64.30 | 22 | 5763 | 10 | SSH brute force detected | Vrai positif | Bloqué (iptables) |
| 5 | 10:35:10 | 192.168.64.30 | 22 | 100001 | 12 | Custom — Brute force SSH critique | Vrai positif | Alerte critique |
| 6 | 10:43:00 | — | — | 550 | 7 | Integrity checksum changed | Vrai positif | Documenté |
| 7 | 10:43:05 | — | — | 100004 | 11 | Custom — Fichier système modifié | Vrai positif | Alerté |
| 8 | 11:10:22 | 192.168.64.30 | 80 | 31101 | 6 | Apache web attack detected | Vrai positif | Documenté |
| 9 | 11:10:25 | 192.168.64.30 | 80 | 100005 | 10 | Custom — Injection SQL détectée | Vrai positif | Alerté |

---

## Synthèse

| Métrique | Valeur |
|----------|--------|
| Total alertes | 9 |
| Vrais positifs | 8 (89%) |
| Faux positifs | 1 (11%) |
| Alertes critiques (niveau ≥ 10) | 4 |
| Règles personnalisées déclenchées | 3 |

---

## Méthodologie de qualification

Pour chaque alerte, la qualification suit ce processus :

1. **Contexte** — L'alerte correspond-elle à une action connue dans la fenêtre de test ?
2. **Corrélation** — Y a-t-il d'autres alertes depuis la même source au même moment ?
3. **Verdict** — Vrai positif (VP) si l'alerte correspond à une attaque réelle, Faux positif (FP) sinon
4. **Action** — Blocage, documentation, ou ignoré selon la criticité

---

## Faux positifs identifiés

| # | Règle | Raison | Correction |
|---|-------|--------|------------|
| 1 | 1002 | Bruit généré par les scripts NSE de Nmap | Ajout d'une exception pour les scans internes |
