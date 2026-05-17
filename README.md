# 🛡️ Mini-SOC — Détection et Réponse aux Incidents

> Projet personnel de cybersécurité — Déploiement d'un environnement SOC complet avec Wazuh (SIEM open source), simulation d'attaques réelles et analyse des alertes.

---

## 📐 Architecture

```
Mac hôte (Docker Desktop)
└── Wazuh Manager + Indexer + Dashboard  ←  SOC / SIEM

UTM (réseau isolé 192.168.64.0/24)
├── VM Cible    192.168.64.20  —  Ubuntu Server 22.04 + Agent Wazuh
└── VM Attacker 192.168.64.30  —  Kali Linux
```

## 🎯 Objectifs

- Déployer un environnement SOC réaliste sur machines virtuelles
- Simuler des attaques réelles et observer les alertes générées
- Créer des règles de détection personnalisées (MITRE ATT&CK)
- Qualifier les alertes (vrais / faux positifs)
- Rédiger un rapport d'incident complet

## ⚔️ Attaques simulées

| Attaque | Outil | Technique MITRE | Détectée |
|---------|-------|-----------------|----------|
| Scan réseau | Nmap | T1046 | ✅ |
| Brute force SSH | Hydra | T1110.001 | ✅ |
| Injection SQL | SQLmap | T1190 | ✅ |

## 📊 Résultats

| Métrique | Valeur |
|----------|--------|
| Alertes générées | 9 |
| Vrais positifs | 8 (89%) |
| Faux positifs | 1 (11%) |
| Règles personnalisées | 5 |
| MTTD moyen | ~3 secondes |
| MTTR moyen | ~8 minutes |

## 🗂️ Structure du dépôt

```
mini-soc/
├── README.md
├── infrastructure/
│   └── docker-compose.yml        # Stack Wazuh complète
├── rules/
│   └── local_rules.xml           # Règles personnalisées Wazuh
├── attacks/
│   ├── 01_nmap_scan.md           # Scan réseau
│   ├── 02_brute_force_ssh.md     # Brute force SSH
│   └── 03_sql_injection.md       # Injection SQL
├── alerts/
│   └── qualification.md          # Tableau triage VP/FP
└── report/
    └── incident_report.md        # Rapport d'incident complet
```

## 🧰 Stack technique

`Wazuh 4.7.4` · `Docker Desktop` · `Ubuntu Server 22.04` · `Kali Linux` · `UTM` · `MITRE ATT&CK v14` · `OpenSearch` · `Nmap` · `Hydra` · `SQLmap`

## 📄 Rapport d'incident

→ [Voir le rapport complet](report/incident_report.md)

---

*Projet réalisé dans le cadre d'une montée en compétences en cybersécurité - Said, 2026*
