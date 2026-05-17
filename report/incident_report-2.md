# Rapport d'Incident — Mini-SOC Personnel

**Référence** : IR-2026-001  
**Date** : Avril 2026  
**Auteur** : Said  
**Statut** : Clôturé  
**Classification** : Confidentiel — Usage interne  

---

## 1. Résumé exécutif

Dans le cadre d'un projet personnel de cybersécurité, un environnement SOC (Security Operations Center) a été déployé sur machines virtuelles avec Wazuh comme SIEM open source. Trois vecteurs d'attaque ont été simulés depuis une machine Kali Linux : un scan réseau (Nmap), une attaque par force brute SSH (Hydra) et une injection SQL (SQLmap).

L'ensemble des attaques a été détecté par Wazuh, analysé et qualifié. 5 règles de détection personnalisées ont été créées pour améliorer la couverture. Sur 9 alertes générées, 8 ont été qualifiées vrais positifs (89%). Aucun système de production n'a été affecté — l'environnement est entièrement isolé.

---

## 2. Environnement technique

### Architecture SOC

| Composant | Rôle | Technologie |
|-----------|------|-------------|
| SOC Manager | SIEM central — collecte, analyse, alertes | Wazuh 4.7.4 (Docker) |
| Wazuh Indexer | Stockage et indexation des alertes | OpenSearch 2.x |
| Wazuh Dashboard | Interface de visualisation | Kibana fork |
| Machine cible | Système surveillé avec agent Wazuh | Ubuntu Server 22.04 |
| Machine attaquante | Simulation d'attaques offensives | Kali Linux 2024 |
| Hyperviseur | Virtualisation des machines | UTM + Docker Desktop |

### Topologie réseau

```
Mac hôte — Docker Desktop
└── Wazuh Manager + Indexer + Dashboard
        ↑ logs / alertes (port 1514)
UTM — Réseau isolé 192.168.64.0/24
├── VM Cible    192.168.64.20  (Ubuntu + Agent Wazuh)
└── VM Attacker 192.168.64.30  (Kali Linux)
```

---

## 3. Chronologie des incidents

### Incident 1 — Scan réseau (10:12 UTC)

| Champ | Détail |
|-------|--------|
| Outil | Nmap 7.94 |
| Technique MITRE | T1046 — Network Service Discovery |
| Durée | ~2 minutes |
| Alertes | 2 (1 VP, 1 FP) |

```bash
nmap -sV -O -p- 192.168.64.20
nmap --script vuln 192.168.64.20
```

Résultat : Découverte des ports 22 (SSH), 80 (HTTP), 3306 (MySQL).

---

### Incident 2 — Brute Force SSH (10:35 UTC)

| Champ | Détail |
|-------|--------|
| Outil | Hydra 9.5 |
| Technique MITRE | T1110.001 — Brute Force: Password Guessing |
| Tentatives | ~300 en 8 minutes |
| Alertes | 3 (3 VP) |

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.64.20 -t 4
```

Résultat : Détection dès la 8ème tentative. Règle personnalisée déclenchée au niveau critique 12.

---

### Incident 3 — Injection SQL (11:10 UTC)

| Champ | Détail |
|-------|--------|
| Outil | SQLmap 1.7 |
| Technique MITRE | T1190 — Exploit Public-Facing Application |
| Type | UNION-based SQL Injection |
| Alertes | 2 (2 VP) |

```bash
sqlmap -u "http://192.168.64.20/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=xxxx; security=low" --dbs --batch
```

Résultat : Extraction de la base de données DVWA incluant les hashes de mots de passe.

---

## 4. Alertes générées et qualification

| # | Timestamp | IP Source | Règle | Niveau | Description | Verdict |
|---|-----------|-----------|-------|--------|-------------|---------|
| 1 | 10:12:05 | 192.168.64.30 | 1002 | 2 | Unknown problem in system | Faux positif |
| 2 | 10:12:18 | 192.168.64.30 | 5706 | 6 | SSH insecure connection | Vrai positif |
| 3 | 10:35:02 | 192.168.64.30 | 5710 | 8 | Multiple SSH auth failures | Vrai positif |
| 4 | 10:35:04 | 192.168.64.30 | 5763 | 10 | SSH brute force detected | Vrai positif |
| 5 | 10:35:10 | 192.168.64.30 | 100001 | 12 | Custom — Brute force critique | Vrai positif |
| 6 | 10:43:00 | — | 550 | 7 | Integrity checksum changed | Vrai positif |
| 7 | 10:43:05 | — | 100004 | 11 | Custom — Fichier système modifié | Vrai positif |
| 8 | 11:10:22 | 192.168.64.30 | 31101 | 6 | Apache web attack | Vrai positif |
| 9 | 11:10:25 | 192.168.64.30 | 100005 | 10 | Custom — Injection SQL | Vrai positif |

**Synthèse :** 9 alertes · 8 vrais positifs (89%) · 1 faux positif (11%)

---

## 5. Règles personnalisées créées

```xml
<!-- Règle 1 : Brute force SSH critique -->
<rule id="100001" level="12">
  <if_matched_sid>5710</if_matched_sid>
  <same_source_ip />
  <description>Brute force SSH critique — plus de 10 echecs meme IP</description>
  <mitre><id>T1110.001</id></mitre>
</rule>

<!-- Règle 2 : Scan de ports -->
<rule id="100002" level="8">
  <if_sid>1002</if_sid>
  <match>port scan</match>
  <description>Scan de ports detecte</description>
  <mitre><id>T1046</id></mitre>
</rule>

<!-- Règle 3 : Connexion SSH depuis IP inconnue -->
<rule id="100003" level="9">
  <if_sid>5715</if_sid>
  <not_same_source_ip />
  <description>Connexion SSH depuis IP non referencee</description>
  <mitre><id>T1078</id></mitre>
</rule>

<!-- Règle 4 : Modification fichier système critique -->
<rule id="100004" level="11">
  <if_sid>550</if_sid>
  <match>/etc/passwd|/etc/shadow|/etc/sudoers</match>
  <description>Modification fichier systeme critique</description>
  <mitre><id>T1098</id></mitre>
</rule>

<!-- Règle 5 : Injection SQL dans logs Apache -->
<rule id="100005" level="10">
  <if_sid>31101</if_sid>
  <url_match>union|select|insert|drop|;--|0x</url_match>
  <description>Tentative injection SQL detectee</description>
  <mitre><id>T1190</id></mitre>
</rule>
```

---

## 6. Cartographie MITRE ATT&CK

| Tactique | Technique | ID | Outil | Détecté |
|----------|-----------|-----|-------|---------|
| Reconnaissance | Network Service Discovery | T1046 | Nmap | ✅ |
| Credential Access | Brute Force: Password Guessing | T1110.001 | Hydra | ✅ |
| Initial Access | Exploit Public-Facing Application | T1190 | SQLmap | ✅ |
| Persistence | Valid Accounts | T1078 | — | ✅ |
| Privilege Escalation | Account Manipulation | T1098 | — | ✅ |

---

## 7. Analyse d'impact

**Scan réseau (T1046)** : En production, cette phase aurait permis de cartographier l'infrastructure et préparer des attaques ciblées. Impact potentiel : moyen.

**Brute Force SSH (T1110.001)** : En cas de succès, accès initial obtenu avec les privilèges root. Impact potentiel : critique — exfiltration de données, pivot réseau, ransomware.

**Injection SQL (T1190)** : Extraction complète de la base de données. Impact potentiel : critique — vol de données utilisateurs, compromission des credentials.

---

## 8. Remédiation

### Actions immédiates

```bash
# Blocage IP attaquante
sudo iptables -A INPUT -s 192.168.64.30 -j DROP
sudo iptables-save > /etc/iptables/rules.v4

# Durcissement SSH
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
sudo systemctl restart ssh

# Fail2Ban
sudo apt install fail2ban -y
sudo systemctl enable --now fail2ban

# WAF Apache
sudo apt install libapache2-mod-security2 -y
sudo a2enmod security2
sudo systemctl restart apache2
```

### Recommandations long terme

1. Authentification SSH par clé uniquement
2. Pare-feu UFW avec liste blanche d'IPs
3. MFA sur tous les accès sensibles
4. Alertes email automatiques pour alertes niveau ≥ 10
5. Audits réguliers avec Lynis et OpenVAS
6. Requêtes préparées (PDO) dans toutes les applications web

---

## 9. Indicateurs de compromission (IOCs)

| Type | Valeur | Contexte |
|------|--------|---------|
| IP | 192.168.64.30 | Machine attaquante Kali Linux |
| Outil | Hydra 9.5 | Brute force SSH |
| Outil | SQLmap 1.7 | Injection SQL |
| Port | 22/TCP | Cible SSH |
| Port | 80/TCP | Cible HTTP / SQLi |
| User | root | Compte ciblé SSH |
| Log | /var/log/auth.log | Traces authentification |
| Règles | 5710, 5763, 100001 | Détection brute force |
| Règles | 31101, 100005 | Détection SQLi |

---

## 10. KPIs SOC

| Indicateur | Valeur | Objectif | Statut |
|-----------|--------|---------|--------|
| MTTD (Mean Time to Detect) | ~3 secondes | < 5 min | ✅ |
| MTTR (Mean Time to Respond) | ~8 minutes | < 30 min | ✅ |
| Taux de détection | 100% | > 95% | ✅ |
| Taux de faux positifs | 11% | < 20% | ✅ |
| Règles personnalisées | 5 | — | ✅ |
| Alertes qualifiées | 9/9 | 100% | ✅ |
| Couverture MITRE ATT&CK | 5 techniques | — | ✅ |

---

## 11. Conclusion

Ce projet a permis de déployer un environnement SOC complet et de valider les capacités de détection de Wazuh face à trois types d'attaques réelles. Toutes les attaques ont été détectées, qualifiées et remédiées avec succès.

Les compétences développées couvrent l'ensemble du cycle SOC : déploiement d'infrastructure (Docker, UTM, Ubuntu), simulation d'attaques offensives (Nmap, Hydra, SQLmap), analyse de logs SIEM, création de règles avec mapping MITRE ATT&CK, qualification d'alertes et rédaction de rapport d'incident.

---

## Annexes

### Stack technique
- **SIEM** : Wazuh 4.7.4 · **Indexer** : OpenSearch 2.x · **Dashboard** : Wazuh Dashboard
- **Virtualisation** : UTM + Docker Desktop (macOS Apple Silicon M-series)
- **OS Cible** : Ubuntu Server 22.04 LTS ARM64
- **OS Attaquant** : Kali Linux 2024
- **Outils offensifs** : Nmap · Hydra · SQLmap · DVWA
- **Framework** : MITRE ATT&CK v14

### Commandes utiles Wazuh
```bash
# Statut des agents connectés
sudo /var/ossec/bin/agent_control -l

# Logs d'alertes en temps réel
sudo tail -f /var/ossec/logs/alerts/alerts.log

# Tester une règle
sudo /var/ossec/bin/wazuh-logtest

# Redémarrer après modification des règles
sudo systemctl restart wazuh-manager
```
