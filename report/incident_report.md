# Rapport d'incident — Mini-SOC Personnel
**Référence** : IR-2026-001  
**Date** : Avril 2026  
**Auteur** : Said  
**Statut** : Clôturé  
**Classification** : Confidentiel — Usage interne  

---

## 1. Résumé exécutif

Dans le cadre d'un projet personnel de cybersécurité, un environnement SOC (Security Operations Center) a été déployé afin de simuler des scénarios d'attaques réels et d'évaluer les capacités de détection d'un SIEM open source. Deux vecteurs d'attaque ont été simulés depuis une machine Kali Linux : un scan réseau avec Nmap et une attaque par force brute SSH avec Hydra. L'ensemble des attaques a été détecté par Wazuh, analysé et qualifié. Des règles de détection personnalisées ont été créées pour améliorer la couverture de détection. Aucun système de production n'a été affecté — l'environnement est entièrement isolé.

---

## 2. Environnement technique

### 2.1 Architecture SOC

| Composant | Rôle | Technologie |
|-----------|------|-------------|
| SOC Manager | SIEM central — collecte, analyse, alertes | Wazuh 4.7.4 (Docker) |
| Machine cible | Système surveillé avec agent Wazuh | Ubuntu Server 22.04 |
| Machine attaquante | Simulation d'attaques offensives | Kali Linux |
| Hyperviseur | Virtualisation des machines | UTM (Apple Silicon) |

### 2.2 Topologie réseau

```
Mac hôte (Docker Desktop)
└── Wazuh Manager + Indexer + Dashboard
        ↑ logs / alertes
UTM (réseau interne 192.168.64.0/24)
├── VM Cible   — 192.168.64.20 (Ubuntu + agent Wazuh)
└── VM Attacker — 192.168.64.30 (Kali Linux)
```

---

## 3. Chronologie des incidents

### Incident 1 — Scan réseau (Reconnaissance)

| Champ | Détail |
|-------|--------|
| Date/Heure | 2026-04-11 10:12:00 UTC |
| Source | 192.168.64.30 (Kali Linux) |
| Cible | 192.168.64.20 (Ubuntu Cible) |
| Technique MITRE | T1046 — Network Service Discovery |
| Outil utilisé | Nmap |
| Durée | ~2 minutes |

**Commandes exécutées :**
```bash
nmap -sV -O -p- 192.168.64.20
nmap --script vuln 192.168.64.20
```

**Résultat :** Découverte des ports ouverts (22/SSH, 80/HTTP, 3306/MySQL). Wazuh a détecté l'activité via les logs système et les règles de détection de scan.

---

### Incident 2 — Brute Force SSH

| Champ | Détail |
|-------|--------|
| Date/Heure | 2026-04-11 10:35:00 UTC |
| Source | 192.168.64.30 (Kali Linux) |
| Cible | 192.168.64.20 — port 22/SSH |
| Technique MITRE | T1110.001 — Brute Force: Password Guessing |
| Outil utilisé | Hydra |
| Tentatives | ~300 tentatives en 8 minutes |

**Commandes exécutées :**
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.64.20
```

**Résultat :** Multiples échecs d'authentification SSH détectés. Wazuh a levé une alerte de niveau 10 (Authentication Brute Force) après le seuil de 8 tentatives échouées depuis la même IP source.

---

## 4. Alertes générées et qualification

### 4.1 Tableau de qualification

| # | Timestamp | IP Source | Règle Wazuh | Niveau | Description | Verdict | Action |
|---|-----------|-----------|-------------|--------|-------------|---------|--------|
| 1 | 10:12:05 | 192.168.64.30 | 1002 | 2 | Unknown problem somewhere in the system | Faux positif | Ignoré — bruit système |
| 2 | 10:12:18 | 192.168.64.30 | 5706 | 6 | SSH insecure connection attempt | Vrai positif | Documenté |
| 3 | 10:35:02 | 192.168.64.30 | 5710 | 8 | Multiple SSH authentication failures | Vrai positif | Alerté |
| 4 | 10:35:04 | 192.168.64.30 | 5763 | 10 | SSH brute force — Multiple auth failures | Vrai positif | Bloqué (iptables) |
| 5 | 10:35:10 | 192.168.64.30 | 100001 | 12 | Règle custom — Brute force SSH critique | Vrai positif | Alerte critique |
| 6 | 10:43:00 | — | 550 | 7 | Integrity checksum changed | Vrai positif | Documenté |

### 4.2 Synthèse

| Métrique | Valeur |
|----------|--------|
| Total alertes générées | 6 |
| Vrais positifs | 5 (83%) |
| Faux positifs | 1 (17%) |
| Alertes critiques (niveau ≥ 10) | 2 |

---

## 5. Règles de détection personnalisées

Les règles suivantes ont été créées dans `/var/ossec/etc/rules/local_rules.xml` pour améliorer la détection :

### Règle 1 — Brute force SSH critique
```xml
<group name="sshd,authentication_failed,custom">
  <rule id="100001" level="12">
    <if_matched_sid>5710</if_matched_sid>
    <same_source_ip />
    <description>Brute force SSH critique — plus de 10 echecs depuis la meme IP</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
  </rule>
</group>
```

### Règle 2 — Scan de ports détecté
```xml
<group name="network,scan,custom">
  <rule id="100002" level="8">
    <if_sid>1002</if_sid>
    <match>port scan</match>
    <description>Scan de ports detecte depuis une source externe</description>
    <mitre>
      <id>T1046</id>
    </mitre>
  </rule>
</group>
```

### Règle 3 — Connexion SSH depuis IP inconnue
```xml
<group name="sshd,custom">
  <rule id="100003" level="9">
    <if_sid>5715</if_sid>
    <not_same_source_ip />
    <description>Connexion SSH reussie depuis une IP non referencee</description>
    <mitre>
      <id>T1078</id>
    </mitre>
  </rule>
</group>
```

### Règle 4 — Modification de fichier système critique
```xml
<group name="syscheck,custom">
  <rule id="100004" level="11">
    <if_sid>550</if_sid>
    <match>/etc/passwd|/etc/shadow|/etc/sudoers</match>
    <description>Modification d un fichier systeme critique detectee</description>
    <mitre>
      <id>T1098</id>
    </mitre>
  </rule>
</group>
```

---

## 6. Cartographie MITRE ATT&CK

| Tactique | Technique | ID | Outil | Détecté |
|----------|-----------|-----|-------|---------|
| Reconnaissance | Network Service Discovery | T1046 | Nmap | ✅ |
| Credential Access | Brute Force: Password Guessing | T1110.001 | Hydra | ✅ |
| Persistence | Valid Accounts | T1078 | — | ✅ |
| Defense Evasion | — | — | — | — |

---

## 7. Analyse d'impact

### 7.1 Impact simulé en environnement réel

**Scan réseau (T1046)** : En environnement de production, cette phase de reconnaissance aurait permis à l'attaquant de cartographier l'infrastructure, identifier les services exposés et préparer des attaques ciblées. Impact potentiel : moyen — aucune donnée compromise mais exposition de la surface d'attaque.

**Brute Force SSH (T1110.001)** : En cas de succès, l'attaquant aurait obtenu un accès initial au système avec les privilèges du compte ciblé. Impact potentiel : critique — accès root possible, exfiltration de données, pivot réseau.

### 7.2 Systèmes affectés

| Système | Impact | Données compromises |
|---------|--------|---------------------|
| VM Cible (Ubuntu) | Simulé — environnement isolé | Aucune |
| VM SOC (Wazuh) | Aucun | Aucune |

---

## 8. Remédiation

### 8.1 Actions immédiates appliquées

**Blocage de l'IP attaquante avec iptables :**
```bash
sudo iptables -A INPUT -s 192.168.64.30 -j DROP
sudo iptables-save > /etc/iptables/rules.v4
```

**Durcissement SSH sur la machine cible :**
```bash
sudo nano /etc/ssh/sshd_config
```
```
PermitRootLogin no
PasswordAuthentication no
MaxAuthTries 3
LoginGraceTime 20
AllowUsers soc
```
```bash
sudo systemctl restart ssh
```

**Mise en place de Fail2Ban :**
```bash
sudo apt install fail2ban -y
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

### 8.2 Recommandations long terme

1. Mettre en place une authentification par clé SSH uniquement (désactiver les mots de passe)
2. Déployer un pare-feu applicatif (UFW) avec liste blanche d'IPs autorisées
3. Activer l'authentification multi-facteurs (MFA) sur tous les accès SSH
4. Mettre en place des alertes email automatiques pour les alertes de niveau ≥ 10
5. Effectuer des audits de sécurité réguliers avec Lynis

---

## 9. Indicateurs de compromission (IOCs)

| Type | Valeur | Contexte |
|------|--------|---------|
| IP | 192.168.64.30 | Machine attaquante Kali Linux |
| User-agent | Hydra | Outil de brute force SSH |
| Port cible | 22/TCP | SSH |
| Fichier log | /var/log/auth.log | Traces des tentatives d'authentification |
| Règle Wazuh | 5710, 5763, 100001 | Règles ayant détecté l'attaque |

---

## 10. KPIs SOC

| Indicateur | Valeur | Objectif |
|-----------|--------|---------|
| MTTD (Mean Time to Detect) | ~3 secondes | < 5 min ✅ |
| MTTR (Mean Time to Respond) | ~8 minutes | < 30 min ✅ |
| Taux de détection | 100% | > 95% ✅ |
| Taux de faux positifs | 17% | < 20% ✅ |
| Règles personnalisées créées | 4 | — |
| Alertes qualifiées | 6/6 | 100% ✅ |

---

## 11. Conclusion

Ce projet a permis de déployer un environnement SOC fonctionnel et de valider les capacités de détection de Wazuh face à des attaques réelles. Les deux vecteurs simulés (scan réseau et brute force SSH) ont été détectés avec succès, qualifiés et remédiés. Les règles personnalisées créées ont amélioré la granularité de la détection et réduit le temps de réponse.

Les compétences développées dans ce projet couvrent l'ensemble du cycle SOC : déploiement d'infrastructure, simulation d'attaques, analyse de logs, création de règles SIEM, qualification d'alertes et rédaction de rapport d'incident.

---

## Annexes

### Annexe A — Commandes de vérification Wazuh
```bash
# Statut des agents
sudo /var/ossec/bin/agent_control -l

# Logs en temps réel
sudo tail -f /var/ossec/logs/alerts/alerts.log

# Règles actives
sudo /var/ossec/bin/wazuh-logtest
```

### Annexe B — Stack technique complète
- **SIEM** : Wazuh 4.7.4
- **Indexer** : OpenSearch 2.x
- **Dashboard** : Wazuh Dashboard (Kibana fork)
- **Virtualisation** : UTM + Docker Desktop
- **OS Cible** : Ubuntu Server 22.04 LTS ARM64
- **OS Attaquant** : Kali Linux 2024
- **Framework** : MITRE ATT&CK v14

