# Attaque 1 — Scan réseau (Nmap)

## Contexte
Phase de reconnaissance pour cartographier la surface d'attaque de la machine cible avant toute exploitation.

## Informations

| Champ | Détail |
|-------|--------|
| Date | 2026-04-11 |
| Heure | 10:12:00 UTC |
| Source | 192.168.64.30 (Kali Linux) |
| Cible | 192.168.64.20 (Ubuntu Cible) |
| Outil | Nmap 7.94 |
| Technique MITRE | T1046 — Network Service Discovery |

## Commandes exécutées

```bash
# Scan complet de tous les ports avec détection de version et OS
nmap -sV -O -p- 192.168.64.20

# Scan de vulnérabilités avec les scripts NSE
nmap --script vuln 192.168.64.20
```

## Résultats du scan

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1
80/tcp   open  http    Apache httpd 2.4.52
3306/tcp open  mysql   MySQL 8.0.32
```

## Alertes générées dans Wazuh

| Règle | Niveau | Description | Verdict |
|-------|--------|-------------|---------|
| 1002 | 2 | Unknown problem somewhere in the system | Faux positif |
| 5706 | 6 | SSH insecure connection attempt | Vrai positif |

## Analyse

Le scan a révélé 3 services exposés. L'alerte niveau 2 est un faux positif lié au bruit des scripts NSE. L'alerte niveau 6 sur SSH est un vrai positif.

## Remédiation appliquée

- Désactivation des services non nécessaires
- Mise en place d'un pare-feu UFW avec règles restrictives
- Limitation des connexions SSH par IP source
