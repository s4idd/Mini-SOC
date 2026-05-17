# Attaque 2 — Brute Force SSH (Hydra)

## Contexte
Tentative d'accès non autorisé par dictionnaire sur le service SSH après avoir identifié le port 22 ouvert lors du scan Nmap.

## Informations

| Champ | Détail |
|-------|--------|
| Date | 2026-04-11 |
| Heure | 10:35:00 UTC |
| Source | 192.168.64.30 (Kali Linux) |
| Cible | 192.168.64.20 — port 22/SSH |
| Outil | Hydra 9.5 |
| Wordlist | /usr/share/wordlists/rockyou.txt |
| Technique MITRE | T1110.001 — Brute Force: Password Guessing |
| Durée | ~8 minutes |
| Tentatives | ~300 |

## Commandes exécutées

```bash
# Activation de la wordlist rockyou
sudo gunzip /usr/share/wordlists/rockyou.txt.gz

# Lancement du brute force SSH
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.64.20 -t 4 -V
```

## Alertes générées dans Wazuh

| Règle | Niveau | Description | Verdict |
|-------|--------|-------------|---------|
| 5710 | 8 | Multiple SSH authentication failures | Vrai positif |
| 5763 | 10 | SSH brute force detected | Vrai positif |
| 100001 | 12 | Custom — Brute force SSH critique | Vrai positif |

## Analyse

Wazuh a détecté l'attaque dès la 8ème tentative échouée (règle 5710). La règle personnalisée 100001 s'est déclenchée au-delà de 10 tentatives avec une sévérité critique (niveau 12). MTTD : ~3 secondes après le seuil.

## Remédiation appliquée

```bash
# Blocage immédiat de l'IP attaquante
sudo iptables -A INPUT -s 192.168.64.30 -j DROP

# Durcissement SSH
sudo nano /etc/ssh/sshd_config
# PermitRootLogin no
# PasswordAuthentication no
# MaxAuthTries 3

# Installation Fail2Ban
sudo apt install fail2ban -y
sudo systemctl enable fail2ban
```
