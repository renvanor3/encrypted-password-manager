# Gestionnaire de mot de passe chiffrée

Gestionnaire de mdp en ligne de commande :

- Chiffrement avec AES-256-GCM
- La clé de chiffrement est dérivée du mdp maître via PBKDF2 avec 500k itérations et sel aléatoire de 16 octets
- Nonce unique par mdp enregistrer
- Aléatoire cryptographique avec us.urandom

## Utilisation

- python pwd_manager.py add website
- python pwd_manager.py get website
- python pwd_manager.py list
- python pwd_manager.py del website

