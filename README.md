# Gestion Contributions Église - V4.3 (Option A)

## Fonctionnalités clés
- Admin principal: admin / Admin123!
- Inscription membre (compte actif immédiatement)
- Rôles: ADMIN, MEMBRE
- Admin: crée comptes membres, enregistre des contributions pour un membre, gère dépenses, exports
- Membre: voit ses contributions, enregistre ses contributions, exports et rapports (scope membre)
- Données: CSV/JSON uniquement (dossier /data)

## Lancer en local
```bash
python -m venv .venv
# Git Bash:
source .venv/Scripts/activate
pip install -r backend/requirements.txt
uvicorn backend.main:app --reload --port 8000
```

Ouvrir: http://127.0.0.1:8000/
Docs API: http://127.0.0.1:8000/docs


## Démarrage rapide (scripts)
- Windows : double-clique `run_local.bat`
- macOS/Linux : `./run_local.sh`

## Notes
- Les usernames sont normalisés (trim + minuscules) pour éviter les erreurs de connexion.
- Les mots de passe sont trimés (espaces invisibles).


## Correctif V4.3
- Correction conflit d'IDs entre 'Mon compte' et 'Créer un compte membre' (admin).
- Ajout champ Email dans la création admin + envoi au backend.
