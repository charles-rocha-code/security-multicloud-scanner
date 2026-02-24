#!/bin/bash

echo "Parando API..."
pkill -f api_with_mfa.py || true

echo "Criando backup..."
cp users_db.json users_db_backup_$(date +%Y%m%d_%H%M%S).json

echo "Zerando banco..."
echo "{}" > users_db.json

echo "Subindo API novamente..."
python3 api_with_mfa.py

