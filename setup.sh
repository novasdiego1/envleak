#!/usr/bin/env bash
# envleak — setup local + push a GitHub
# Uso:  ./setup.sh TU_USUARIO_GITHUB
set -e

USER_GH="${1:?Uso: ./setup.sh TU_USUARIO_GITHUB}"

echo "→ Reemplazando YOURUSER por $USER_GH"
sed -i.bak "s/YOURUSER/$USER_GH/g" README.md pyproject.toml && rm -f *.bak

echo "→ Probando que corre"
python3 -m envleak . --no-color | head -6

echo "→ Inicializando git"
git init -q
git add .
git commit -q -m "envleak 0.1.0 — secret scanner for the AI agent surface"
git branch -M main
git remote add origin "https://github.com/$USER_GH/envleak.git" 2>/dev/null || true

echo ""
echo "Listo localmente. Ahora:"
echo "  1. Creá el repo vacío en https://github.com/new  (nombre: envleak, público, SIN README)"
echo "  2. git push -u origin main"
echo ""
echo "Después, para PyPI:"
echo "  pip install build twine"
echo "  python -m build"
echo "  twine upload dist/*"
