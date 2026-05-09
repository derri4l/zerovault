#!/bin/bash

set -euo pipefail

echo "Installing Zerovault..."

if ! command -v python3 >/dev/null 2>&1; then
    echo "Python3 is required."
    exit 1
fi

project_dir="$(cd "$(dirname "$0")" && pwd)"

install_dir="$HOME/.local/share/zerovault"
bin_dir="$HOME/.local/bin"

mkdir -p "$install_dir"
mkdir -p "$bin_dir"

cp "$project_dir/main.py" "$install_dir/"
cp "$project_dir/keychain.py" "$install_dir/"
cp "$project_dir/requirements.txt" "$install_dir/"

cd "$install_dir"

if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi


echo "Installing dependencies..."

.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt

cat > "$bin_dir/zvault" << EOF
#!/bin/bash
exec "$install_dir/.venv/bin/python3" "$install_dir/main.py" "\$@"
EOF

chmod +x "$bin_dir/zvault"

echo ""
echo "Installation complete."
echo ""

if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo "~/.local/bin is not in your PATH."
    echo "Add this line to your shell config:"
    echo 'export PATH="$HOME/.local/bin:$PATH"'
    echo ""
fi

echo "Run: zvault init"
