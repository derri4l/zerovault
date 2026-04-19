#!/bin/bash
echo "Welcome to zerovault. Getting dependencies."
python3 -m venv .zvault
source .zvault/bin/activate

pip install cryptography argon2-cffi
clear

echo "Creating zvault alias..."
zerovault=$(pwd)
echo "alias zvault='python3 $zerovault/main.py'" >> ~/.bashrc
source ~/.bashrc

echo "Setup complete. Run 'zvault init' to create your vault."
echo "If alias doesn't work, run: source ~/.bashrc"
