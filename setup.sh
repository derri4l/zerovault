#!/bin/bash
echo "Welcome to zerovault. Getting dependencies."
pip install cryptography argon2-cffi --break-system-packages

clear

echo "Creating zvault alias..."
zerovault=$(pwd)
echo "alias zvault='python3 $zerovault/main.py'" >> ~/.bashrc
source ~/.bashrc

echo "Setup complete. Run 'zvault init' to create your vault."
echo "If alias doesn't work, run: source ~/.bashrc"
