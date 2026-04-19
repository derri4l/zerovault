#!/bin/bash
echo "Welcome to zerovault. Getting dependencies."

if ! command -v python3 &> /dev/null; then
    echo "Python3 not found. Please install it first."
    exit 1
fi

python3 -m venv .zvault
.zvault/bin/pip install cryptography argon2-cffi

echo "Creating zvault alias..."
zerovault=$(pwd)
echo "alias zvault='.zvault/bin/python3 $zerovault/main.py'" >> ~/.bashrc

echo "Setup complete. Run 'source ~/.bashrc' then 'zvault init'."
