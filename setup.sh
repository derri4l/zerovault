#!/bin/bash

echo "Welcome to zerovault. Getting dependencies."

#check for py3
if ! command -v python3 &> /dev/null; then
    echo "Python3 not found. Please install it first."
    exit 1
fi

#create the enviroment and install dependencies
python3 -m venv .zvault
.zvault/bin/pip install cryptography argon2-cffi

clear

# create alias for zvault in .bashrc
echo "Creating zvault alias..."

zerovault=$(pwd)

if grep -q "^alias zvault=" ~/.bashrc; then
    echo "Alias already exists."
else
    echo "alias zvault='.zvault/bin/python3 $zerovault/main.py'" >> ~/.bashrc
fi

echo "Setup complete. Run 'source ~/.bashrc' then 'zvault init'."
