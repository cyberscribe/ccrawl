#!/bin/bash

# Create and activate virtual environment
python3 -m venv ccrawl_env
source ccrawl_env/bin/activate

# Install requirements
pip install -r requirements.txt

# Run the crawler
python ccrawl.py "$@"

# Deactivate virtual environment
deactivate

