#!/bin/sh
# Run the full test suite (unit + local-chain end-to-end). No network needed.
cd "$(dirname "$0")" || exit 1
python3 -m unittest discover -s tests -p "test*.py" -v
