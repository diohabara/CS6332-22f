#!/usr/bin/env bash
# Convert jupyter files to markdown
# Usage: convert.sh
set -eou pipefail
for f in *.ipynb; do
    jupyter nbconvert --to markdown "$f"
done
shfmt -w -i 4 convert.sh
