#!/usr/bin/env bash
# Convert jupyter files to markdown
# Usage: convert.sh
set -eou pipefail
for f in *.ipynb; do
    # file=${f%.*}
    jupyter nbconvert --output-dir='./docs' --execute --to pdf "$f"
done
shfmt -w -i 4 bin/convert.sh
