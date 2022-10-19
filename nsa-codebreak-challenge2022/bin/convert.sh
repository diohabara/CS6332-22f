#!/usr/bin/env bash
# Convert jupyter files to markdown
# Usage: convert.sh
set -eou pipefail
for f in *.ipynb; do
    file=${f%.*}
    jupyter nbconvert --to markdown "$file"
    pandoc -s "$file".md -o "docs/$file".pdf
done
shfmt -w -i 4 convert.sh
zip -r solutions docs
