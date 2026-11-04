#!/usr/bin/env bash
# Build a self-contained Overleaf project zip and check that it compiles from a clean copy.
set -euo pipefail
cd "$(dirname "$0")"
OUT=overleaf
rm -rf "$OUT/project" && mkdir -p "$OUT/project/figures" "$OUT/project/tables"
cp main.tex numbers.tex references.bib "$OUT/project/"
cp figures/*.pdf "$OUT/project/figures/"
cp tables/*.tex "$OUT/project/tables/"
( cd "$OUT/project" && latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex > ../clean_build.log 2>&1 )
pages=$(grep -o 'main.pdf ([0-9]* pages' "$OUT/project/main.log" | grep -o '[0-9]*' | tail -1)
( cd "$OUT/project" && latexmk -c > /dev/null 2>&1; rm -f main.bbl )
rm -f "$OUT/tkde-overleaf.zip"
( cd "$OUT/project" && zip -qr ../tkde-overleaf.zip main.tex numbers.tex references.bib figures tables )
echo "clean build OK, ${pages:-?} pages -> $OUT/tkde-overleaf.zip"
