#!/bin/bash
set -Eeuo pipefail

# sertifikatsok.js and .css are subject to change, so best to add some cache busting
jshash=$(sha256sum ./www/resources/sertifikatsok.js | head -c 64)
mv ./www/resources/sertifikatsok.js "./www/resources/sertifikatsok-${jshash}.js"
sed -i -e "s/sertifikatsok.js/sertifikatsok-${jshash}.js/" "www/index.html"

csshash=$(sha256sum ./www/resources/sertifikatsok.css | head -c 64)
mv "./www/resources/sertifikatsok.css" "./www/resources/sertifikatsok-${csshash}.css"
sed -i -e "s/sertifikatsok.css/sertifikatsok-${csshash}.css/" "www/index.html"

find "www" -name '*.js' -type f -execdir "terser" '{}' --mangle \
  --compress --output '{}' \;
find "www" -name '*.css' -type f -execdir "csso" '{}' --output '{}' \;
find "www" -name '*.html' -type f -execdir "html-minifier-terser" \
  --remove-comments --collapse-whitespace --output '{}' '{}' \;
