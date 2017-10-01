#!/bin/bash


DIR="$( cd "$( dirname "$0" )" && pwd )"
BIN_DIR="$(readlink -f $DIR/../../)"

UGLIFY_ES=$BIN_DIR/node_modules/uglify-es/bin/uglifyjs
CSSO=$BIN_DIR/node_modules/csso-cli/bin/csso
HTML_MINFIER=$BIN_DIR/node_modules/html-minifier/cli.js
BROTLI=/usr/local/bin/brotli

WWW_DIR=/var/www/sertifikatsok
SERVICE_NAME=sertifikatsok


temp_dir=$(mktemp --directory) 
uuid=$(uuidgen)

cp $DIR/../www/* $temp_dir -R
cd $temp_dir

# sertifikatsok.js and .css are subject to change, so best to add some cache busting
mv ./resources/sertifikatsok.js ./resources/sertifikatsok-$uuid.js
sed -i -e "s/sertifikatsok.js/sertifikatsok-$uuid.js/" index.html
mv ./resources/sertifikatsok.css ./resources/sertifikatsok-$uuid.css
sed -i -e "s/sertifikatsok.css/sertifikatsok-$uuid.css/" index.html

find $temp_dir -name '*.js' -type f -exec $UGLIFY_ES  '{}' --mangle --compress -o '{}' \;
find $temp_dir -name '*.css' -type f -exec $CSSO '{}' --output '{}' \;
find $temp_dir -name '*.html' -type f -exec $HTML_MINFIER --remove-comments --collapse-whitespace --output '{}' '{}' \;

find $temp_dir -type f -not -name '*.png' -exec $BROTLI '{}' \;

rsync $temp_dir/ $WWW_DIR --delete --recursive

rm -Rf $temp_dir

sudo /usr/bin/systemctl reload $SERVICE_NAME
