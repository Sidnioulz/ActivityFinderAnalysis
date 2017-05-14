#!/bin/sh

find . | while read file; do
  encoding=`file "$file" | grep ISO`
  if [ "x$encoding" != "x" ]; then
    iconv -f ISO-8859-1 -t UTF-8 "$file" > "$file.new"
    mv "$file.new" "$file"
  fi
done
