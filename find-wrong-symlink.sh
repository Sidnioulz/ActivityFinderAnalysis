#!/bin/sh
#ln -s /location/to/link linkname
#ln -s /location/to/link2 newlink
#mv -T newlink linkname

cd ./applications/

# Can be -f 11 instead of -f 12 on old systems, adjust accordingly
for i in `find . -type l -ls | tr -s " " | cut -d" " -f 12`; do
  dest=`ls "$i" -la`
  if [ "x`echo $dest | grep $PWD`" = "x" ]; then
    name="`echo $dest | cut -d" " -f9`"
    target="`echo $dest | cut -d" " -f11`"
#    echo $dest
#    echo $name
#    echo "$PWD/$target"
    rm $name
    ln -s "$PWD/$(basename $target)" $name
  fi
done

cd -
