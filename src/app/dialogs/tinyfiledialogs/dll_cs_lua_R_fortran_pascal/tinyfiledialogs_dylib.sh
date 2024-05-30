#! /bin/sh

# clang -c ../tinyfiledialogs.c
# clang -dynamiclib tinyfiledialogs.o -o tinyfiledialogsIntel.dylib
# clang -o hello.app ../hello.c ./tinyfiledialogsIntel.dylib

clang -c ../tinyfiledialogs.c

if [ `uname -s` = "Darwin" ]; then
 echo Darwin
 if  [ `uname -m` = "x86_64" ]; then
  echo x86_64
  clang -dynamiclib tinyfiledialogs.o -o tinyfiledialogsIntel.dylib
 elif [ `uname -m` = "arm64" ]; then
  echo arm64
  clang -dynamiclib tinyfiledialogs.o -o tinyfiledialogsAppleSilicon.dylib
 fi
fi
