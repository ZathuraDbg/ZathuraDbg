#! /bin/sh

if [ `uname -s` = "Linux" ]; then
 echo Linux
 gcc -m32 -fPIC -shared -o tinyfiledialogsLinux86.so ../tinyfiledialogs.c
 gcc -m32 -o hello ../hello.c ./tinyfiledialogsLinux86.so

 gcc -m64 -fPIC -shared -o tinyfiledialogsLinux64.so ../tinyfiledialogs.c
 gcc -m64 -o hello ../hello.c ./tinyfiledialogsLinux64.so
elif [ `uname -s` = "OpenBSD" ]; then
 echo OpenBSD
 clang -m32 -fPIC -shared -o tinyfiledialogsOpenBSDx86.so ../tinyfiledialogs.c
 clang -m32 -o hello ../hello.c ./tinyfiledialogsOpenBSDx86.so

 clang -m64 -fPIC -shared -o tinyfiledialogsOpenBSDx64.so ../tinyfiledialogs.c
 clang -m64 -o hello ../hello.c ./tinyfiledialogsOpenBSDx64.so
else
 echo Other Unix
fi
