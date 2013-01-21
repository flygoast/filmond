#! /bin/bash
LC_ALL=C
LANG=C
rm -f version.h
LOCALVER=`git rev-list HEAD | wc -l| awk '{print \$1}'`
if [ $LOCALVER -gt 1 ]; then
    VER=`git rev-list origin/master | wc -l | awk '{print \$1}'`
    if [ $VER -ne $LOCALVER ]; then
        VER="$VER+$(($LOCALVER-$VER))"
    fi

    if ! git diff --quiet HEAD; then
        VER="$VER"M
    fi
    VER="$VER $(git rev-list HEAD -n 1 | cut -c 1-7)"
else
    VER="0"
fi

TAG=`git describe 2>/dev/null`
if [ "x$TAG" = "x" ]; then
    TAG="0.0"
fi
FULL_VERSION="$TAG.$VER"
cat version.h.template | sed "s/\$GIT_VERSION/$FULL_VERSION/g" > version.h
echo "Generated version.h"
