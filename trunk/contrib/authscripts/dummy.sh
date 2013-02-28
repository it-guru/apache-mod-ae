#!/bin/sh
read A
if [ "$1" = "admin" -a "$A" = "acache" ]; then
   exit 0
fi
if [ "$1" = "user" -a "$A" = "ac" ]; then
   exit 0
fi
if [ "$1" = "guest" -a "$A" = "" ]; then
   exit 0
fi
exit 1
