#!/bin/sh
#
# Authentification forwarding using curl
#
PATH="/opt/curl/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export PATH
unset http_proxy
unset HTTP_PROXY
unset https_proxy
unset HTTPS_PROXY
URL="$1"
USER="$2"
read PASS
if [ "$PASS" = "" ]; then
   PASS="none"
fi
RES=`cat <<EOF | curl -K -
-s
-k
-o /dev/null
--write-out %{http_code}
-u $USER:$PASS 
--url  "$URL"
EOF
`
echo $RES
if [ "$RES" = "200" ]; then
   exit 0
fi
exit 1
