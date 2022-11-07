#!/bin/bash

SHORT=c:,h
LONG=checkout:,help
OPTS=$(getopt -a -n weather --options $SHORT --longoptions $LONG -- "$@")

eval set -- "$OPTS"

while :
do
  case "$1" in
    -c | --checkout )
      checkout="$2"
      shift 2
      ;;
    -h | --help)
      "build.sh [-c|--checkout <branch>] [-h|--help]"
      exit 2
      ;;
    --)
      shift;
      break
      ;;
    *)
      echo "Unexpected option: $1"
      ;;
  esac
done

set -e

git clone https://github.com/hashicorp/vault


cd vault

if [ -n "$checkout" ]; then
  git checkout "$checkout"
fi

git apply < /src/ui-patch/vault-ui-auth-emerg-yubiotp.patch



make static-dist


rm -rf /src/ui-dist
mkdir -p /src/ui-dist
cp -r http/web_ui/* /src/ui-dist