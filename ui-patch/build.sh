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
else
  git checkout $(cat /src/.vault-version)
fi

git apply < /src/ui-patch/vault-ui-auth-emerg-yubiotp.patch



make static-dist

if ! type go > /dev/null; then
	echo "Go not installed, installing using gimme" 
	eval "$(curl -sL https://raw.githubusercontent.com/travis-ci/gimme/master/gimme | \
		GIMME_GO_VERSION=stable bash)"
fi

make bin

rm -rf /src/{ui-dist,bin-dist}
mkdir -p /src/{ui-dist,bin-dist}

cp -r http/web_ui/* /src/ui-dist
cp bin/vault /src/bin-dist

