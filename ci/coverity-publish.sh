#!/bin/bash

set -e

# Results check
[ ! -d "cov-int" ] && echo "Coverity directory not found" && exit 1

# Upload results
echo "Archiving results"
tar czf cov-src.tgz cov-int

SOURCE_DIR=${SOURCE_DIR:-$( cd "$( dirname "${BASH_SOURCE[0]}" )" && dirname $( pwd ) )}
SHA=$(cd ${SOURCE_DIR} && git rev-parse --short HEAD)

echo "Uploading to scan.coverity.com as $SHA"
HTML="$(curl \
	--silent \
	--write-out "\n%{http_code}" \
	--form token="$COVERITY_TOKEN" \
	--form email=$COVERITY_EMAIL \
	--form file=@cov-src.tgz \
	--form version="$SHA" \
	--form description="$COVERITY_PROJECT build" \
	https://scan.coverity.com/builds?project=$COVERITY_PROJECT)"

# Body is everything up to the last line
BODY="$(echo "$HTML" | head -n-1)"

# Status code is the last line
STATUS_CODE="$(echo "$HTML" | tail -n1)"

if [ "${STATUS_CODE}" != "200" -a "${STATUS_CODE}" != "201" ]; then
	echo "Received error code ${STATUS_CODE} from Coverity"
	exit 1
fi
