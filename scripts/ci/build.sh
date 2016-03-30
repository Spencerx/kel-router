#!/bin/bash
set -ev

here=$(cd "$(dirname "${BASH_SOURCE}")"; pwd -P)
. $here/_common.sh

git archive --format=tar "$TRAVIS_COMMIT" | docker run -i -e BUILDPACK_URL=https://github.com/kelproject/system-go-buildpack.git $BUILDER_IMAGE - > $BUNDLE_FILE
