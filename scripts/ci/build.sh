#!/bin/bash
set -ev

here=$(cd "$(dirname "${BASH_SOURCE}")"; pwd -P)
. $here/_common.sh

git archive --format=tar "$TRAVIS_COMMIT" | docker run -i $BUILDER_IMAGE - > $BUNDLE_FILE
