#!/bin/bash
set -ex

here=$(cd "$(dirname "${BASH_SOURCE}")"; pwd -P)
. $here/common.sh

gsutil cp "$BUNDLE_FILE" gs://release.kelproject.com/bundles/router/
