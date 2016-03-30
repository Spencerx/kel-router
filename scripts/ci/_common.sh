if [ -n "$TRAVIS_TAG" ]; then
    BUILD_TAG="$TRAVIS_TAG"
else
    BUILD_TAG="git-${TRAVIS_COMMIT:0:8}"
fi

BUILDER_IMAGE="quay.io/kelproject/bundle-builder:git-1e209f97"
BUNDLE_FILE="router-$BUILD_TAG.tgz"
