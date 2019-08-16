#!/bin/bash

if [[ $VULAS_RELEASE =~ ^(\d+\.\d+\.\d+-SNAPSHOT)$ ]]; then
    echo "$DOCKER_HUB_NARAMSIM_PASSWORD" | docker login -u "$DOCKER_HUB_NARAMSIM_USERNAME" --password-stdin
    (cd docker && push-images.sh -r registry.hub.docker.com -p vulas -v "${VULAS_RELEASE}")
else
    echo '[!] Refusing to push non-snapshot version'
    echo "    VULAS_RELEASE: $VULAS_RELEASE"
fi