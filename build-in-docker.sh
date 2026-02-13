#!/usr/bin/env bash

set -ex

# Build Lambda package in Amazon Linux 2-based image compatible with AWS runtime

docker build -t cio-lambda-proxy-builder .

# Run build inside container, mounting current project into /app and executing build.sh there
docker run --rm -v "$(pwd):/app" -w /app cio-lambda-proxy-builder ./build.sh

echo "✅ Docker build completed"
