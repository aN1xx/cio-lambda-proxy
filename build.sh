#!/usr/bin/env bash

set -ex

# Build script that prepares lambda-package.zip
# This script must run inside environment with Python & pip; it does not need Docker itself.

BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PACKAGE_DIR="${BASE_DIR}/cio_lambda_proxy"
BUILD_DIR="${BASE_DIR}/build"

# clean build dir
if [ -d "${BUILD_DIR}" ]; then
    rm -rf "${BUILD_DIR}"
fi

mkdir -p "${BUILD_DIR}"

# copy source code
cp -rf "${PACKAGE_DIR}" "${BUILD_DIR}/"

# export dependencies from poetry
poetry self add poetry-plugin-export 2>/dev/null || true
poetry export -f requirements.txt --output "${BUILD_DIR}/requirements.txt" --without-hashes

(
    cd "${BUILD_DIR}"
    # install deps into build dir for Linux platform (AWS Lambda compatibility)
    pip install --upgrade pip
    
    # Install all dependencies normally
    pip install --target . -r requirements.txt
    
    # Remove macOS-specific binary files that won't work in Lambda
    find . -name "*.dylib" -delete 2>/dev/null || true
    find . -name "*darwin.so" -delete 2>/dev/null || true
    
    echo "⚠️  Warning: Removed macOS-specific binaries. This package needs to be rebuilt in Linux environment for production use."
    
    rm -f requirements.txt

    # pre-compile pyc files (optional but nice)
    python -m compileall -q -f .

    chmod -R ugo+r .
    chmod -R ugo+rX .
)

(
    cd "${BUILD_DIR}"
    
    # FINAL CHECK: Remove any remaining macOS-specific binaries before packaging
    find . -name "*darwin.so" -delete 2>/dev/null || true
    find . -name "*.dylib" -delete 2>/dev/null || true
    
    echo "📋 Final package contents check:"
    darwin_files=$(find . -name "*darwin*" | wc -l)
    echo "   Darwin files: $darwin_files"
    
    zip -r ../lambda-package.zip . -x "*.pyc" "*/__pycache__/*"
)

echo "✅ Build completed successfully in ${BUILD_DIR}"
echo "📦 Lambda package created: lambda-package.zip"
