#!/bin/bash
set -e

echo "Starting build process..."
./build.sh

echo "Pushing the package to PyPI..."
uv publish
