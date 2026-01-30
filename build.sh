#!/bin/bash
set -e

echo "Cleaning dist directory..."
rm -rf dist/

echo "Building the package..."
uv build
