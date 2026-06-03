#! /bin/bash

./compile.sh

set -x
docker build -f Dockerfile.minimal -t dns-lb ./
