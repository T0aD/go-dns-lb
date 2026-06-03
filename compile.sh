#! /bin/bash

set -x

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o dns-lb
ls -lh ./dns-lb

