#! /bin/bash

set -x
DNS_BACKENDS=online1.lescigales.org:5353,online3.lescigales.org:5353 go run ./dns-lb.go -port 6666 $@


