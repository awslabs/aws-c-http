#!/usr/bin/env bash
set -e

sudo nginx -t

curl http://localhost:80
