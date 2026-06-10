#!/bin/sh
# Bootstrap the autotools build system.
set -e
mkdir -p automake m4
autoreconf -fi
