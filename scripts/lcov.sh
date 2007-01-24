#!/bin/sh
make -f scripts/lcov.mk lcov-clean && \
make -f scripts/lcov.mk lcov-build && \
make -f scripts/lcov.mk lcov-report
