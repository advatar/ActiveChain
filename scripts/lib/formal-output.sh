#!/usr/bin/env bash

# Formal tools emit proof progress and warnings on both output streams. Keep
# them in one evidence stream so callers can validate everything they display.
capture_formal_output() {
  "$@" 2>&1
}
