#!/bin/sh

# This script runs every time the container starts.

# The `git` command expects to run in a directory, but our scanner
# specifies the path. We'll run this from the root. The scanner will
# use the correct path provided in its arguments.
git config --global --add safe.directory /scan

# Now, execute the main gitleaks-lite application, passing along
# all the arguments that were given to the container.
exec gitleaks-lite "$@"
