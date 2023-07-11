#!/bin/bash

set -o pipefail
set -o xtrace
set -o errexit

rsync -av --exclude target/ --exclude .git/ . atrium:manual-http-download/
