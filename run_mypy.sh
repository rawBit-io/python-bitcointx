#!/usr/bin/env sh
#-*-mode: sh; encoding: utf-8-*-

_MY_DIR="$( cd "$( dirname "${0}" )" && pwd )"
set -ex
[ -d "${_MY_DIR}" ]
[ "${_MY_DIR}/run_mypy.sh" -ef "${0}" ]
cd "${_MY_DIR}"

CUSTOM_STRICT_OPTIONS=""
CUSTOM_STRICT_OPTIONS+="--warn-unused-configs "
CUSTOM_STRICT_OPTIONS+="--disallow-subclassing-any "
CUSTOM_STRICT_OPTIONS+="--disallow-any-generics "
CUSTOM_STRICT_OPTIONS+="--disallow-untyped-calls "
#CUSTOM_STRICT_OPTIONS+="--disallow-untyped-defs "
CUSTOM_STRICT_OPTIONS+="--disallow-incomplete-defs "
CUSTOM_STRICT_OPTIONS+="--check-untyped-defs "
CUSTOM_STRICT_OPTIONS+="--disallow-untyped-decorators "
CUSTOM_STRICT_OPTIONS+="--no-implicit-optional "
CUSTOM_STRICT_OPTIONS+="--warn-redundant-casts "
CUSTOM_STRICT_OPTIONS+="--warn-unused-ignores "
CUSTOM_STRICT_OPTIONS+="--warn-return-any "

mypy $CUSTOM_STRICT_OPTIONS `find ./bitcointx ./examples -path ./bitcointx/tests -prune -o -name "*.py" -print|sort`
mypy `find ./bitcointx/tests -name "*.py" -print|sort`
