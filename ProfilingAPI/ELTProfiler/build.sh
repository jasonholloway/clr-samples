#!/bin/sh

[ -z "${CORECLR_PATH:-}" ] && CORECLR_PATH=~/coreclr
[ -z "${BuildOS:-}"      ] && BuildOS=Linux
[ -z "${BuildArch:-}"    ] && BuildArch=x64
[ -z "${BuildType:-}"    ] && BuildType=Debug
[ -z "${Output:-}"       ] && Output=CorProfiler.so

printf '  CORECLR_PATH : %s\n' "$CORECLR_PATH"
printf '  BuildOS      : %s\n' "$BuildOS"
printf '  BuildArch    : %s\n' "$BuildArch"
printf '  BuildType    : %s\n' "$BuildType"

printf '  Building %s ... ' "$Output"


CXX_FLAGS="$CXX_FLAGS --no-undefined -Wno-invalid-noreturn -fPIC -fms-extensions -DHOST_64BIT -DBIT64 -DPAL_STDCPP_COMPAT -DPLATFORM_UNIX -std=c++11 -pthread"
INCLUDES="-I $CORECLR_PATH/src/pal/inc/rt -I $CORECLR_PATH/src/pal/prebuilt/inc -I $CORECLR_PATH/src/pal/inc -I $CORECLR_PATH/src/inc -I $CORECLR_PATH/bin/Product/$BuildOS.$BuildArch.$BuildType/inc"

clang++ -shared -g -O0 -fno-limit-debug-info -o $Output $CXX_FLAGS $INCLUDES ClassFactory.cpp CorProfiler.cpp dllmain.cpp asmhelpers/amd64/systemv/asmhelpers.S
# clang++ -shared -std=c++20 -g -O0 -fno-limit-debug-info -o $Output $CXX_FLAGS $INCLUDES ClassFactory.cpp CorProfiler.cpp dllmain.cpp asmhelpers/amd64/systemv/asmhelpers.S

printf 'Done.\n'

