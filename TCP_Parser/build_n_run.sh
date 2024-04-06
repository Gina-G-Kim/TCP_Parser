#!/bin/bash

cmake -S . -B build -DCMAKE_PREFIX_PATH=../pcapplusplus-23.09-ubuntu-22.04-gcc-11.2.0-x86_64

cmake --build build

./TCP_Capture > result.txt
