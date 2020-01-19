#!/bin/bash

cd algo/cuda
make
cd ../..

./autogen.sh
./configure CFLAGS="-O3"

make


