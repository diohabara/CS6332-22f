#!/usr/bin/env bash
make -e obj-intel64/inscount.so
pin -t obj-intel64/inscount.so -- /bin/ls
cat inscount.out