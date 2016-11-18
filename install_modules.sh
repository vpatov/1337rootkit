#!/bin/sh

make clean
make
dmesg -c
rmmod -f rootkit.ko
lsmod | grep rootkit
insmod rootkit.ko
lsmod | grep rootkit
