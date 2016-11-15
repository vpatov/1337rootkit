#!/bin/sh

make clean
make
dmesg -c
rmmod rootkit.ko
lsmod | grep rootkit
insmod rootkit.ko
lsmod | grep rootkit
