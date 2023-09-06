# for test
dmesg -C
rmmod fw
insmod fw.ko
lsmod | grep "fw"
dmesg