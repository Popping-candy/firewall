# for test
make clean
make
dmesg -C
sudo insmod fw.ko
lsmod | grep "fw"
dmesg