insmod netfilter_checksni.ko
dmesg | grep netfilter_checksni

rmmod netfilter_checksni
dmesg | grep netfilter_checksni
