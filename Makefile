obj-m += netfilter_checksni.o
netfilter_checksni-objs := /src/netfilter_checksni.o  ./src/common/common.o  

ccflags-y := -I$(src)/src/include


BUILD_DIR := $(PWD)/bin
BUILD_DIR_MAKEFILE := $(BUILD_DIR)/Makefile

all: $(BUILD_DIR_MAKEFILE)
	make -C /lib/modules/$(shell uname -r)/build M=$(BUILD_DIR) src=$(PWD) modules 

$(BUILD_DIR):
	mkdir -p "$@"

$(BUILD_DIR_MAKEFILE): $(BUILD_DIR)
	touch "$@"

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(BUILD_DIR) src=$(PWD) clean
	rm -rf $(BUILD_DIR)






 