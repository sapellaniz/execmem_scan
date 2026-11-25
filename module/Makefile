obj-m := execmem_scan.o

execmem_scan-y := main.o \
		  common.o \
                  vmap_enum.o \
                  module_enum.o \
                  ftrace_enum.o \
                  es_classifier.o \
		  es_reporter.o
                  #free.o

ccflags-y += -I$(src)/include

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
