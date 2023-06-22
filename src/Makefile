obj-m += import-helper.o

all:
	make -C ${KBUILD_PATH} M=$(PWD)/src/ modules

clean:
	make -C ${KBUILD_PATH} M=$(PWD)/src/ clean
