obj-m += import-helper.o

all:
	make -C ${KBUILD_PATH} M=$(PWD) modules

clean:
	make -C ${KBUILD_PATH} M=$(PWD) clean
