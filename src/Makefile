MAKE?=make

obj-m += import-helper.o

all:
	${MAKE} -C ${KBUILD_PATH} M=$(PWD)/src/ modules

clean:
	${MAKE} -C ${KBUILD_PATH} M=$(PWD)/src/ clean
