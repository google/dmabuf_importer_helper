all:
	make ${KBUILD_PATH} -C src/ all

dkms:
	sudo cp -R . /usr/src/import_helper-1.0
	sudo dkms remove -m import_helper -v 1.0 || true
	sudo dkms add -m import_helper -v 1.0 || true
	sudo dkms build -m import_helper -v 1.0
	sudo dkms install -m import_helper -v 1.0

dkms_clean:
	sudo dkms remove -m import_helper -v 1.0 || true

clean:
	make ${KBUILD_PATH} -C src/ clean
