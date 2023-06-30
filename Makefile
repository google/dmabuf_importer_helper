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

tarball:
	sudo cp -R . /usr/src/import_helper-1.0
	sudo dkms remove -m import_helper -v 1.0 || true
	sudo dkms add -m import_helper -v 1.0 || true
	sudo dkms mktarball -m import_helper -v 1.0 --source-only

image: tarball
	$(eval TEMP_DIR := $(shell mktemp -d -t import_helper_XXXX))
	dd if=/dev/zero of="${TEMP_DIR}/import_helper.img" bs=4K count=64K
	sudo mkfs.ext4 "${TEMP_DIR}/import_helper.img"
	mkdir -p "${TEMP_DIR}/mnt"
	sudo mount -o loop "${TEMP_DIR}/import_helper.img" "${TEMP_DIR}/mnt"
	#sudo tar cvzf ${TEMP_DIR}/mnt/import_helper.tar.gz .
	sudo cp /var/lib/dkms/import_helper/1.0/tarball//import_helper-1.0-source-only.dkms.tar.gz "${TEMP_DIR}/mnt/"
	sudo umount "${TEMP_DIR}/mnt"
	sudo cp  "${TEMP_DIR}/import_helper.img" import_helper.img
	rm -R ${TEMP_DIR}
	echo "Image file import_helper.img created."

clean:
	make ${KBUILD_PATH} -C src/ clean
