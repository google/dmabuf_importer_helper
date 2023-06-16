#ifndef _DRIVERS_GOOGLE_DMA_BUF_IMPORT_HELPER_H_
#define _DRIVERS_GOOGLE_DMA_BUF_IMPORT_HELPER_H_

#include <linux/types.h>
#include <linux/ioctl.h>
#include <linux/uio.h>

#define HELPER_MAX_IOVECS_COUNT 64

struct import_helper_map {
	/* in */
	__u32 fd;
	__u32 dbdf[4];
	__u32 attach_handle;
	/* out */
	__u32 iovecs_count;
};
struct import_helper_get_iovecs {
	/* in */
	__u32 attach_handle;
        __u32 offset;
	/* out */
	__u32 num_valid_iovecs;
	struct iovec iovecs[HELPER_MAX_IOVECS_COUNT];
};

struct import_helper_unmap {
	/* in */
	__u32 attach_handle;
};

#define IMPORT_HELPER_MAP _IOC( \
                _IOC_NONE, 0, 1, \
                sizeof(struct import_helper_map))
#define IMPORT_HELPER_GET_IOVECS _IOC( \
                _IOC_NONE, 0, 2, \
                sizeof(struct import_helper_get_iovecs))
#define IMPORT_HELPER_UNMAP _IOC( \
                _IOC_NONE, 0, 3, \
                sizeof(struct import_helper_unmap))

#endif  // _DRIVERS_GOOGLE_DMA_BUF_IMPORT_HELPER_H_
