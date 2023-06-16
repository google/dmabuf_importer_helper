#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/dma-buf.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/pci.h>
#include <linux/uaccess.h>
#include "import-helper.h"

struct dmabuf_import {
	__u32 attach_handle;
	struct dma_buf *dbuf;
	struct dma_buf_attachment *dbuf_attach;
	struct sg_table *sgt;
	struct pci_dev *pdev;
	struct list_head node;
};

struct import_helper_context {
	struct list_head dmabufs;
	struct mutex lock;
};

static struct pci_dev *get_pci_dev(int domain,
				   int bus,
				   int device,
				   int func)
{
	struct pci_bus *b;
	struct pci_dev *pdev;

	b = pci_find_bus(domain, bus);
	if (!b)
		return NULL;
	pdev = pci_get_slot(b, PCI_DEVFN(device, func));
	if (!pdev)
		return NULL;
	return pdev;
}

static void release_dmabuf_import(struct dmabuf_import *imp)
{
	if (imp->sgt)
		(void) dma_buf_unmap_attachment(
					imp->dbuf_attach,
					imp->sgt,
					DMA_BIDIRECTIONAL);

	if (imp->dbuf_attach)
		(void)dma_buf_detach(imp->dbuf, imp->dbuf_attach);
	dma_buf_put(imp->dbuf);
	pci_dev_put(imp->pdev);
}

static struct dmabuf_import* get_dmabuf_import_locked(
				struct import_helper_context *ctx,
				__u32 attach_handle)
{
	struct dmabuf_import *imp;

	list_for_each_entry(imp, &ctx->dmabufs, node) {
		if (imp->attach_handle == attach_handle)
			return imp;
	}
	return NULL;
}

static int import_helper_map(struct import_helper_context *ctx,
			     unsigned long arg)
{
	int ret;
	struct pci_dev *pdev;
	struct dma_buf *dbuf;
	struct import_helper_map hmap;
	struct dmabuf_import *imp;

        ret = copy_from_user(&hmap,
                             (void*)arg, sizeof(hmap));
	if (ret < 0) {
		pr_err("Failed to copy user args: %d", ret);
		return -EFAULT;
        }

	/* domain, bus, device, function */
	pdev = get_pci_dev(hmap.dbdf[0], hmap.dbdf[1],
			   hmap.dbdf[2], hmap.dbdf[3]);
	if (!pdev) {
		pr_err("Failed to get pci device");
		return -EINVAL;
	}

	imp = kzalloc(sizeof(*imp), GFP_KERNEL);
	if (!imp) {
		pr_err("Failed to alloc memory for mapping");
		ret = -ENOMEM;
		goto failed_pci_dev_put;
	}

	dbuf = dma_buf_get(hmap.fd);
	if (IS_ERR(dbuf)) {
		pr_err("Failed to get dmabuf: %li", PTR_ERR(dbuf));
		ret = PTR_ERR(dbuf);
		goto failed_get_dma_buf;
	}
	imp->dbuf = dbuf;

	imp->dbuf_attach = dma_buf_attach(dbuf, &pdev->dev);
	if (IS_ERR(imp->dbuf_attach)) {
		ret = PTR_ERR(imp->dbuf_attach);
		pr_err("Failed to attach dmabuf: %d", ret);
		imp->dbuf_attach = NULL;
		goto failed_import_cleanup;
	}

	imp->sgt = dma_buf_map_attachment(imp->dbuf_attach, DMA_BIDIRECTIONAL);
	if (IS_ERR(imp->sgt)) {
		ret = PTR_ERR(imp->sgt);
		pr_err("Failed to map attachment: %d", ret);
		imp->sgt = NULL;
		goto failed_import_cleanup;
	}

	imp->pdev = pdev;
	imp->attach_handle = hmap.attach_handle;
	hmap.iovecs_count = imp->sgt->nents;

	if (copy_to_user((void*)arg, &hmap, sizeof(hmap))) {
		ret = -EFAULT;
		pr_err("Failed to copy output to user");
		goto failed_import_cleanup;
	}

	mutex_lock(&ctx->lock);
	list_add(&imp->node, &ctx->dmabufs);
	mutex_unlock(&ctx->lock);

	return 0;
failed_import_cleanup:
	release_dmabuf_import(imp);
failed_get_dma_buf:
	kfree(imp);
failed_pci_dev_put:
	pci_dev_put(pdev);

	return ret;
}

static int import_helper_unmap(struct import_helper_context *ctx,
			     unsigned long arg)
{
	int ret;
        struct import_helper_unmap param;
        struct dmabuf_import *imp;

        ret = copy_from_user(&param, (void*)arg, sizeof(param));
        if (ret < 0) {
		pr_err("Failed to copy user args");
                return -EFAULT;
	}

        mutex_lock(&ctx->lock);
        imp = get_dmabuf_import_locked(ctx, param.attach_handle);
        if (!imp) {
                ret = -EINVAL;
		pr_err("Invalid attach handle provided: %d",
		       param.attach_handle);
                goto out;
        }

	list_del(&imp->node);
	release_dmabuf_import(imp);
        kfree(imp);
        ret = 0;
out:
        mutex_unlock(&ctx->lock);
        return ret;
}

static int import_helper_get_iovecs(struct import_helper_context *ctx,
			     unsigned long arg)
{
	int ret = 0;
        unsigned int i;
        struct import_helper_get_iovecs get_iovecs;
        struct dmabuf_import *imp;
        struct scatterlist *sg;

        ret = copy_from_user(&get_iovecs, (void*)arg, sizeof(get_iovecs));
        if (ret < 0) {
                pr_err("Failed to copy ioctl arg");
                return -EFAULT;
        }

	mutex_lock(&ctx->lock);
	imp = get_dmabuf_import_locked(ctx, get_iovecs.attach_handle);
	if (!imp) {
		ret = -EINVAL;
		pr_err("Invalid attach handle provided: %d",
                       get_iovecs.attach_handle);
		goto out;
	}

	if (imp->sgt->nents <= get_iovecs.offset) {
		ret = -EINVAL;
		pr_err("Invalid offset provided: %u", get_iovecs.offset);
		goto out;
	}

	i = 0;
	get_iovecs.num_valid_iovecs = 0;
	for_each_sg(imp->sgt->sgl, sg, imp->sgt->nents, i) {
		if (i < get_iovecs.offset)
			continue;

		get_iovecs.iovecs[get_iovecs.num_valid_iovecs].iov_base
				= (void*) sg_dma_address(sg);
		get_iovecs.iovecs[get_iovecs.num_valid_iovecs++].iov_len
				= sg_dma_len(sg);
		if (get_iovecs.num_valid_iovecs >= HELPER_MAX_IOVECS_COUNT)
			break;
	}

	if (copy_to_user((void*)arg, &get_iovecs, sizeof(get_iovecs))) {
		pr_err("Failed to copy output to user");
                ret = -EFAULT;
	}
out:
	mutex_unlock(&ctx->lock);
	return ret;
}

static long import_helper_ioctl(struct file *filep,
			  unsigned int ioctl,
			  unsigned long arg)
{
	long ret;
	struct import_helper_context *ctx;

	ctx = filep->private_data;
	if (!ctx) {
		pr_err("File doesn't have import context");
		return -EINVAL;
	}

	switch (ioctl) {
		case IMPORT_HELPER_MAP:
			ret = import_helper_map(ctx, arg);
			break;
		case IMPORT_HELPER_UNMAP:
			ret = import_helper_unmap(ctx, arg);
			break;
		case IMPORT_HELPER_GET_IOVECS:
			ret = import_helper_get_iovecs(ctx, arg);
                        break;
		default:
			ret = -ENOTTY;
	}

	return ret;
}

static int import_helper_open(struct inode *inode, struct file *filep)
{
	struct import_helper_context *ctx;

	ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	INIT_LIST_HEAD(&ctx->dmabufs);
	mutex_init(&ctx->lock);

	filep->private_data = ctx;
	return 0;
}

static int import_helper_release(struct inode *inode, struct file *filep)
{
	struct import_helper_context *ctx;
	struct dmabuf_import *imp, *imp2;

	ctx = filep->private_data;
	if (!ctx)
		return -EINVAL;

	filep->private_data = NULL;
	mutex_lock(&ctx->lock);
	list_for_each_entry_safe(imp, imp2, &ctx->dmabufs, node) {
		list_del(&imp->node);
		release_dmabuf_import(imp);
		kfree(imp);
	}
	mutex_unlock(&ctx->lock);
	return 0;
}

static const struct file_operations import_helper_fops = {
	.owner = THIS_MODULE,
        .open = import_helper_open,
	.release = import_helper_release,
	.unlocked_ioctl = import_helper_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = import_helper_ioctl,
#endif
};

static struct miscdevice import_helper_misc_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "dmabuf_import_helper",
	.fops = &import_helper_fops,
};

int import_helper_dev_init(void)
{
	int ret;

	ret = misc_register(&import_helper_misc_dev);
	if (ret < 0) {
		pr_err("Cannot create import helper misc device: %d\n", ret);
		return ret;
	}
	return 0;
}

void import_helper_dev_exit(void)
{
	misc_deregister(&import_helper_misc_dev);
}

module_init(import_helper_dev_init);
module_exit(import_helper_dev_exit);

MODULE_AUTHOR("Samiullah Khawaja <skhawaja@google.com>");
MODULE_LICENSE("GPL");
