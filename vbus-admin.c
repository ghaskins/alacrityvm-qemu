/*
 * Add support for directly administering a virtual-bus container
 * from within QEMU
 *
 * Copyright (c) 2009, Novell Inc, Gregory Haskins <ghaskins@novell.com>
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/io.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include "vbus-admin.h"

/* ---- kernel interface --------*/

#include <linux/ioctl.h>
#include <linux/types.h>

#define VBUS_ADMIN_MAGIC 0xdf39ab56
#define VBUS_ADMIN_VERSION 1

struct vbus_admin_negotiate {
	__u32 magic;
	__u32 version;
	__u64 capabilities;
};

struct vbus_admin_userbuf {
	__u64 ptr;
	__u32 len;
};

struct vbus_admin_dev_create {
	__u32                     flags;     /* in */
	__u64                     type;      /* char* in */
	struct vbus_admin_userbuf name;      /* char* out */
	__u8                      pad[36];
};

#define VBUS_ADMIN_IOCTL_MAGIC 'V'

#define VBUS_ADMIN_NEGOTIATE \
  _IOWR(VBUS_ADMIN_IOCTL_MAGIC, 0x00, struct vbus_admin_negotiate)
#define VBUS_ADMIN_DEV_CREATE \
  _IOW(VBUS_ADMIN_IOCTL_MAGIC, 0x01, struct vbus_admin_dev_create)

/* ---- kernel interface --------*/

static int admin_fd = -1;

static void
vbus_admin_init(void)
{
       struct vbus_admin_negotiate negotiate = {
               .magic        = VBUS_ADMIN_MAGIC,
               .version      = VBUS_ADMIN_VERSION,
               .capabilities = 0, /* no advanced features (yet) */
       };
       int ret;

       admin_fd = open("/dev/vbus-admin", 0);
       if (admin_fd < 0)
               return;

       ret = ioctl(admin_fd, VBUS_ADMIN_NEGOTIATE, &negotiate);
       if (ret < 0) {
               perror("vbus-admin present but failed to negotiate");
               return;
       }
}

int
vbus_device_attr_set(const char *dev, const char *attr, const char *val)
{
	char path[1024];
	int ret;
	int fd;
	int len = strlen(val);

	snprintf(path, sizeof(path), "/sys/vbus/devices/%s/%s", dev, attr);

	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -errno;

	ret = write(fd, val, len);
	
	close(fd);

	if (ret < 0)
		return -errno;

	if (ret != len)
		return -EFAULT;

	return 0;
}

int
vbus_device_attr_get(const char *dev, const char *attr,
		     char *val, size_t len)
{
	char path[1024];
	int ret;
	int fd;

	snprintf(path, sizeof(path), "/sys/vbus/devices/%s/%s", dev, attr);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;

	ret = read(fd, val, len);
	
	close(fd);

	if (ret < 0)
		return -errno;

	return ret;
}

int
vbus_device_create(const char *type, char *name, size_t namelen)
{
       struct vbus_admin_dev_create params = {
               .type = (__u64)type,
               .name = {
                       .ptr = (__u64)name,
                       .len = namelen,
               },
       };
       int ret;

       if (admin_fd < 0)
	 vbus_admin_init();

       if (admin_fd < 0)
	 return -ENOSYS;

       ret = ioctl(admin_fd, VBUS_ADMIN_DEV_CREATE, &params);
       if (ret < 0)
               return -errno;

       return 0;
}

