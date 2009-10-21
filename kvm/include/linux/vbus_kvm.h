/*
 * Copyright 2009 Novell.  All Rights Reserved.
 *
 * Virtual-Bus connector for KVM
 *
 * Author:
 *      Gregory Haskins <ghaskins@novell.com>
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef _LINUX_VBUS_KVM_H
#define _LINUX_VBUS_KVM_H

#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/vbus_pci.h>

#define VBUS_KVM_ABI_MAGIC 0x34f0ab23
#define VBUS_KVM_ABI_VERSION 2

struct vbus_kvm_negotiate {
	__u32 magic;
	__u32 version;
	__u64 capabilities;
};

struct vbus_kvm_open {
	__u32 flags;
	__s32 vmfd;
	__u8  pad[56];
};

struct vbus_kvm_eventq_assign {
	__u32 flags;
	__u32 queue;
	__s32 fd;
	__u32 count;
	__u64 ring;
	__u64 data;
	__u8  pad[32];
};

#define VBUS_KVM_MAGIC 'K'

#define VBUS_KVM_NEGOTIATE \
  _IOWR(VBUS_KVM_MAGIC, 0x00, struct vbus_kvm_negotiate)
#define VBUS_KVM_OPEN \
  _IOW(VBUS_KVM_MAGIC, 0x01, struct vbus_kvm_open)
#define VBUS_KVM_SIGADDR_ASSIGN \
  _IOW(VBUS_KVM_MAGIC, 0x02, __u32)
#define VBUS_KVM_EVENTQ_ASSIGN \
  _IOW(VBUS_KVM_MAGIC, 0x03, struct vbus_kvm_eventq_assign)
#define VBUS_KVM_READY\
  _IO(VBUS_KVM_MAGIC, 0x04)
#define VBUS_KVM_SLOWCALL \
  _IOW(VBUS_KVM_MAGIC, 0x05, struct vbus_pci_call_desc)
#define VBUS_KVM_FCC_ASSIGN \
  _IOW(VBUS_KVM_MAGIC, 0x06, struct vbus_pci_call_desc)
#define VBUS_KVM_FCC_DEASSIGN \
  _IOW(VBUS_KVM_MAGIC, 0x07, __u32)

#endif /* _LINUX_VBUS_KVM_H */
