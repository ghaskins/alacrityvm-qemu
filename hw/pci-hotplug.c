/*
 * QEMU PCI hotplug support
 *
 * Copyright (c) 2004 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "hw.h"
#include "boards.h"
#include "pci.h"
#include "net.h"
#include "sysemu.h"
#include "pc.h"
#include "monitor.h"
#include "block_int.h"
#include "scsi-disk.h"
#include "virtio-blk.h"
#include "qemu-config.h"
#include "device-assignment.h"

#if defined(TARGET_I386)
static PCIDevice *qemu_pci_hot_add_nic(Monitor *mon,
                                       const char *devaddr,
                                       const char *opts_str)
{
    QemuOpts *opts;
    int ret;

    opts = qemu_opts_parse(&qemu_net_opts, opts_str ? opts_str : "", NULL);
    if (!opts) {
        monitor_printf(mon, "parsing network options '%s' failed\n",
                       opts_str ? opts_str : "");
        return NULL;
    }

    qemu_opt_set(opts, "type", "nic");

    ret = net_client_init(mon, opts, 0);
    if (ret < 0)
        return NULL;
    if (nd_table[ret].devaddr) {
        monitor_printf(mon, "Parameter addr not supported\n");
        return NULL;
    }
    return pci_nic_init(&nd_table[ret], "rtl8139", devaddr);
}

void drive_hot_add(Monitor *mon, const QDict *qdict)
{
    int dom, pci_bus;
    unsigned slot;
    int type, bus;
    PCIDevice *dev;
    DriveInfo *dinfo = NULL;
    const char *pci_addr = qdict_get_str(qdict, "pci_addr");
    const char *opts = qdict_get_str(qdict, "opts");
    BusState *scsibus;

    dinfo = add_init_drive(opts);
    if (!dinfo)
        goto err;
    if (dinfo->devaddr) {
        monitor_printf(mon, "Parameter addr not supported\n");
        goto err;
    }
    type = dinfo->type;
    bus = drive_get_max_bus (type);

    switch (type) {
    case IF_SCSI:
        if (pci_read_devaddr(mon, pci_addr, &dom, &pci_bus, &slot)) {
            goto err;
        }
        dev = pci_find_device(pci_bus, slot, 0);
        if (!dev) {
            monitor_printf(mon, "no pci device with address %s\n", pci_addr);
            goto err;
        }
        scsibus = QLIST_FIRST(&dev->qdev.child_bus);
        scsi_bus_legacy_add_drive(DO_UPCAST(SCSIBus, qbus, scsibus),
                                  dinfo, dinfo->unit);
        monitor_printf(mon, "OK bus %d, unit %d\n",
                       dinfo->bus,
                       dinfo->unit);
        break;
    case IF_NONE:
        monitor_printf(mon, "OK\n");
        break;
    default:
        monitor_printf(mon, "Can't hot-add drive to type %d\n", type);
        goto err;
    }
    return;

err:
    if (dinfo)
        drive_uninit(dinfo);
    return;
}

static PCIDevice *qemu_pci_hot_add_storage(Monitor *mon,
                                           const char *devaddr,
                                           const char *opts)
{
    PCIDevice *dev;
    DriveInfo *dinfo = NULL;
    int type = -1;
    char buf[128];
    PCIBus *bus;
    int devfn;

    if (get_param_value(buf, sizeof(buf), "if", opts)) {
        if (!strcmp(buf, "scsi"))
            type = IF_SCSI;
        else if (!strcmp(buf, "virtio")) {
            type = IF_VIRTIO;
        } else {
            monitor_printf(mon, "type %s not a hotpluggable PCI device.\n", buf);
            return NULL;
        }
    } else {
        monitor_printf(mon, "no if= specified\n");
        return NULL;
    }

    if (get_param_value(buf, sizeof(buf), "file", opts)) {
        dinfo = add_init_drive(opts);
        if (!dinfo)
            return NULL;
        if (dinfo->devaddr) {
            monitor_printf(mon, "Parameter addr not supported\n");
            return NULL;
        }
    } else {
        dinfo = NULL;
    }

    bus = pci_get_bus_devfn(&devfn, devaddr);
    if (!bus) {
        monitor_printf(mon, "Invalid PCI device address %s\n", devaddr);
        return NULL;
    }

    switch (type) {
    case IF_SCSI:
        dev = pci_create(bus, devfn, "lsi53c895a");
        break;
    case IF_VIRTIO:
        if (!dinfo) {
            monitor_printf(mon, "virtio requires a backing file/device.\n");
            return NULL;
        }
        dev = pci_create(bus, devfn, "virtio-blk-pci");
        qdev_prop_set_drive(&dev->qdev, "drive", dinfo);
        break;
    default:
        dev = NULL;
    }
    if (!dev || qdev_init(&dev->qdev) < 0)
        return NULL;
    return dev;
}

#ifdef CONFIG_KVM_DEVICE_ASSIGNMENT
static PCIDevice *qemu_pci_hot_assign_device(Monitor *mon,
                                             const char *devaddr,
                                             const char *opts_str)
{
    QemuOpts *opts;
    DeviceState *dev;

    opts = add_assigned_device(opts_str);
    if (opts == NULL) {
        monitor_printf(mon, "Error adding device; check syntax\n");
        return NULL;
    }
    dev = qdev_device_add(opts);
    return DO_UPCAST(PCIDevice, qdev, dev);
}
#endif /* CONFIG_KVM_DEVICE_ASSIGNMENT */

void pci_device_hot_add(Monitor *mon, const QDict *qdict)
{
    PCIDevice *dev = NULL;
    const char *pci_addr = qdict_get_str(qdict, "pci_addr");
    const char *type = qdict_get_str(qdict, "type");
    const char *opts = qdict_get_try_str(qdict, "opts");

    /* strip legacy tag */
    if (!strncmp(pci_addr, "pci_addr=", 9)) {
        pci_addr += 9;
    }

    if (!opts) {
        opts = "";
    }

    if (!strcmp(pci_addr, "auto"))
        pci_addr = NULL;

    if (strcmp(type, "nic") == 0)
        dev = qemu_pci_hot_add_nic(mon, pci_addr, opts);
    else if (strcmp(type, "storage") == 0)
        dev = qemu_pci_hot_add_storage(mon, pci_addr, opts);
#ifdef CONFIG_KVM_DEVICE_ASSIGNMENT
    else if (strcmp(type, "host") == 0)
        dev = qemu_pci_hot_assign_device(mon, pci_addr, opts);
#endif /* CONFIG_KVM_DEVICE_ASSIGNMENT */
    else
        monitor_printf(mon, "invalid type: %s\n", type);

    if (dev) {
        monitor_printf(mon, "OK domain %d, bus %d, slot %d, function %d\n",
                       0, pci_bus_num(dev->bus), PCI_SLOT(dev->devfn),
                       PCI_FUNC(dev->devfn));
    } else
        monitor_printf(mon, "failed to add %s\n", opts);
}
#endif

void pci_device_hot_remove(Monitor *mon, const char *pci_addr)
{
    PCIDevice *d;
    int dom, bus;
    unsigned slot;

    if (pci_read_devaddr(mon, pci_addr, &dom, &bus, &slot)) {
        return;
    }

    d = pci_find_device(bus, slot, 0);
    if (!d) {
        monitor_printf(mon, "slot %d empty\n", slot);
        return;
    }
    qdev_unplug(&d->qdev);
}

void do_pci_device_hot_remove(Monitor *mon, const QDict *qdict)
{
    pci_device_hot_remove(mon, qdict_get_str(qdict, "pci_addr"));
}

static int pci_match_fn(void *dev_private, void *arg)
{
    PCIDevice *dev = dev_private;
    PCIDevice *match = arg;

    return (dev == match);
}

/*
 * OS has executed _EJ0 method, we now can remove the device
 */
void pci_device_hot_remove_success(PCIDevice *d)
{
    int class_code;

    class_code = d->config_read(d, PCI_CLASS_DEVICE+1, 1);

    switch(class_code) {
    case PCI_BASE_CLASS_NETWORK:
        destroy_nic(pci_match_fn, d);
        break;
    }
}
