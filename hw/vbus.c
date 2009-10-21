/*
 * Add in-kernel "vbus" device support by surfacing a PCI->OTHER bridge
 *
 * Copyright (c) 2009, Novell Inc, Gregory Haskins <ghaskins@novell.com>
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/io.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/vbus_kvm.h>
#include "qemu-kvm.h"
#include "hw.h"
#include "pci.h"

#include "vbus.h"

#define  PCI_CAP_ID_MSI	0x05

#define PCI_MSI_FLAGS		2	/* Various flags */
#define  PCI_MSI_FLAGS_64BIT	0x80	/* 64-bit addresses allowed */
#define  PCI_MSI_FLAGS_QSIZE	0x70	/* Message queue size configured */
#define  PCI_MSI_FLAGS_QMASK	0x0e	/* Maximum queue size available */
#define  PCI_MSI_FLAGS_ENABLE	0x01	/* MSI feature enabled */
#define  PCI_MSI_FLAGS_MASKBIT	0x100	/* 64-bit mask bits allowed */
#define PCI_MSI_RFU		3	/* Rest of capability flags */
#define PCI_MSI_ADDRESS_LO	4	/* Lower 32 bits */
#define PCI_MSI_ADDRESS_HI	8	/* Upper 32 bits (if PCI_MSI_FLAGS_64BIT set) */
#define PCI_MSI_DATA_32		8	/* 16 bits of data for 32-bit devices */
#define PCI_MSI_DATA_64		12	/* 16 bits of data for 64-bit devices */
#define PCI_MSI_MASK_BIT	16	/* Mask bits register */

#define EVENTQ_COUNT 8

struct Priv {
	PCIDevice                            dev;
	int                                  vbusfd;
	struct {
		struct {
			struct kvm_irq_routing_entry routing;
			int                          irqfd;
			int                          ioeventfd;
		} irq[EVENTQ_COUNT];
		int                                  count;
		int                                  enabled:1;
	} interrupts;
	struct {
		int                          key;
		uint32_t                     addr;
	} mmio;
	struct vbus_pci_regs                 registers;
	uint32_t                             signals;
	uint32_t                             hcver;
};

static struct Priv *to_priv(PCIDevice *dev)
{
	return (struct Priv*)dev;
}

static void
vbus_pci_mmio_map(PCIDevice *pci_dev, int region_num,
		  uint32_t addr, uint32_t size, int type)
{
	struct Priv *priv = to_priv(pci_dev);

	cpu_register_physical_memory(addr, size, priv->mmio.key);
	priv->mmio.addr = addr;
}

static void
vbus_pci_pio_map(PCIDevice *pci_dev, int region_num,
		  uint32_t addr, uint32_t size, int type)
{
	struct Priv *priv = to_priv(pci_dev);
	int ret;

	if (!priv->signals) {
		priv->signals = addr;
		ret = ioctl(priv->vbusfd, VBUS_KVM_SIGADDR_ASSIGN, &addr);

		if (ret < 0)
			perror("failed to assign signal address");
	}
}

static int
vbus_pci_eventq_assign(struct Priv *priv, int idx,
		       uint32_t count, uint64_t ringp, uint64_t datap)
{
	PCIDevice *dev = &priv->dev;
	struct vbus_kvm_eventq_assign assign;
	struct kvm_irq_routing_entry *irq;
	unsigned int pos = dev->cap.start;
	uint32_t addr;
	uint16_t data;
	int irqfd = 0, ioeventfd = 0;
	int ret;

	irq = &priv->interrupts.irq[idx].routing;

	addr = *(uint32_t *)&dev->config[pos + PCI_MSI_ADDRESS_LO];
	data = *(uint16_t *)&dev->config[pos + PCI_MSI_DATA_32];
	data += idx;

	irq->u.msi.address_lo = addr;
	irq->u.msi.address_hi = 0;
	irq->u.msi.data       = data;

	irq->type = KVM_IRQ_ROUTING_MSI;

	ret = kvm_get_irq_route_gsi(kvm_context);
	if (ret < 0) {
		perror("vbus: kvm_get_irq_route_gsi");
		return ret;
	}

	irq->gsi = ret;

	ret = kvm_add_routing_entry(kvm_context, irq);
	if (ret < 0) {
		perror("vbus: kvm_add_routing_entry");
		return ret;
	}

	ret = kvm_commit_irq_routes(kvm_context);
	if (ret < 0) {
		perror("vbus: kvm_commit_irq_routes");
		return ret;
	}

	ret = kvm_irqfd(kvm_context, irq->gsi, 0);
	if (ret < 0) {
		perror("vbus: failed to create irqfd");
		return ret;
	}

	irqfd = ret;

	assign.flags = 0;
	assign.queue = idx;
	assign.fd    = irqfd;
	assign.count = count;
	assign.ring  = ringp;
	assign.data  = datap;

	ret = ioctl(priv->vbusfd, VBUS_KVM_EVENTQ_ASSIGN, &assign);
	if (ret < 0) {
		perror("vbus: failed to eventq-assign");
		goto cleanup;
	}

	ioeventfd = ret;

	ret = kvm_assign_ioeventfd(kvm_context,
				   priv->signals,
				   sizeof(__u32),
				   ioeventfd, idx,
				   IOEVENTFD_FLAG_DATAMATCH |
				   IOEVENTFD_FLAG_PIO);
	if (ret < 0) {
		perror("vbus: failed to assign ioeventfd");
		goto cleanup;
	}

	priv->interrupts.irq[idx].ioeventfd = ioeventfd;
	priv->interrupts.irq[idx].irqfd     = irqfd;

	return 0;

cleanup:
	if (irqfd)
		close(irqfd);

	if (ioeventfd)
		close(ioeventfd);

	return ret;
}

static int
bridgecall_negotiate(struct Priv *priv)
{
	struct vbus_pci_call_desc *desc = &priv->registers.bridgecall;
	struct vbus_pci_bridge_negotiate params;

	if (desc->len != sizeof(params))
		return -EINVAL;

	cpu_physical_memory_read(desc->datap, (void *)&params, sizeof(params));

	if (params.magic != VBUS_PCI_ABI_MAGIC)
		return -EINVAL;

	if (params.version != priv->hcver)
		return -EINVAL;

	params.capabilities = 0;

	cpu_physical_memory_write(desc->datap, (void *)&params, sizeof(params));

	return 0;
}

static int
bridgecall_qreg(struct Priv *priv)
{
	struct vbus_pci_call_desc *desc = &priv->registers.bridgecall;
	struct vbus_pci_busreg params;
	int i;
	int ret;

	if (desc->len != sizeof(params))
		return -EINVAL;

	cpu_physical_memory_read(desc->datap, (void *)&params, sizeof(params));

	if (!priv->interrupts.enabled || params.count != priv->interrupts.count)
		return -EINVAL;

	for (i = 0; i < priv->interrupts.count; i++) {
		struct vbus_pci_eventqreg *qreg = &params.eventq[i];

		ret = vbus_pci_eventq_assign(priv, i,
					     qreg->count, qreg->ring, qreg->data);
		if (ret < 0)
			return ret;
	}

	ioctl(priv->vbusfd, VBUS_KVM_READY, NULL);

	return 0;
}

static int
bridgecall_fwd_call(struct Priv *priv, int nr)
{
	struct vbus_pci_call_desc *desc = &priv->registers.bridgecall;
	struct vbus_pci_call_desc params;
	int ret;

	if (desc->len != sizeof(params))
		return -EINVAL;

	cpu_physical_memory_read(desc->datap, (void *)&params, sizeof(params));

	ret = ioctl(priv->vbusfd, nr, &params);
	if (ret < 0)
		return -errno;

	return ret;
}

static uint32_t
vbus_pci_mmio_read_null(void *opaque, target_phys_addr_t addr)
{
        return 0;
}

static uint32_t
vbus_pci_mmio_readl(void *opaque, target_phys_addr_t addr)
{
	struct Priv *priv = (struct Priv *)opaque;
	struct vbus_pci_call_desc *desc = &priv->registers.bridgecall;

	switch (desc->vector) {
	case VBUS_PCI_BRIDGE_NEGOTIATE:
		return bridgecall_negotiate(priv);
	case VBUS_PCI_BRIDGE_QREG:
		return bridgecall_qreg(priv);
	case VBUS_PCI_BRIDGE_SLOWCALL:
		return bridgecall_fwd_call(priv, VBUS_KVM_SLOWCALL);
	case VBUS_PCI_BRIDGE_FASTCALL_ADD:
		return bridgecall_fwd_call(priv, VBUS_KVM_FCC_ASSIGN);
	default:
		return -EINVAL;
	}
}

static void
vbus_pci_mmio_write_null(void *opaque, target_phys_addr_t addr, uint32_t value)
{
}

static void
vbus_pci_mmio_writel(void *opaque, target_phys_addr_t addr, uint32_t value)
{
	struct Priv *priv = (struct Priv *)opaque;
	char *buf = (char *)&priv->registers;

	if (addr > sizeof(priv->registers) - sizeof(uint32_t))
		return;

	memcpy(&buf[addr], &value, sizeof(value));
}

static CPUReadMemoryFunc *vbus_pci_read[] = {
       &vbus_pci_mmio_read_null,
       &vbus_pci_mmio_read_null,
       &vbus_pci_mmio_readl,
};

static CPUWriteMemoryFunc *vbus_pci_write[] = {
       &vbus_pci_mmio_write_null,
       &vbus_pci_mmio_write_null,
       &vbus_pci_mmio_writel,
};

static int
vbus_pci_cap_init(PCIDevice *dev)
{
	int offset = dev->cap.start;

	dev->cap.length = 0;

	memset(&dev->config[offset], 0, PCI_CAPABILITY_CONFIG_MSI_LENGTH);
	dev->config[offset] = PCI_CAP_ID_MSI;
	dev->config[offset+PCI_MSI_FLAGS] = 0x06; /* request 8 vectors */
	dev->cap.length += PCI_CAPABILITY_CONFIG_MSI_LENGTH;

	return 0;
}

static void
vbus_pci_cap_write_config(PCIDevice *dev, uint32_t addr, uint32_t val, int len)
{
	struct Priv       *priv = to_priv(dev);
	unsigned int       pos = dev->cap.start;
	unsigned int       ctrl = pos + PCI_MSI_FLAGS;

	pci_default_cap_write_config(dev, addr, val, len);

	/* Check if this is not a write to the control register. */
	if (!(addr <= ctrl && (addr + len) > ctrl))
		return;

	if (!priv->interrupts.enabled && val & 1) {
		int total;
		uint8_t flags = dev->config[pos+PCI_MSI_FLAGS];

		total = 1 << ((flags & PCI_MSI_FLAGS_QSIZE) >> 4);

		if (total > EVENTQ_COUNT)
			total = EVENTQ_COUNT;

		priv->interrupts.count   = total;
		priv->interrupts.enabled = 1;
	}
}

void
pci_vbus_init(PCIBus *bus)
{
	struct Priv *priv;
	PCIDevice *dev;
	uint8_t *config;
	int fd;
	int ret;
	struct vbus_kvm_negotiate negotiate = {
		.magic        = VBUS_KVM_ABI_MAGIC,
		.version      = VBUS_KVM_ABI_VERSION,
		.capabilities = 0, /* no advanced features (yet) */
	};
	struct vbus_kvm_open openargs = {
		.vmfd         = kvm_state->vmfd,
	};

	if (!kvm_check_extension(kvm_state, KVM_CAP_IRQFD)
	    || !kvm_check_extension(kvm_state, KVM_CAP_IOEVENTFD))
		return;

	fd = open("/dev/vbus-kvm", 0);
	if (fd < 0)
		return;

	ret = ioctl(fd, VBUS_KVM_NEGOTIATE, &negotiate);
	if (ret < 0) {
		perror("vbus present but failed to negotiate");
		goto out;
	}

	dev = pci_register_device(bus, "vbus", sizeof(*priv),
				  -1, NULL, NULL);
	if (!dev) {
		perror("vbus present but PCI allocation failed");
		goto out;
	}

	config = dev->config;
	pci_config_set_vendor_id(config, PCI_VENDOR_ID_NOVELL);
	pci_config_set_device_id(config, PCI_DEVICE_ID_VIRTUAL_BUS);
	pci_config_set_class(config, PCI_CLASS_BRIDGE_OTHER);

	config[0x08] = VBUS_PCI_ABI_VERSION;

	pci_enable_capability_support(dev, 0,
				      NULL,
				      vbus_pci_cap_write_config,
				      vbus_pci_cap_init);

	priv = to_priv(dev);

	memset(&priv->interrupts, 0, sizeof(priv->interrupts));
	memset(&priv->mmio, 0, sizeof(priv->mmio));
	memset(&priv->registers, 0, sizeof(priv->registers));

	priv->signals = 0;
	priv->vbusfd = fd;
	priv->mmio.key = cpu_register_io_memory(vbus_pci_read, vbus_pci_write,
						priv);

	ret = ioctl(fd, VBUS_KVM_OPEN, &openargs);
	if (ret < 0) {
		perror("vbus present but failed to open");
		goto out;
	}

	priv->hcver = ret;

	pci_register_bar(dev, 0, sizeof(struct vbus_pci_regs),
			 PCI_ADDRESS_SPACE_MEM, vbus_pci_mmio_map);
	pci_register_bar(dev, 1, sizeof(struct vbus_pci_signals),
			 PCI_ADDRESS_SPACE_IO, vbus_pci_pio_map);

	return;
out:
	close(fd);
}
