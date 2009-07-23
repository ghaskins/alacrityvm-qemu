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

#define REG_OFFSET_DATA   offsetof(struct vbus_pci_regs, hypercall.data)
#define REG_OFFSET_RESULT offsetof(struct vbus_pci_regs, hypercall.result)

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
		int                                  enabled:1;
	} interrupts;
	struct {
		int                          key;
		uint32_t                     addr;
	} mmio;
	struct vbus_pci_regs                 registers;
	uint32_t                             pioaddr;
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

	priv->pioaddr = addr;
}

static int
hc_generic(struct Priv *priv)
{
	struct vbus_pci_hypercall *hc = &priv->registers.hypercall.data;
	int ret;

	ret = ioctl(priv->vbusfd, VBUS_KVM_HYPERCALL, hc);
	if (ret < 0)
		return -errno;

	return ret;
}

static int
hc_devshm(struct Priv *priv)
{
	struct vbus_pci_hypercall *hc = &priv->registers.hypercall.data;
	int ret;
	int fd;

	fd = ioctl(priv->vbusfd, VBUS_KVM_HYPERCALL, hc);
	if (fd < 0)
		return -errno;

	if (fd > 0) {
		int handle = fd + EVENTQ_COUNT;

		ret = kvm_assign_ioeventfd(kvm_context,
					   priv->pioaddr,
					   sizeof(__u32),
					   fd, handle,
					   IOEVENTFD_FLAG_DATAMATCH |
					   IOEVENTFD_FLAG_PIO);
		if (ret < 0) {
			printf("VBUS: could not register ioeventfd: %d\n",
			       ret);
			goto out;
		}
		
		return handle;
	}

	return 0;

out:
	close(fd);
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
	uint32_t ret = 0;

	if (addr == REG_OFFSET_RESULT) {
		struct vbus_pci_hypercall *hc;

		hc = &priv->registers.hypercall.data;

		switch (hc->vector) {
		case VBUS_PCI_HC_DEVSHM:
			ret = hc_devshm(priv);
			break;
		default:
			ret = hc_generic(priv);
			break;
		}
	}

        return ret;
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
	struct Priv *priv = to_priv(dev);
	unsigned int       pos = dev->cap.start;
	unsigned int       ctrl = pos + PCI_MSI_FLAGS;

	pci_default_cap_write_config(dev, addr, val, len);
	
	/* Check if this is not a write to the control register. */
	if (!(addr <= ctrl && (addr + len) > ctrl))
		return;

	/*
	 * We only get here if this is a write to the control register,
	 * but we only emulate the PIO side-effects if this is the first
	 * time we have seen an MSI_ENABLE operation.  I.e. all MSI_DISABLE
	 * and subsequent MSI_ENABLE operations are ignored
	 */ 
	if (!priv->interrupts.enabled && val & 1) {
		int i, total;
		uint8_t flags = dev->config[pos+PCI_MSI_FLAGS];

		total = 1 << ((flags & PCI_MSI_FLAGS_QSIZE) >> 4);

		if (total > EVENTQ_COUNT)
			total = EVENTQ_COUNT;

		/* We need to register a GSI for each vector returned */
		for (i = 0; i < total; i++) {
			struct kvm_irq_routing_entry *irq;
			uint32_t addr;
			uint16_t data;
			int irqfd = 0, ioeventfd = 0;
			int ret;
			struct vbus_kvm_eventq_assign assign;

			irq = &priv->interrupts.irq[i].routing;

			addr = *(uint32_t *)&dev->config[pos +
							 PCI_MSI_ADDRESS_LO];

			data = *(uint16_t *)&dev->config[pos + PCI_MSI_DATA_32];
			data += i;

			irq->u.msi.address_lo = addr;
			irq->u.msi.address_hi = 0;
			irq->u.msi.data       = data;

			irq->type = KVM_IRQ_ROUTING_MSI;
			
			irq->gsi = kvm_get_irq_route_gsi(kvm_context);
			if (irq->gsi < 0) {
				perror("vbus: kvm_get_irq_route_gsi");
				return;
			}
			
			kvm_add_routing_entry(kvm_context, irq);
			if (kvm_commit_irq_routes(kvm_context) < 0) {
				perror("vbus: kvm_commit_irq_routes");
				return;
			}

			irqfd = kvm_irqfd(kvm_context, irq->gsi, 0);
			if (irqfd < 0) {
				perror("vbus: failed to create irqfd");
				return;
			}

			assign.queue = i;
			assign.fd    = irqfd;

			ioeventfd = ioctl(priv->vbusfd,
					  VBUS_KVM_EVENTQ_ASSIGN,
					  &assign);
			if (ioeventfd < 0) {
				perror("vbus: failed to eventq-assign");
				goto cleanup;
			}

			ret = kvm_assign_ioeventfd(kvm_context,
						   priv->pioaddr,
						   sizeof(__u32),
						   ioeventfd, i,
						   IOEVENTFD_FLAG_DATAMATCH |
						   IOEVENTFD_FLAG_PIO);
			if (ret < 0) {
				perror("vbus: failed to assign ioeventfd");
				goto cleanup;
			}

			priv->interrupts.irq[i].ioeventfd = ioeventfd;
			priv->interrupts.irq[i].irqfd     = irqfd;

			continue;

		cleanup:
			if (irqfd)
				close(irqfd);

			if (ioeventfd)
				close(ioeventfd);

			return;
		}

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
		.vmfd         = kvm_context->vm_fd,
		.capabilities = 0, /* no advanced features (yet) */
	};

	if (!kvm_check_extension(kvm_context, KVM_CAP_IRQFD)
	    || !kvm_check_extension(kvm_context, KVM_CAP_IOEVENTFD))
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

	pci_enable_capability_support(dev, 0,
				      NULL,
				      vbus_pci_cap_write_config,
				      vbus_pci_cap_init);

	priv = to_priv(dev);

	memset(&priv->interrupts, 0, sizeof(priv->interrupts));
	memset(&priv->mmio, 0, sizeof(priv->mmio));
	memset(&priv->registers, 0, sizeof(priv->registers));

	priv->pioaddr = 0;
	priv->vbusfd = fd;
	priv->mmio.key = cpu_register_io_memory(vbus_pci_read, vbus_pci_write,
						priv);

	pci_register_bar(dev, 0, 32, PCI_ADDRESS_SPACE_MEM,
			 vbus_pci_mmio_map);
	pci_register_bar(dev, 1, sizeof(uint32_t), PCI_ADDRESS_SPACE_IO,
			 vbus_pci_pio_map);


	return;
out:
	close(fd);
}
