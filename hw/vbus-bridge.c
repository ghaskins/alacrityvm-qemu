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
#include <sys/eventfd.h>
#include <linux/vbus_kvm.h>
#include "qemu-kvm.h"
#include "pthread.h"
#include "hw.h"
#include "pci.h"

#include "vbus-bridge.h"

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
		int                          inputfd;
		int                          outputfd;
		void                        *outputhandle;
		struct {
			struct kvm_irq_routing_entry routing;
			int                          enabled:1;
		} msi;
		struct {
			pthread_t            thread;
			pthread_barrier_t    barrier;
		} intx;
	} interrupt;
	struct {
		int                          key;
		uint32_t                     addr;
	} mmio;
	struct vbus_pci_regs                 registers;
	uint32_t                             signals;
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

	priv->signals = addr;
}

static int
vbus_pci_attach_msi(struct Priv *priv)
{
	PCIDevice *dev = &priv->dev;
	struct kvm_irq_routing_entry *irq;
	unsigned int pos = dev->cap.start;
	uint32_t addr;
	uint16_t data;
	int ret;

	irq = &priv->interrupt.msi.routing;

	addr = *(uint32_t *)&dev->config[pos + PCI_MSI_ADDRESS_LO];
	data = *(uint16_t *)&dev->config[pos + PCI_MSI_DATA_32];

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

	priv->interrupt.inputfd = ret;

	return 0;
}

static void
vbus_pci_detach_msi(struct Priv *priv)
{
	struct kvm_irq_routing_entry *irq;
	irq = &priv->interrupt.msi.routing;

	kvm_del_routing_entry(kvm_context, irq);
}

static void *intx_thread_fn(void *arg)
{
	struct Priv *priv = (struct Priv *)arg;
	int ret;

	pthread_barrier_wait(&priv->interrupt.intx.barrier);

	for (;;) {
		uint64_t val;
		uint64_t i;

		ret = read(priv->interrupt.inputfd, &val, sizeof(val));
		if (ret < 0) {
			perror("vbus: failed to read intx thread");
			exit(ret);
		}

		for (i = 0; i < val; i++)
			qemu_irq_pulse(priv->dev.irq[0]);
	}
}

static int
vbus_pci_attach_intx(struct Priv *priv)
{
	int ret;

	ret = eventfd(0, 0);
	if (ret < 0)
		return ret;

	priv->interrupt.inputfd = ret;

	pthread_barrier_init(&priv->interrupt.intx.barrier, NULL, 2);

	ret = pthread_create(&priv->interrupt.intx.thread, NULL,
			     intx_thread_fn, priv);
	if (ret < 0)
		return ret;

	pthread_barrier_wait(&priv->interrupt.intx.barrier);

	return 0;
}

static void
vbus_pci_detach_intx(struct Priv *priv)
{
	pthread_cancel(priv->interrupt.intx.thread);
	pthread_join(priv->interrupt.intx.thread, NULL);
}

static int
vbus_pci_eventq_assign(struct Priv *priv,
		       uint32_t count, uint64_t ringp, uint64_t datap)
{
	struct vbus_kvm_eventq_assign assign;
	int outputfd = 0;
	int ret;

	if (priv->interrupt.msi.enabled)
		ret = vbus_pci_attach_msi(priv);
	else
		ret = vbus_pci_attach_intx(priv);
	if (ret < 0) {
		perror("vbus: failed to attach interrupt");
		goto cleanup;
	}

	assign.flags = 0;
	assign.queue = 0;
	assign.fd    = priv->interrupt.inputfd;
	assign.count = count;
	assign.ring  = ringp;
	assign.data  = datap;

	ret = ioctl(priv->vbusfd, VBUS_KVM_EVENTQ_ASSIGN, &assign);
	if (ret < 0) {
		perror("vbus: failed to eventq-assign");
		goto cleanup;
	}

	outputfd = ret;

	ret = kvm_assign_ioeventfd(kvm_context,
				   priv->signals,
				   sizeof(__u32),
				   outputfd, 0,
				   IOEVENTFD_FLAG_DATAMATCH |
				   IOEVENTFD_FLAG_PIO,
				   &priv->interrupt.outputhandle);
	if (ret < 0) {
		perror("vbus: failed to assign ioeventfd");
		goto cleanup;
	}

	priv->interrupt.outputfd = outputfd;

	return 0;

cleanup:
	if (priv->interrupt.inputfd) {
		close(priv->interrupt.inputfd);
		priv->interrupt.inputfd = 0;
	}

	if (outputfd)
		close(outputfd);

	return ret;
}

static int
bridge_reset(struct Priv *priv)
{
	struct vbus_kvm_negotiate negotiate = {
		.magic        = VBUS_KVM_ABI_MAGIC,
		.version      = VBUS_KVM_ABI_VERSION,
		.capabilities = 0, /* no advanced features (yet) */
	};
	struct vbus_kvm_open openargs = {
		.vmfd         = kvm_state->vmfd,
	};
	int fd = -1;
	int ret;
	int ver;

	if (priv->interrupt.outputfd) {
		ret = kvm_deassign_ioeventfd(kvm_context,
					     priv->interrupt.outputhandle);
		if (ret < 0)
			perror("failed to deassign");

		close(priv->interrupt.outputfd);
		priv->interrupt.outputfd = 0;
	}

	if (priv->interrupt.inputfd) {
		if (priv->interrupt.msi.enabled)
			vbus_pci_detach_msi(priv);
		else
			vbus_pci_detach_intx(priv);
			
		close(priv->interrupt.inputfd);
		priv->interrupt.inputfd = 0;
	}

	if (priv->vbusfd != -1) {
		close(priv->vbusfd);
		priv->vbusfd = -1;
	}

	fd = open("/dev/vbus-kvm", 0);
	if (fd < 0)
		return -EINVAL;

	ret = ioctl(fd, VBUS_KVM_NEGOTIATE, &negotiate);
	if (ret < 0)
		goto out;

	ret = ioctl(fd, VBUS_KVM_OPEN, &openargs);
	if (ret < 0)
		goto out;

	ver = ret;

	if (priv->signals) {
		ret = ioctl(fd, VBUS_KVM_SIGADDR_ASSIGN, &priv->signals);
		if (ret < 0) {
			perror("failed to assign signal address");
			goto out;
		}
	}

	priv->vbusfd = fd;

	return ver;

out:
	close(fd);
	return ret;
}

static int
bridgecall_negotiate(struct Priv *priv)
{
	struct vbus_pci_call_desc *desc = &priv->registers.bridgecall;
	struct vbus_pci_bridge_negotiate params;
	int ret;

	if (desc->len != sizeof(params))
		return -EINVAL;

	cpu_physical_memory_read(desc->datap, (void *)&params, sizeof(params));

	if (params.magic != VBUS_PCI_ABI_MAGIC)
		return -EINVAL;

	params.capabilities = 0;

	ret = bridge_reset(priv);

	if (params.version != ret)
		ret = -EINVAL;

	cpu_physical_memory_write(desc->datap, (void *)&params, sizeof(params));

	return ret;
}

static int
bridgecall_qreg(struct Priv *priv)
{
	struct vbus_pci_call_desc *desc = &priv->registers.bridgecall;
	struct vbus_pci_busreg params;
	struct vbus_pci_eventqreg *qreg;
	int ret;

	if (desc->len != sizeof(params))
		return -EINVAL;

	if (priv->vbusfd == -1)
		return -EINVAL;

	cpu_physical_memory_read(desc->datap, (void *)&params, sizeof(params));

	if (params.count != 1)
		return -EINVAL;

	qreg = &params.eventq[0];

	ret = vbus_pci_eventq_assign(priv, qreg->count, qreg->ring, qreg->data);
	if (ret < 0)
		return ret;

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

	if (priv->vbusfd == -1)
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
	dev->config[offset+PCI_MSI_FLAGS] = 0; /* request 1 vector */
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

	priv->interrupt.msi.enabled = val & 1;
}

void
pci_vbus_bridge_init(PCIBus *bus)
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

	if (!kvm_check_extension(kvm_state, KVM_CAP_IRQFD)
	    || !kvm_check_extension(kvm_state, KVM_CAP_IOEVENTFD))
		return;

	fd = open("/dev/vbus-kvm", 0);
	if (fd < 0)
		return;

	ret = ioctl(fd, VBUS_KVM_NEGOTIATE, &negotiate);
	close(fd);

	if (ret < 0) {
		perror("vbus present but failed to negotiate");
		return;
	}

	dev = pci_register_device(bus, "vbus", sizeof(*priv),
				  -1, NULL, NULL);
	if (!dev) {
		perror("vbus present but PCI allocation failed");
		return;
	}

	config = dev->config;
	pci_config_set_vendor_id(config, PCI_VENDOR_ID_NOVELL);
	pci_config_set_device_id(config, PCI_DEVICE_ID_VIRTUAL_BUS);
	pci_config_set_class(config, PCI_CLASS_BRIDGE_OTHER);

	config[0x08] = VBUS_PCI_ABI_VERSION;
	config[0x3d] = 1; /* advertise legacy intx */

	pci_enable_capability_support(dev, 0,
				      NULL,
				      vbus_pci_cap_write_config,
				      vbus_pci_cap_init);

	priv = to_priv(dev);

	memset(&priv->interrupt, 0, sizeof(priv->interrupt));
	memset(&priv->mmio, 0, sizeof(priv->mmio));
	memset(&priv->registers, 0, sizeof(priv->registers));

	priv->signals = 0;
	priv->vbusfd = -1;
	priv->mmio.key = cpu_register_io_memory(vbus_pci_read, vbus_pci_write,
						priv);

	pci_register_bar(dev, 0, sizeof(struct vbus_pci_regs),
			 PCI_ADDRESS_SPACE_MEM, vbus_pci_mmio_map);
	pci_register_bar(dev, 1, sizeof(struct vbus_pci_signals),
			 PCI_ADDRESS_SPACE_IO, vbus_pci_pio_map);

	return;
}
