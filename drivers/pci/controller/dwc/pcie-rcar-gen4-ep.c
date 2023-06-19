// SPDX-License-Identifier: GPL-2.0-only
/*
 * PCIe Endpoint driver for Renesas R-Car Gen4 Series SoCs
 * Copyright (C) 2022-2023 Renesas Electronics Corporation
 */

#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/of_device.h>
#include <linux/pci.h>
#include <linux/platform_device.h>

#include "pcie-rcar-gen4.h"
#include "pcie-designware.h"

static void rcar_gen4_pcie_ep_pre_init(struct dw_pcie_ep *ep)
{
	struct dw_pcie *dw = to_dw_pcie_from_ep(ep);
	struct rcar_gen4_pcie *rcar = to_rcar_gen4_pcie(dw);
	u8 val;

	rcar_gen4_pcie_basic_init(rcar);

	dw_pcie_dbi_ro_wr_en(dw);

	/* Single function */
	val = dw_pcie_readb_dbi(dw, PCI_HEADER_TYPE);
	val &= ~PCI_HEADER_TYPE_MULTI_FUNC;
	dw_pcie_writeb_dbi(dw, PCI_HEADER_TYPE, val);

	dw_pcie_dbi_ro_wr_dis(dw);

	writel(PCIEDMAINTSTSEN_INIT, rcar->base + PCIEDMAINTSTSEN);
}

static void rcar_gen4_pcie_ep_deinit(struct dw_pcie_ep *ep)
{
	struct dw_pcie *dw = to_dw_pcie_from_ep(ep);
	struct rcar_gen4_pcie *rcar = to_rcar_gen4_pcie(dw);

	writel(0, rcar->base + PCIEDMAINTSTSEN);
}

static int rcar_gen4_pcie_ep_raise_irq(struct dw_pcie_ep *ep, u8 func_no,
				       enum pci_epc_irq_type type,
				       u16 interrupt_num)
{
	struct dw_pcie *dw = to_dw_pcie_from_ep(ep);

	switch (type) {
	case PCI_EPC_IRQ_INTX:
		return dw_pcie_ep_raise_intx_irq(ep, func_no);
	case PCI_EPC_IRQ_MSI:
		return dw_pcie_ep_raise_msi_irq(ep, func_no, interrupt_num);
	default:
		dev_err(dw->dev, "Unknown IRQ type\n");
		return -EINVAL;
	}

	return 0;
}

static const struct pci_epc_features rcar_gen4_pcie_epc_features = {
	.linkup_notifier = false,
	.msi_capable = true,
	.msix_capable = false,
	.reserved_bar = 1 << BAR_5,
	.align = SZ_1M,
};

static const struct pci_epc_features*
rcar_gen4_pcie_ep_get_features(struct dw_pcie_ep *ep)
{
	return &rcar_gen4_pcie_epc_features;
}

static const struct dw_pcie_ep_ops pcie_ep_ops = {
	.ep_pre_init = rcar_gen4_pcie_ep_pre_init,
	.ep_deinit = rcar_gen4_pcie_ep_deinit,
	.raise_irq = rcar_gen4_pcie_ep_raise_irq,
	.get_features = rcar_gen4_pcie_ep_get_features,
};

static int rcar_gen4_add_pcie_ep(struct rcar_gen4_pcie *rcar,
				 struct platform_device *pdev)
{
	struct dw_pcie_ep *ep = &rcar->dw.ep;
	int ret;

	rcar->mode = DW_PCIE_EP_TYPE;
	ep->ops = &pcie_ep_ops;

	ret = dw_pcie_ep_init(ep);
	if (ret) {
		dev_err(&pdev->dev, "Failed to initialize endpoint\n");
		return ret;
	}

	return 0;
}

static void rcar_gen4_remove_pcie_ep(struct rcar_gen4_pcie *rcar)
{
	dw_pcie_ep_exit(&rcar->dw.ep);
}

static int rcar_gen4_pcie_ep_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct rcar_gen4_pcie *rcar;
	int err;

	rcar = rcar_gen4_pcie_devm_alloc(dev);
	if (!rcar)
		return -ENOMEM;

	err = rcar_gen4_pcie_get_resources(rcar, pdev);
	if (err < 0) {
		dev_err(dev, "Failed to request resource: %d\n", err);
		return err;
	}

	platform_set_drvdata(pdev, rcar);

	err = rcar_gen4_pcie_prepare(rcar);
	if (err < 0)
		return err;

	err = rcar_gen4_add_pcie_ep(rcar, pdev);
	if (err < 0)
		goto err_add;

	return 0;

err_add:
	rcar_gen4_pcie_unprepare(rcar);

	return err;
}

static int rcar_gen4_pcie_ep_remove(struct platform_device *pdev)
{
	struct rcar_gen4_pcie *rcar = platform_get_drvdata(pdev);

	rcar_gen4_remove_pcie_ep(rcar);
	rcar_gen4_pcie_unprepare(rcar);

	return 0;
}

static const struct of_device_id rcar_gen4_pcie_of_match[] = {
	{ .compatible = "renesas,rcar-gen4-pcie-ep", },
	{},
};

static struct platform_driver rcar_gen4_pcie_ep_driver = {
	.driver = {
		.name = "pcie-rcar-gen4-ep",
		.of_match_table = rcar_gen4_pcie_of_match,
	},
	.probe = rcar_gen4_pcie_ep_probe,
	.remove = rcar_gen4_pcie_ep_remove,
};
module_platform_driver(rcar_gen4_pcie_ep_driver);

MODULE_DESCRIPTION("Renesas R-Car Gen4 PCIe endpoint controller driver");
MODULE_LICENSE("GPL");
