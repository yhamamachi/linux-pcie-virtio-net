// SPDX-License-Identifier: GPL-2.0-only
/*
 * PCIe host controller driver for Renesas R-Car Gen4 Series SoCs
 * Copyright (C) 2022-2023 Renesas Electronics Corporation
 */

#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/of_device.h>
#include <linux/pci.h>
#include <linux/platform_device.h>

#include "pcie-rcar-gen4.h"
#include "pcie-designware.h"

static int rcar_gen4_pcie_host_init(struct dw_pcie_rp *pp)
{
	struct dw_pcie *dw = to_dw_pcie_from_pp(pp);
	struct rcar_gen4_pcie *rcar = to_rcar_gen4_pcie(dw);
	int ret;
	u32 val;

	gpiod_set_value_cansleep(dw->pe_rst, 1);

	ret = clk_bulk_prepare_enable(DW_PCIE_NUM_CORE_CLKS, dw->core_clks);
	if (ret) {
		dev_err(dw->dev, "Failed to enable ref clocks\n");
		return ret;
	}

	ret = rcar_gen4_pcie_basic_init(rcar);
	if (ret < 0) {
		clk_bulk_disable_unprepare(DW_PCIE_NUM_CORE_CLKS, dw->core_clks);
		return ret;
	}

	/*
	 * According to the section 3.5.7.2 "RC Mode" in DWC PCIe Dual Mode
	 * Rev.5.20a, we should disable two BARs to avoid unnecessary memory
	 * assignment during device enumeration.
	 */
	dw_pcie_writel_dbi2(dw, PCI_BASE_ADDRESS_0, 0x0);
	dw_pcie_writel_dbi2(dw, PCI_BASE_ADDRESS_1, 0x0);

	if (IS_ENABLED(CONFIG_PCI_MSI)) {
		/* Enable MSI interrupt signal */
		val = readl(rcar->base + PCIEINTSTS0EN);
		val |= MSI_CTRL_INT;
		writel(val, rcar->base + PCIEINTSTS0EN);
	}

	msleep(100);	/* pe_rst requires 100msec delay */

	gpiod_set_value_cansleep(dw->pe_rst, 0);

	return 0;
}

static const struct dw_pcie_host_ops rcar_gen4_pcie_host_ops = {
	.host_init = rcar_gen4_pcie_host_init,
};

static int rcar_gen4_add_dw_pcie_rp(struct rcar_gen4_pcie *rcar,
				   struct platform_device *pdev)
{
	struct dw_pcie *dw = &rcar->dw;
	struct dw_pcie_rp *pp = &dw->pp;

	pp->num_vectors = MAX_MSI_IRQS;
	pp->ops = &rcar_gen4_pcie_host_ops;

	return dw_pcie_host_init(pp);
}

static void rcar_gen4_remove_dw_pcie_rp(struct rcar_gen4_pcie *rcar)
{
	dw_pcie_host_deinit(&rcar->dw.pp);
	gpiod_set_value_cansleep(rcar->dw.pe_rst, 1);
}

static int rcar_gen4_pcie_probe(struct platform_device *pdev)
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

	rcar->mode = DW_PCIE_RC_TYPE;
	err = rcar_gen4_add_dw_pcie_rp(rcar, pdev);
	if (err < 0)
		goto err_add;

	return 0;

err_add:
	rcar_gen4_pcie_unprepare(rcar);

	return err;
}

static int rcar_gen4_pcie_remove(struct platform_device *pdev)
{
	struct rcar_gen4_pcie *rcar = platform_get_drvdata(pdev);

	rcar_gen4_remove_dw_pcie_rp(rcar);
	rcar_gen4_pcie_unprepare(rcar);

	return 0;
}

static const struct of_device_id rcar_gen4_pcie_of_match[] = {
	{ .compatible = "renesas,rcar-gen4-pcie", },
	{},
};

static struct platform_driver rcar_gen4_pcie_driver = {
	.driver = {
		.name = "pcie-rcar-gen4",
		.of_match_table = rcar_gen4_pcie_of_match,
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
	.probe = rcar_gen4_pcie_probe,
	.remove = rcar_gen4_pcie_remove,
};
module_platform_driver(rcar_gen4_pcie_driver);

MODULE_DESCRIPTION("Renesas R-Car Gen4 PCIe host controller driver");
MODULE_LICENSE("GPL");
