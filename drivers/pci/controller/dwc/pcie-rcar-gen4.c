// SPDX-License-Identifier: GPL-2.0-only
/*
 * PCIe host/endpoint controller driver for Renesas R-Car Gen4 Series SoCs
 * Copyright (C) 2022-2023 Renesas Electronics Corporation
 */

#include <linux/delay.h>
#include <linux/io.h>
#include <linux/of_device.h>
#include <linux/pci.h>
#include <linux/pm_runtime.h>
#include <linux/reset.h>

#include "pcie-rcar-gen4.h"
#include "pcie-designware.h"

/* Renesas-specific */
#define PCIERSTCTRL1		0x0014
#define  APP_HOLD_PHY_RST	BIT(16)
#define  APP_LTSSM_ENABLE	BIT(0)

#define SPEED_CHANGE_MAX_RETRIES	5

static void rcar_gen4_pcie_ltssm_enable(struct rcar_gen4_pcie *rcar,
					bool enable)
{
	u32 val;

	val = readl(rcar->base + PCIERSTCTRL1);
	if (enable) {
		val |= APP_LTSSM_ENABLE;
		val &= ~APP_HOLD_PHY_RST;
	} else {
		val &= ~APP_LTSSM_ENABLE;
		val |= APP_HOLD_PHY_RST;
	}
	writel(val, rcar->base + PCIERSTCTRL1);
}

static int rcar_gen4_pcie_link_up(struct dw_pcie *dw)
{
	struct rcar_gen4_pcie *rcar = to_rcar_gen4_pcie(dw);
	u32 val, mask;

	val = readl(rcar->base + PCIEINTSTS0);
	mask = RDLH_LINK_UP | SMLH_LINK_UP;

	return (val & mask) == mask;
}

static void rcar_gen4_pcie_speed_change(struct dw_pcie *dw)
{
	u32 val;

	val = dw_pcie_readl_dbi(dw, PCIE_LINK_WIDTH_SPEED_CONTROL);
	val &= ~PORT_LOGIC_SPEED_CHANGE;
	dw_pcie_writel_dbi(dw, PCIE_LINK_WIDTH_SPEED_CONTROL, val);

	val = dw_pcie_readl_dbi(dw, PCIE_LINK_WIDTH_SPEED_CONTROL);
	val |= PORT_LOGIC_SPEED_CHANGE;
	dw_pcie_writel_dbi(dw, PCIE_LINK_WIDTH_SPEED_CONTROL, val);
}

static int rcar_gen4_pcie_start_link(struct dw_pcie *dw)
{
	struct rcar_gen4_pcie *rcar = to_rcar_gen4_pcie(dw);
	int i;

	rcar_gen4_pcie_ltssm_enable(rcar, true);

	/*
	 * Require direct speed change here. Otherwise RDLH_LINK_UP of
	 * PCIEINTSTS0 which is this controller specific register may not
	 * be set.
	 */
	if (rcar->mode == DW_PCIE_RC_TYPE) {
		for (i = 0; i < SPEED_CHANGE_MAX_RETRIES; i++) {
			rcar_gen4_pcie_speed_change(dw);
			msleep(100);
			if (dw_pcie_link_up(dw))
				return 0;
		}

		return -ETIMEDOUT;	/* Failed */
	}

	return 0;
}

static void rcar_gen4_pcie_stop_link(struct dw_pcie *dw)
{
	struct rcar_gen4_pcie *rcar = to_rcar_gen4_pcie(dw);

	rcar_gen4_pcie_ltssm_enable(rcar, false);
}

int rcar_gen4_pcie_basic_init(struct rcar_gen4_pcie *rcar)
{
	struct dw_pcie *dw = &rcar->dw;
	u32 val;

	if (!reset_control_status(dw->core_rsts[DW_PCIE_PWR_RST].rstc))
		reset_control_assert(dw->core_rsts[DW_PCIE_PWR_RST].rstc);

	val = readl(rcar->base + PCIEMSR0);
	if (rcar->mode == DW_PCIE_RC_TYPE)
		val |= DEVICE_TYPE_RC;
	else if (rcar->mode == DW_PCIE_EP_TYPE)
		val |= DEVICE_TYPE_EP;
	else
		return -EINVAL;

	if (dw->num_lanes < 4)
		val |= BIFUR_MOD_SET_ON;

	writel(val, rcar->base + PCIEMSR0);

	return reset_control_deassert(dw->core_rsts[DW_PCIE_PWR_RST].rstc);
}

int rcar_gen4_pcie_prepare(struct rcar_gen4_pcie *rcar)
{
	struct device *dev = rcar->dw.dev;
	int err;

	pm_runtime_enable(dev);
	err = pm_runtime_resume_and_get(dev);
	if (err < 0) {
		dev_err(dev, "Failed to resume/get Runtime PM\n");
		pm_runtime_disable(dev);
	}

	return err;
}

void rcar_gen4_pcie_unprepare(struct rcar_gen4_pcie *rcar)
{
	struct device *dev = rcar->dw.dev;
	struct dw_pcie *dw = &rcar->dw;

	if (!reset_control_status(dw->core_rsts[DW_PCIE_PWR_RST].rstc))
		reset_control_assert(dw->core_rsts[DW_PCIE_PWR_RST].rstc);
	pm_runtime_put(dev);
	pm_runtime_disable(dev);
}

int rcar_gen4_pcie_get_resources(struct rcar_gen4_pcie *rcar,
				 struct platform_device *pdev)
{
	/* Renesas-specific registers */
	rcar->base = devm_platform_ioremap_resource_byname(pdev, "app");
	if (IS_ERR(rcar->base))
		return PTR_ERR(rcar->base);

	return 0;
}

static const struct dw_pcie_ops dw_pcie_ops = {
	.start_link = rcar_gen4_pcie_start_link,
	.stop_link = rcar_gen4_pcie_stop_link,
	.link_up = rcar_gen4_pcie_link_up,
};

struct rcar_gen4_pcie *rcar_gen4_pcie_devm_alloc(struct device *dev)
{
	struct rcar_gen4_pcie *rcar;

	rcar = devm_kzalloc(dev, sizeof(*rcar), GFP_KERNEL);
	if (!rcar)
		return NULL;

	rcar->dw.dev = dev;
	rcar->dw.ops = &dw_pcie_ops;
	dw_pcie_cap_set(&rcar->dw, EDMA_UNROLL);

	return rcar;
}
