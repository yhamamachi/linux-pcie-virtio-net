/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * PCIe host/endpoint controller driver for Renesas R-Car Gen4 Series SoCs
 * Copyright (C) 2022-2023 Renesas Electronics Corporation
 */

#ifndef _PCIE_RCAR_GEN4_H_
#define _PCIE_RCAR_GEN4_H_

#include <linux/io.h>
#include <linux/pci.h>

#include "pcie-designware.h"

/* Renesas-specific */
#define PCIEMSR0		0x0000
#define  BIFUR_MOD_SET_ON	BIT(0)
#define  DEVICE_TYPE_EP		0
#define  DEVICE_TYPE_RC		BIT(4)

#define PCIEINTSTS0		0x0084
#define PCIEINTXSTS		0x0090
#define PCIEINTSTS0EN		0x0310
#define  MSI_CTRL_INT		BIT(26)
#define  SMLH_LINK_UP		BIT(7)
#define  RDLH_LINK_UP		BIT(6)
#define PCIEDMAINTSTSEN		0x0314
#define  PCIEDMAINTSTSEN_INIT	GENMASK(15, 0)
#define PCIEINTXSTSEN		0x0318
#define PCIEINTXSTSCLR		0x0348

struct rcar_gen4_pcie {
	enum dw_pcie_device_mode mode;
	struct dw_pcie dw;
	void __iomem *base;
};
#define to_rcar_gen4_pcie(x)	dev_get_drvdata((x)->dev)

int rcar_gen4_pcie_basic_init(struct rcar_gen4_pcie *rcar);
int rcar_gen4_pcie_prepare(struct rcar_gen4_pcie *pcie);
void rcar_gen4_pcie_unprepare(struct rcar_gen4_pcie *pcie);
int rcar_gen4_pcie_get_resources(struct rcar_gen4_pcie *rcar,
				 struct platform_device *pdev);
struct rcar_gen4_pcie *rcar_gen4_pcie_devm_alloc(struct device *dev);

#endif /* _PCIE_RCAR_GEN4_H_ */
