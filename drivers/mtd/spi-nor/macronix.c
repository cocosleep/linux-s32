// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2005, Intec Automation Inc.
 * Copyright (C) 2014, Freescale Semiconductor, Inc.
 * Copyright 2022-2024 NXP
 */

#include <linux/mtd/spi-nor.h>

#include "core.h"

static int
mx25l25635_post_bfpt_fixups(struct spi_nor *nor,
			    const struct sfdp_parameter_header *bfpt_header,
			    const struct sfdp_bfpt *bfpt)
{
	/*
	 * MX25L25635F supports 4B opcodes but MX25L25635E does not.
	 * Unfortunately, Macronix has re-used the same JEDEC ID for both
	 * variants which prevents us from defining a new entry in the parts
	 * table.
	 * We need a way to differentiate MX25L25635E and MX25L25635F, and it
	 * seems that the F version advertises support for Fast Read 4-4-4 in
	 * its BFPT table.
	 */
	if (bfpt->dwords[SFDP_DWORD(5)] & BFPT_DWORD5_FAST_READ_4_4_4)
		nor->flags |= SNOR_F_4B_OPCODES;

	return 0;
}

static const struct spi_nor_fixups mx25l25635_fixups = {
	.post_bfpt = mx25l25635_post_bfpt_fixups,
};

static int spi_nor_macronix_set_octal_dtr(struct spi_nor *nor, bool enable)
{
	struct spi_mem_op op;
	u8 *buf = nor->bouncebuf;
	*buf = 0xff;
	u8 addr_width = 4;
	int ret;

	/* The assumption is that the memory is in SPI 1-1-1 mode by default */
	op = (struct spi_mem_op)
		SPI_MEM_OP(SPI_MEM_OP_CMD(SPINOR_OP_RDCR2, 1),
			   SPI_MEM_OP_ADDR(addr_width, 0x0, 1),
			   SPI_MEM_OP_NO_DUMMY,
			   SPI_MEM_OP_DATA_IN(1, buf, 1));

	ret = spi_mem_exec_op(nor->spimem, &op);
	if (ret) {
		dev_err(nor->dev, "Failed to read CR2\n");
		return ret;
	}

	ret = spi_nor_write_enable(nor);
	if (ret) {
		dev_err(nor->dev, "Failed to enable write\n");
		return ret;
	}

	ret = spi_nor_wait_till_ready(nor);
	if (ret)
		return ret;

	*buf &= ~CR2_STR_OPI_EN;
	*buf |= CR2_DTR_OPI_EN;

	op = (struct spi_mem_op)
		SPI_MEM_OP(SPI_MEM_OP_CMD(SPINOR_OP_WRCR2, 1),
			   SPI_MEM_OP_ADDR(addr_width, 0x0, 1),
			   SPI_MEM_OP_NO_DUMMY,
			   SPI_MEM_OP_DATA_OUT(1, buf, 1));
	ret = spi_mem_exec_op(nor->spimem, &op);
	if (ret) {
		dev_err(nor->dev, "Failed to enable octal DTR mode\n");
		return ret;
	}

	return 0;
}

static void mx25uw51245g_default_init(struct spi_nor *nor)
{
	nor->params->set_octal_dtr = spi_nor_macronix_set_octal_dtr;
}

static int mx25uw51245g_late_init(struct spi_nor *nor)
{
	/* erase size in case it is set to 4K from BFPT */
	nor->erase_opcode = SPINOR_OP_SE_4B;
	nor->mtd.erasesize = nor->info->sector_size;

	nor->params->hwcaps.mask |= SNOR_HWCAPS_PP_8_8_8_DTR;

	spi_nor_set_pp_settings(&nor->params->page_programs[SNOR_CMD_PP_8_8_8_DTR],
				SPINOR_OP_PP_4B, SNOR_PROTO_8_8_8_DTR);

	/* The spi-nor core will always double the amount of dummy cycles if the
	 * protocol is DTR, but this memory's SFDP already takes it into account.
	 * Maximum 20 cycles are needed and using too many can cause the device
	 * to run incorrectly.
	 */
	spi_nor_set_read_settings(&nor->params->reads[SNOR_CMD_READ_8_8_8_DTR],
				0, 10, SPINOR_OP_READ_1_4_4_DTR_4B,
				SNOR_PROTO_8_8_8_DTR);

	/* Identify (free) samples with empty SFDP table */
	if (nor->cmd_ext_type == SPI_NOR_EXT_NONE) {
		nor->cmd_ext_type = SPI_NOR_EXT_INVERT;

		nor->params->rdsr_addr_nbytes = 4;
		nor->params->rdsr_dummy = 4;
	}

	return 0;
}

static struct spi_nor_fixups mx25uw51245g_fixups = {
	.default_init = mx25uw51245g_default_init,
	.late_init = mx25uw51245g_late_init,
};

static const struct flash_info macronix_nor_parts[] = {
	/* Macronix */
	{ "mx25l512e",   INFO(0xc22010, 0, 64 * 1024,   1)
		NO_SFDP_FLAGS(SECT_4K) },
	{ "mx25l2005a",  INFO(0xc22012, 0, 64 * 1024,   4)
		NO_SFDP_FLAGS(SECT_4K) },
	{ "mx25l4005a",  INFO(0xc22013, 0, 64 * 1024,   8)
		NO_SFDP_FLAGS(SECT_4K) },
	{ "mx25l8005",   INFO(0xc22014, 0, 64 * 1024,  16) },
	{ "mx25l1606e",  INFO(0xc22015, 0, 64 * 1024,  32)
		NO_SFDP_FLAGS(SECT_4K) },
	{ "mx25l3205d",  INFO(0xc22016, 0, 64 * 1024,  64)
		NO_SFDP_FLAGS(SECT_4K) },
	{ "mx25l3255e",  INFO(0xc29e16, 0, 64 * 1024,  64)
		NO_SFDP_FLAGS(SECT_4K) },
	{ "mx25l6405d",  INFO(0xc22017, 0, 64 * 1024, 128)
		NO_SFDP_FLAGS(SECT_4K) },
	{ "mx25u2033e",  INFO(0xc22532, 0, 64 * 1024,   4)
		NO_SFDP_FLAGS(SECT_4K) },
	{ "mx25u3235f",	 INFO(0xc22536, 0, 64 * 1024,  64)
		NO_SFDP_FLAGS(SECT_4K | SPI_NOR_DUAL_READ |
			      SPI_NOR_QUAD_READ) },
	{ "mx25u4035",   INFO(0xc22533, 0, 64 * 1024,   8)
		NO_SFDP_FLAGS(SECT_4K) },
	{ "mx25u8035",   INFO(0xc22534, 0, 64 * 1024,  16)
		NO_SFDP_FLAGS(SECT_4K) },
	{ "mx25u6435f",  INFO(0xc22537, 0, 64 * 1024, 128)
		NO_SFDP_FLAGS(SECT_4K) },
	{ "mx25l12805d", INFO(0xc22018, 0, 64 * 1024, 256)
		FLAGS(SPI_NOR_HAS_LOCK | SPI_NOR_4BIT_BP)
		NO_SFDP_FLAGS(SECT_4K) },
	{ "mx25l12855e", INFO(0xc22618, 0, 64 * 1024, 256) },
	{ "mx25r1635f",  INFO(0xc22815, 0, 64 * 1024,  32)
		NO_SFDP_FLAGS(SECT_4K | SPI_NOR_DUAL_READ |
			      SPI_NOR_QUAD_READ) },
	{ "mx25r3235f",  INFO(0xc22816, 0, 64 * 1024,  64)
		NO_SFDP_FLAGS(SECT_4K | SPI_NOR_DUAL_READ |
			      SPI_NOR_QUAD_READ) },
	{ "mx25u12835f", INFO(0xc22538, 0, 64 * 1024, 256)
		NO_SFDP_FLAGS(SECT_4K | SPI_NOR_DUAL_READ |
			      SPI_NOR_QUAD_READ) },
	{ "mx25l25635e", INFO(0xc22019, 0, 64 * 1024, 512)
		NO_SFDP_FLAGS(SPI_NOR_DUAL_READ | SPI_NOR_QUAD_READ)
		.fixups = &mx25l25635_fixups },
	{ "mx25u25635f", INFO(0xc22539, 0, 64 * 1024, 512)
		NO_SFDP_FLAGS(SECT_4K)
		FIXUP_FLAGS(SPI_NOR_4B_OPCODES) },
	{ "mx25u51245g", INFO(0xc2253a, 0, 64 * 1024, 1024)
		NO_SFDP_FLAGS(SECT_4K | SPI_NOR_DUAL_READ | SPI_NOR_QUAD_READ)
		FIXUP_FLAGS(SPI_NOR_4B_OPCODES) },
	{ "mx25uw51245g", INFO(0xc2813a, 0, 64 * 1024, 1024)
		NO_SFDP_FLAGS(SPI_NOR_OCTAL_READ | SPI_NOR_OCTAL_DTR_READ)
		FIXUP_FLAGS(SPI_NOR_4B_OPCODES | SPI_NOR_IO_MODE_EN_VOLATILE)
		.fixups = &mx25uw51245g_fixups },
	{ "mx25v8035f",  INFO(0xc22314, 0, 64 * 1024,  16)
		NO_SFDP_FLAGS(SECT_4K | SPI_NOR_DUAL_READ |
			      SPI_NOR_QUAD_READ) },
	{ "mx25l25655e", INFO(0xc22619, 0, 64 * 1024, 512) },
	{ "mx66l51235f", INFO(0xc2201a, 0, 64 * 1024, 1024)
		NO_SFDP_FLAGS(SPI_NOR_DUAL_READ | SPI_NOR_QUAD_READ)
		FIXUP_FLAGS(SPI_NOR_4B_OPCODES) },
	{ "mx66u51235f", INFO(0xc2253a, 0, 64 * 1024, 1024)
		NO_SFDP_FLAGS(SECT_4K | SPI_NOR_DUAL_READ | SPI_NOR_QUAD_READ)
		FIXUP_FLAGS(SPI_NOR_4B_OPCODES) },
	{ "mx66l1g45g",  INFO(0xc2201b, 0, 64 * 1024, 2048)
		NO_SFDP_FLAGS(SECT_4K | SPI_NOR_DUAL_READ |
			      SPI_NOR_QUAD_READ) },
	{ "mx66l1g55g",  INFO(0xc2261b, 0, 64 * 1024, 2048)
		NO_SFDP_FLAGS(SPI_NOR_QUAD_READ) },
	{ "mx66u2g45g",	 INFO(0xc2253c, 0, 64 * 1024, 4096)
		NO_SFDP_FLAGS(SECT_4K | SPI_NOR_DUAL_READ | SPI_NOR_QUAD_READ)
		FIXUP_FLAGS(SPI_NOR_4B_OPCODES) },
};

static void macronix_nor_default_init(struct spi_nor *nor)
{
	nor->params->quad_enable = spi_nor_sr1_bit6_quad_enable;
}

static int macronix_nor_late_init(struct spi_nor *nor)
{
	if (!nor->params->set_4byte_addr_mode)
		nor->params->set_4byte_addr_mode = spi_nor_set_4byte_addr_mode_en4b_ex4b;

	return 0;
}

static const struct spi_nor_fixups macronix_nor_fixups = {
	.default_init = macronix_nor_default_init,
	.late_init = macronix_nor_late_init,
};

const struct spi_nor_manufacturer spi_nor_macronix = {
	.name = "macronix",
	.parts = macronix_nor_parts,
	.nparts = ARRAY_SIZE(macronix_nor_parts),
	.fixups = &macronix_nor_fixups,
};