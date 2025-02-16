/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright 2020-2023 NXP */
#ifndef LLCE_INTERFACE_CORE2CORE_H
#define LLCE_INTERFACE_CORE2CORE_H

#define LLCE_CORE2CORE_HINTC0R(BASE) (BASE)
#define LLCE_CORE2CORE_HINTC1R(BASE) (BASE + 0x04U)
#define LLCE_CORE2CORE_HINTC2R(BASE) (BASE + 0x08U)
#define LLCE_CORE2CORE_HINTC3R(BASE) (BASE + 0x0CU)

#define LLCE_CORE2CORE_C0INTHR(BASE) (BASE + 0x20U)
#define LLCE_CORE2CORE_C1INTHR(BASE) (BASE + 0x24U)
#define LLCE_CORE2CORE_C2INTHR(BASE) (BASE + 0x28U)
#define LLCE_CORE2CORE_C3INTHR(BASE) (BASE + 0x2CU)

#define LLCE_CORE2CORE_C0INTCR(BASE) (BASE + 0x40U)
#define LLCE_CORE2CORE_C1INTCR(BASE) (BASE + 0x44U)
#define LLCE_CORE2CORE_C2INTCR(BASE) (BASE + 0x48U)
#define LLCE_CORE2CORE_C3INTCR(BASE) (BASE + 0x4CU)

#define LLCE_CORE2CORE_HINTC0ER(BASE) (BASE + 0x60U)
#define LLCE_CORE2CORE_HINTC1ER(BASE) (BASE + 0x64U)
#define LLCE_CORE2CORE_HINTC2ER(BASE) (BASE + 0x68U)
#define LLCE_CORE2CORE_HINTC3ER(BASE) (BASE + 0x6CU)

#define LLCE_CORE2CORE_C0INTHER(BASE) (BASE + 0x80U)
#define LLCE_CORE2CORE_C1INTHER(BASE) (BASE + 0x84U)
#define LLCE_CORE2CORE_C2INTHER(BASE) (BASE + 0x88U)
#define LLCE_CORE2CORE_C3INTHER(BASE) (BASE + 0x8CU)

#define LLCE_CORE2CORE_C0INTCER(BASE) (BASE + 0xA0U)
#define LLCE_CORE2CORE_C1INTCER(BASE) (BASE + 0xA4U)
#define LLCE_CORE2CORE_C2INTCER(BASE) (BASE + 0xA8U)
#define LLCE_CORE2CORE_C3INTCER(BASE) (BASE + 0xACU)

#define LLCE_CORE2CORE_C1INTHR_RXLUT_FLAG (0x01U)
#define LLCE_CORE2CORE_HINTC1R_RXLUT_FLAG (0x04U)

#endif /* LLCE_INTERFACE_CORE2CORE_H */
