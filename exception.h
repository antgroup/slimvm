/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 Ant Group Corporation.
 */

#ifndef _EXCEPTION_H
#define _EXCEPTION_H

#include <asm/types.h>
#include "vmx.h"

#define DE_VECTOR 0
#define DB_VECTOR 1
#define BP_VECTOR 3
#define OF_VECTOR 4
#define BR_VECTOR 5
#define UD_VECTOR 6
#define NM_VECTOR 7
#define DF_VECTOR 8
#define TS_VECTOR 10
#define NP_VECTOR 11
#define SS_VECTOR 12
#define GP_VECTOR 13
#define PF_VECTOR 14
#define MF_VECTOR 16
#define AC_VECTOR 17
#define MC_VECTOR 18
#define XM_VECTOR 19
#define VE_VECTOR 20
#define VE_VECTOR_KERN 21

#define SIG_BOUNCE SIGCHLD
/*
 * Sentry use execption 20 to simulate virtulization exception.
 */
#define VIRTUAL_EXCEPTION_VECTOR VE_VECTOR
#define VIRTUAL_EXCEPTION_VECTOR_KERN VE_VECTOR_KERN

int slimvm_signal_handler(struct vmx_vcpu *vcpu);
int slimvm_exception_handler(u32 intr_info, struct vmx_vcpu *vcpu);
void slimvm_inject_vector(struct vmx_vcpu *vcpu, u64 vector);
void slimvm_inject_nmi(struct vmx_vcpu *vcpu);

void exceptions_restore_guest_regs(struct vmx_vcpu *vcpu);

#endif /* _EXCEPTION_H */
