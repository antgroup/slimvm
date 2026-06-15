#ifndef __VMCB_OPS_H
#define __VMCB_OPS_H

#include <asm/svm.h>

struct vmcb_config {
	int size;
	int order;
};

#endif /* __VMCB_OPS_H */
