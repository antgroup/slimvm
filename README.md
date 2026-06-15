# SlimVM

## What is SlimVM?

SlimVM is a Linux kernel module specifically designed for [gVisor][gvisor] to
provide hardware virtualization capabilities using Intel VT-x (VMX) and
AMD/Hygon SVM.

SlimVM is implemented based on [DUNE][dune].

## Why does SlimVM exist?

Accelerate gVisor guest kernel sentry's system calls to the host kernel.

### How it works

In a traditional gVisor + KVM setup, every guest syscall triggers a full VM exit,
returns to the userspace sentry process, which then re-enters the kernel via a
regular syscall — multiple expensive context switches on every operation:

```
gr0 (guest ring 0) -> hr0 (host ring 0, vm_exit)
                   -> hr3 (host ring 3, ioctl return)
                   -> hr0 (re-invoke syscall)
```

SlimVM eliminates this overhead. When the guest executes a `VMCALL` (Intel) or
`VMMCALL` (AMD/Hygon), the VM exits into root mode where SlimVM directly invokes
the host kernel's syscall handler, then immediately resumes the guest — no
userspace round-trip:

```
gr0 (guest ring 0) -> hr0 (vmcall/vmmcall + direct function call)
```

This eliminates expensive context switches between user space and kernel space.

## Features

- **Hardware Virtualization**: Leverages Intel VT-x (VMX/EPT) and AMD/Hygon SVM (NPT)
- **System Call Interception**: Intercepts and handles syscalls via `vmcall`/`vmmcall` instructions
- **Memory Isolation**: Uses EPT (Intel) / NPT (AMD) for guest physical to host physical address translation
- **Seccomp Integration**: Supports seccomp-BPF filters for syscall filtering
- **Multi-Version Support**: Supports Linux kernels 5.10.y, 5.15.y, and 6.1.y

## Architecture Support

| Architecture           | Status    |
| ---------------------- | --------- |
| x86_64 (Intel VMX)     | Supported |
| x86_64 (AMD/Hygon SVM) | Supported |
| ARM                    | Planned   |

SlimVM is built as a single self-contained module that links both the Intel
(VMX) and AMD/Hygon (SVM) engines. At load time it detects the CPU vendor and
binds the matching engine through a vendor operations table
(`struct slimvm_engine_ops`), mirroring how Linux KVM shares a common core
between `kvm-intel.ko` and `kvm-amd.ko`.

## Module Conflict

**Notice**: SlimVM conflicts with the `kvm` module because both require exclusive
access to the CPU virtualization hardware. You must remove `kvm` before using
SlimVM:

```sh
# Intel
sudo rmmod kvm_intel kvm
# AMD / Hygon
sudo rmmod kvm_amd kvm
```

## Installing from Source

### Requirements

Make sure the following dependencies are installed:

* Linux kernel headers for your target version (5.10.y, 5.15.y, or 6.1.y)
* GCC and standard build tools
* Root access for module installation

On Debian/Ubuntu:
```sh
sudo apt-get install build-essential linux-headers-$(uname -r)
```

On RHEL/CentOS:
```sh
sudo yum install gcc kernel-devel-$(uname -r)
```

### Building

Build for the current running kernel:
```sh
make
```

Build for a specific kernel version (when headers are installed):
```sh
make BUILD_KERNEL=6.1.0
```

Build using kernel source tree (for cross-compilation or custom kernels):
```sh
# Make sure the kernel source is prepared:
# cd /path/to/linux-6.1.y && make modules_prepare

make KSRC=/path/to/linux-6.1.y BUILD_KERNEL=6.1.y
```

Build with debug logging enabled (activates `pr_debug` output in dmesg):
```sh
make DEBUG=y
```

### Installing

```sh
sudo make install
```

### Loading the Module

```sh
sudo insmod slimvm.ko
# or
sudo modprobe slimvm
```

Check if loaded successfully:
```sh
lsmod | grep slimvm
dmesg | tail -20
```

### Unloading the Module

```sh
sudo rmmod slimvm
```

### Cleaning Build Artifacts

```sh
make clean
```

## Monitoring

SlimVM exposes runtime information via sysctl and procfs:

| Interface                              | Mode       | Description                           |
| -------------------------------------- | ---------- | ------------------------------------- |
| `/proc/sys/slimvm/slimvm_vcpu_num`     | read-only  | Total vCPU count across all instances |
| `/proc/sys/slimvm/slimvm_vm_num`       | read-only  | Total VM instance count               |
| `/proc/sys/slimvm/slimvm_debug_enable` | read-write | Toggle runtime debug logging          |
| `/proc/slimvm/vm_mem_stat`             | read-only  | Per-instance nested-PT (EPT/NPT) memory statistics |

Example:
```sh
# Check number of active instances
cat /proc/sys/slimvm/slimvm_vm_num

# Enable runtime debug logging
echo 1 | sudo tee /proc/sys/slimvm/slimvm_debug_enable

# View per-instance EPT statistics (SID, 4K pages, 2M pages, invalidation stats)
cat /proc/slimvm/vm_mem_stat
```

## Uninstalling

```sh
sudo make uninstall
```

## Citation

If you use SlimVM in your research, please cite our EuroSys 2026 paper:

```bibtex
@inproceedings{10.1145/3767295.3769332,
  author    = {Chai, Xiaohu and Hu, Keyang and Tan, Jianfeng and Bie, Tiwei and Tan, Guotao and Zhou, Tianyu and Shen, Anqi and Yang, Xinyao and Chen, Xin and Wang, Xu and Yu, Feng and He, Zhengyu and Du, Dong and Xia, Yubin and Chen, Kang and Chen, Yu},
  title     = {{SKernel}: An Elastic and Efficient Secure Container System at Scale with a Split-Kernel Architecture},
  booktitle = {Proceedings of the European Conference on Computer Systems (EuroSys '26)},
  year      = {2026},
  location  = {Edinburgh, Scotland, UK},
  numpages  = {19},
  publisher = {ACM},
  address   = {New York, NY, USA},
  doi       = {10.1145/3767295.3769332},
  url       = {https://doi.org/10.1145/3767295.3769332},
  note      = {April 27--30, 2026}
}
```

## License

Licensed under GPLv2, with some files dual-licensed as GPL-2.0 OR MIT (derived from [DUNE][dune]). See [LICENSE](LICENSE) for details.

## References

- [gVisor][gvisor] - Google's container sandbox runtime
- [DUNE][dune] - Sandboxing with Intel VT-x

[gvisor]: https://github.com/google/gvisor
[dune]: https://github.com/project-dune/dune
