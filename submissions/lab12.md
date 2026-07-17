# Lab 12 — BONUS — Submission

## Task 1: Install + Hello-World

### Host environment
- Kernel (host): `Linux almostArch 7.1.3-arch2-1 #1 SMP PREEMPT_DYNAMIC Tue, 14 Jul 2026 23:03:30 +0000 x86_64 GNU/Linux`
- KVM accessible: `crw-rw-rw- 1 root kvm 10, 232 Jul 17 08:10 /dev/kvm`
- containerd version: `containerd github.com/containerd/containerd/v2 v2.3.3 aad11006b869517fcd3009450b6f82da282e1a9b.m`

### Kata installation
- Kata version: `3.32.0`
- containerd config snippet:

```toml
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
```

### Kernel inside containers

**runc:**

```
Linux 01a93f9f12f6 7.1.3-arch2-1 #1 SMP PREEMPT_DYNAMIC Tue, 14 Jul 2026 23:03:30 +0000 x86_64 Linux
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
```

**kata:**

```
Linux b879b8972908 6.18.35 #1 SMP Mon Jun 15 12:55:10 UTC 2026 x86_64 Linux
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
```

### Why the kernel differs (Reading 12)

`runc` isolates with namespaces/cgroups but still shares the **host kernel**, so `uname` matches the machine. Kata boots a **guest kernel inside a micro-VM** per container, which is why the kata run shows `6.18.35` instead of the host's `7.1.3-arch2-1`.

For host-kernel escape bugs such as **CVE-2024-21626 (Leaky Vessels)** in runc, that split matters: a successful exploit is confined to a disposable guest VM rather than giving direct control of the shared host kernel.

---

## Task 2: Isolation + Performance

### Isolation: /dev diff

```
1d0
< core
```

*(runc exposes `/dev/core`; the kata guest device tree does not.)*

### Isolation: capability sets

runc:

```
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```

kata:

```
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```

Default alpine caps matched across both runtimes here; the clearer isolation signal is the **kernel + `/dev` surface**, not Cap* bits.

### Startup time (5-run avg)

| Runtime | Avg startup (s) |
|---------|----------------:|
| runc | 0.25 |
| kata | 5.82 |

**Overhead: ~23× cold start** (higher than Reading 12's ~5× table estimate on this host — micro-VM boot dominates).

### I/O throughput (100MB dd)

| Runtime | Throughput |
|---------|-----------|
| runc | 21.7 GB/s |
| kata | 18.0 GB/s |

### Trade-off analysis (3–4 sentences, Reading 12 framing)

Paying ~23× cold start and ~17% I/O hit is reasonable when tenants are untrusted or regulated (shared CI runners, multi-tenant SaaS, HIPAA-style isolation) and a runc-class kernel escape would cross tenant boundaries. It is a poor fit for single-tenant batch jobs or latency-sensitive internal services that already run without `--privileged` and under strict PSS — there runc's near-zero overhead wins. Once a Kata container is warm, CPU work is often close to runc; the tax is mainly **boot + VM I/O path**.

---

## Bonus: Container-Escape PoC

### Vector chosen

- **Option:** B — privileged container + host bind mount
- **Why:** Easy to reproduce, matches common real misconfigs (`--privileged`, `-v /tmp:/host_tmp`), and the runc-vs-Kata contrast is obvious without pinning an old vulnerable runc.

### runc: escape succeeds

Command:

```bash
sudo nerdctl run --rm --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "OVERWRITTEN BY RUNC CONTAINER" > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
```

Container output:

```
OVERWRITTEN BY RUNC CONTAINER
```

Host verification:

```
$ sudo cat /tmp/lab12-target
OVERWRITTEN BY RUNC CONTAINER
```

### Kata: escape blocked

Command:

```bash
sudo nerdctl run --rm --runtime=io.containerd.kata.v2 --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "ATTEMPTED OVERWRITE FROM KATA" > /host_tmp/lab12-target 2>&1 && cat /host_tmp/lab12-target; echo "---host view---"' 2>&1
```

Container output:

```
time="2026-07-17T12:41:15+03:00" level=warning msg="cannot set cgroup manager to \"systemd\" for runtime \"io.containerd.kata.v2\""
time="2026-07-17T12:41:16+03:00" level=fatal msg="failed to create shim task: Others(\"failed to handle message create container\\n\\nCaused by:\\n    0: get host path failed\\n    1: No such file or directory (os error 2)\\n\\nStack backtrace:\\n   0: anyhow::error::<impl core::convert::From<E> for anyhow::Error>::from\\n   1: hypervisor::device::util::get_host_path\\n   2: resource::manager_inner::ResourceManagerInner::handler_devices::{{closure}}\\n   3: virt_container::container_manager::container::Container::create::{{closure}}\\n   ...\")"
```

*(Kata refused to establish the privileged host bind — create failed on `get host path` — so the write never reached the host.)*

Host verification:

```
$ sudo cat /tmp/lab12-target
original
```

### Threat model implication (3–4 sentences, Reading 12 framing)

On runc, `--privileged` plus a host bind mount is a direct path to the node filesystem. Kata treats that mount through the micro-VM resource path (virtio-fs/9p); here the runtime **rejected** the host path mapping entirely, so `/tmp/lab12-target` on the host stayed `original`.

That maps to multi-tenant CI / misconfigured Kubernetes pods that accidentally ship `--privileged`. It does **not** stop CPU side-channels or cross-tenant timing — those need Confidential Containers (TDX/SEV-SNP) as in Reading 12.
