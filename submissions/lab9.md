# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

**Falco:** `falcosecurity/falco:0.43.1` (modern eBPF)  
**Target:** `lab9-target` (alpine:3.20)

### Baseline alert A — Terminal shell in container

```json
{"hostname":"47a99a485dc5","output":"2026-07-10T10:58:16.829043414+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=systemd command=sh -lc echo \"shell-in-container test\" terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=1104928f46ce container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"1104928f46ce","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.arg.flags":"EXE_WRITABLE|EXE_LOWER_LAYER","evt.time.iso8601":1783681096829043414,"evt.type":"execve","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"shell-in-container test\"","proc.exepath":"/bin/busybox","proc.name":"sh","proc.pname":"systemd","proc.tty":34816,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-07-10T10:58:16.829043414Z"}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)

```json
{"hostname":"47a99a485dc5","output":"2026-07-10T10:58:16.899768322+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=<NA> ggparent=<NA> gggparent=<NA> evt_type=open user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=systemd command=cat /etc/shadow terminal=0 container_id=1104928f46ce container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"1104928f46ce","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783681096899768322,"evt.type":"open","fd.name":"/etc/shadow","k8s.ns.name":null,"k8s.pod.name":null,"proc.aname[2]":null,"proc.aname[3]":null,"proc.aname[4]":null,"proc.cmdline":"cat /etc/shadow","proc.exepath":"/bin/busybox","proc.name":"cat","proc.pname":"systemd","proc.tty":0,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],"time":"2026-07-10T10:58:16.899768322Z"}
```

### Custom rule

See `labs/lab9/falco/rules/custom-rules.yaml` (also split as `custom-tmp.yaml` + `custom-cryptominer.yaml` in rules.d).

### Custom rule fired

```json
{"hostname":"47a99a485dc5","output":"2026-07-10T10:58:16.968339295+0000: Warning Write to /tmp by container (user=root container=lab9-target file=/tmp/my-write.txt cmd=sh -lc echo \"test\" > /tmp/my-write.txt) container_id=1104928f46ce container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"1104928f46ce","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783681096968339295,"fd.name":"/tmp/my-write.txt","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"test\" > /tmp/my-write.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-10T10:58:16.968339295Z"}
```

### Tuning consideration (Lecture 9 slide 8)

The `/tmp` write rule fires on legitimate temp files (logging, package managers). I would add an `exceptions:` block for known-good images or `proc.name` values (e.g. `java`, `node`) rather than weakening the base rule globally. `exceptions:` keeps the deny-by-default posture while silencing predictable noise per workload; `and not proc.name=...` is fine for one-off cases but scales worse across many services.

---

## Task 2: Conftest Policy-as-Code

**Policy:** `labs/lab9/policies/extra/hardening.rego` — 5 deny rules (runAsNonRoot, allowPrivilegeEscalation, cap drop ALL, memory limits, digest pin).

### Compliant manifest passes (`juice-hardened.yaml`)

```
5 tests, 5 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (`juice-unhardened.yaml`)

```
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container 'juice-shop' must pin image by digest (@sha256:), not tag
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container 'juice-shop' must set resources.limits.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Pod must set spec.template.spec.securityContext.runAsNonRoot to true

5 tests, 2 passed, 0 warnings, 3 failures, 0 exceptions
```

### Compose policy generalizes (`compose-security.rego`)

```
--- compose PASS ---
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

--- compose FAIL ---
FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true
4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```

### Why CI-time vs admission-time (Lecture 9 slide 9)

**CI-time** Conftest in the PR pipeline gives fast feedback before merge — no cluster credentials needed. **Admission-time** policy (Kyverno / Gatekeeper) blocks bad manifests at apply. Running both is defense in depth: CI prevents most mistakes early; admission catches manual applies or CI bypass. Falco remains the runtime layer neither replaces.

---

## Bonus: Cryptominer Detection Rule

Rule **Possible Cryptominer Activity** in `custom-cryptominer.yaml` — `evt.type=connect` + `fd.sport in (3333, 4444, …)`.

### Triggered alert

Re-trigger if log line missing after first run:

```bash
docker exec lab9-target /bin/sh -c 'nc -w 2 127.0.0.1 3333' 2>/dev/null || true
sleep 2
grep -i "Possible cryptominer" labs/lab9/falco/logs/falco.log | tail -1
```

Rule loaded successfully: `custom-cryptominer.yaml | schema validation: ok`. Paste JSON alert line after re-trigger above.

### Reflection

**Indicators:** outbound `connect` to common mining-pool ports (3333/4444/5555/7777). **Misses:** HTTPS pools, obfuscated miners, in-browser mining without classic `proc.name`. **SLA matrix:** CRITICAL cryptominer → immediate isolate/kill workload; WARNING `/tmp` rules tuned separately so on-call is not flooded.
