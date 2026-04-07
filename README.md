# agentsh + exe.dev

Runtime security governance for AI agents using [agentsh](https://github.com/canyonroad/agentsh) v0.17.0 with [exe.dev](https://exe.dev) VMs. 90 security tests across 13 categories.

## Why agentsh + exe.dev?

**exe.dev provides isolation. agentsh provides governance.**

exe.dev VMs give AI agents a secure, isolated compute environment. But isolation alone doesn't prevent an agent from:

- **Exfiltrating data** to unauthorized endpoints
- **Accessing cloud metadata** (AWS/GCP/Azure credentials at 169.254.169.254)
- **Leaking secrets** in outputs (API keys, tokens, PII)
- **Running dangerous commands** (sudo, ssh, kill, nc)
- **Reaching internal networks** (10.x, 172.16.x, 192.168.x)
- **Deleting workspace files** permanently

agentsh adds the governance layer that controls what agents can do inside the VM, providing defense-in-depth:

```
+---------------------------------------------------------+
|  exe.dev VM (Isolation)                                  |
|  +---------------------------------------------------+  |
|  |  agentsh (Governance)                             |  |
|  |  +---------------------------------------------+  |  |
|  |  |  AI Agent                                   |  |  |
|  |  |  - Commands are policy-checked              |  |  |
|  |  |  - Network requests are filtered            |  |  |
|  |  |  - File I/O is intercepted (FUSE+Landlock)  |  |  |
|  |  |  - Child processes are traced (ptrace)      |  |  |
|  |  |  - Secrets are redacted from output         |  |  |
|  |  |  - All actions are audited                  |  |  |
|  |  +---------------------------------------------+  |  |
|  +---------------------------------------------------+  |
+---------------------------------------------------------+
```

## What agentsh Adds

| exe.dev Provides | agentsh Adds |
|------------------|--------------|
| VM isolation (Ubuntu 22.04) | Command blocking (policy precheck) |
| Root SSH access | Child process interception (ptrace execve) |
| Network isolation | File I/O policy (FUSE + seccomp file_monitor) |
| Persistent environment | Kernel-level path restriction (Landlock v5) |
| SSH-based API | Domain allowlist/blocklist |
| | Cloud metadata blocking |
| | Environment variable filtering |
| | Secret detection and redaction (DLP) |
| | Bash builtin interception (BASH_ENV) |
| | Shell shim enforcement (shim.conf force) |
| | Soft-delete file quarantine |
| | LLM request auditing |
| | Complete audit logging |

## Quick Start

### Prerequisites

- Node.js 18+
- [exe.dev](https://exe.dev) account with an SSH key registered
- SSH access to `exe.dev` working from your terminal (`ssh exe.dev ls`)

### Install and Run

```bash
git clone https://github.com/canyonroad/agentsh-exe.dev
cd agentsh-exe.dev
npm install

# Provision a VM and install agentsh (takes ~2 minutes)
npx tsx setup.ts

# Run the full test suite (90 tests)
npx tsx test-agentsh.ts
```

### Cleanup

When done, destroy the VM:

```bash
ssh exe.dev rm agentsh-test
```

## What the Tests Cover

The `test-agentsh.ts` script provisions an exe.dev VM, installs agentsh, and runs 90 security tests across 13 categories:

1. **Installation** -- agentsh binary present, seccomp linkage
2. **Server & config** -- health check, policy and config files in place, FUSE and seccomp enabled
3. **Shell shim** -- shim installed, `bash.real` preserved, commands routed through policy engine
4. **Shell shim enforcement** -- direct SSH tests: sudo/su/ssh/kill blocked, echo/python3 allowed, /etc writes blocked, evil.com blocked, env sudo blocked
5. **Policy evaluation** -- static `policy-test` for sudo, echo, workspace, credentials, /etc, soft-delete
6. **Security diagnostics** -- `agentsh detect`: seccomp, ptrace, cgroups, landlock, capability-drop
7. **Security diagnostics (session)** -- FUSE mount active, HTTPS_PROXY set
8. **Command blocking** -- sudo, su, ssh, kill, rm -rf blocked; echo, python3, git allowed
9. **Network blocking** -- npmjs.org allowed; metadata (169.254.169.254), evil.com, private networks, github.com blocked (default-deny)
10. **Environment policy** -- AWS/OPENAI/SECRET vars filtered; HOME, PATH present; BASH_ENV set
11. **File I/O** -- workspace and /tmp writes allowed; /etc, /usr/bin writes blocked via FUSE + Landlock; symlink escape blocked; credential paths (/root/.ssh, /root/.aws, /proc/1/environ) blocked
12. **Multi-context blocking** -- sudo blocked via env, xargs, find -exec, nested scripts, direct /usr/bin/sudo, Python subprocess, and os.system (ptrace execve interception)
13. **FUSE soft delete** -- workspace file quarantine and recovery via `agentsh trash`

## How It Works

exe.dev has no SDK -- VMs are accessed purely over SSH. The `exe.ts` wrapper translates API calls into SSH commands through the exe.dev gateway:

```
npx tsx setup.ts
       |
       v
ssh exe.dev new --name=agentsh-test   # create VM
       |
       v
ssh exe.dev ssh agentsh-test ...      # install deps + agentsh deb
       |
       v
base64-encode config files over SSH   # copy config.yaml + default.yaml
       |
       v
ssh exe.dev ssh agentsh-test agentsh server &   # start policy engine
       |
       v
ssh exe.dev ssh agentsh-test agentsh shim install-shell  # replace /bin/bash
       |
       v
echo "force=true" > /etc/agentsh/shim.conf   # enforce policy without TTY
```

Once the shell shim is installed, every command that runs on the VM passes through the agentsh policy engine -- no explicit `agentsh exec` calls needed.

### Security enforcement stack

exe.dev VMs (kernel 6.12) provide full security primitive support. agentsh uses all of them:

| Layer | Mechanism | What it enforces |
|-------|-----------|-----------------|
| **Shell shim** | Static binary replacing /bin/bash | Routes all commands through policy engine; shim.conf forces enforcement without TTY |
| **Policy precheck** | API-level command evaluation | Blocks sudo, su, ssh, kill, rm -rf before execution |
| **Ptrace** | execve-only tracing | Catches child process escalation (env sudo, xargs sudo, Python subprocess) |
| **Landlock v5** | Kernel path restrictions | Blocks writes to /etc, /usr/bin even for root; restricts execute paths |
| **Seccomp** | file_monitor via user-notify | Enforces file_rules at syscall level |
| **FUSE** | Virtual filesystem overlay | Soft-delete quarantine for workspace files |
| **Network proxy** | Embedded HTTP/HTTPS proxy | Domain allowlist, metadata blocking, private network blocking |
| **DLP** | Pattern matching on LLM traffic | Redacts API keys, tokens, PII from outputs |

```
ssh exe.dev ssh agentsh-test "env sudo whoami"
                   |
                   v
          +-------------------+
          |  Shell Shim       |  /bin/bash -> agentsh-shell-shim
          |  (intercepts)     |
          +--------+----------+
                   |
                   v
          +-------------------+
          |  agentsh server   |  Policy precheck: /bin/bash -> ALLOW
          |  (port 18080)     |  Ptrace: traces child execve()
          +--------+----------+
                   |
                   v
          +-------------------+
          |  bash runs        |  env -> execve("/usr/bin/sudo")
          |  "env sudo"       |        |
          +--------+----------+        v
                              Ptrace intercepts execve
                              Policy check: sudo -> DENY
                              Kill process (SIGKILL)
```

Unlike other sandbox platforms, agentsh is not baked into a custom image. It is installed at runtime on a fresh `ubuntu:22.04` VM by `setup.ts`, making the setup fully reproducible and independent of any sandbox-specific tooling.

## Configuration

Security is configured through two files:

- **`config.yaml`** -- Server and enforcement configuration:
  - `sandbox.ptrace` -- execve-only tracing for child process interception
  - `sandbox.seccomp.file_monitor` -- syscall-level file I/O enforcement
  - `sandbox.fuse` -- workspace overlay with soft-delete quarantine
  - `sandbox.network` -- embedded proxy for domain filtering
  - `landlock` -- kernel-level path restrictions (read/write/execute)
  - `dlp` -- secret detection patterns (API keys, tokens, PII)
  - `proxy` -- LLM request interception and auditing
- **`default.yaml`** -- [Policy rules](https://www.agentsh.org/docs/#policy-reference): [command rules](https://www.agentsh.org/docs/#command-rules), [network rules](https://www.agentsh.org/docs/#network-rules), [file rules](https://www.agentsh.org/docs/#file-rules), [environment policy](https://www.agentsh.org/docs/#environment-policy)

See the [agentsh documentation](https://www.agentsh.org/docs/) for the full policy reference.

## Project Structure

```
agentsh-exe.dev/
├── exe.ts               # SSH wrapper: createVM, destroyVM, run, copyToVM, writeFile, waitForSSH
├── setup.ts             # Provisions a VM and installs agentsh end-to-end
├── test-agentsh.ts      # Security test suite (90 tests, 13 categories)
├── config.yaml          # agentsh server config (ptrace, seccomp, FUSE, Landlock, DLP, network)
├── default.yaml         # Security policy (commands, network, files, env vars)
└── package.json
```

## Related Projects

- [agentsh](https://github.com/canyonroad/agentsh) -- Runtime security for AI agents ([docs](https://www.agentsh.org/docs/))
- [exe.dev](https://exe.dev) -- SSH-native cloud VM platform

## License

MIT
