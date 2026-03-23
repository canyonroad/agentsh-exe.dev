# agentsh + exe.dev

Runtime security governance for AI agents using [agentsh](https://github.com/canyonroad/agentsh) v0.16.5 with [exe.dev](https://exe.dev) VMs.

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
|  |  |  - File I/O is intercepted (FUSE)           |  |  |
|  |  |  - Secrets are redacted from output         |  |  |
|  |  |  - All actions are audited                  |  |  |
|  |  +---------------------------------------------+  |  |
|  +---------------------------------------------------+  |
+---------------------------------------------------------+
```

## What agentsh Adds

| exe.dev Provides | agentsh Adds |
|------------------|--------------|
| VM isolation (Ubuntu 22.04) | Command blocking (seccomp) |
| Root SSH access | File I/O policy (FUSE) |
| Network isolation | Domain allowlist/blocklist |
| Persistent environment | Cloud metadata blocking |
| SSH-based API | Environment variable filtering |
| | Secret detection and redaction (DLP) |
| | Bash builtin interception (BASH_ENV) |
| | Landlock execution restrictions |
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

# Run the full test suite
npx tsx test-agentsh.ts
```

### Cleanup

When done, destroy the VM:

```bash
ssh exe.dev rm agentsh-test
```

## What the Tests Cover

The `test-agentsh.ts` script provisions an exe.dev VM, installs agentsh, and runs security tests across 11 categories:

1. **Installation** -- agentsh binary present, version correct, seccomp linkage
2. **Server & config** -- health check, policy and config files in place, FUSE enabled, seccomp active
3. **Shell shim** -- shim installed, `bash.real` preserved, commands routed through policy engine
4. **Policy evaluation** -- static `policy-test` for sudo, echo, workspace, credentials, /etc
5. **Security diagnostics** -- `agentsh detect`: seccomp, cgroups_v2, landlock, ebpf available
6. **Command blocking** -- sudo, su, ssh, kill, rm -rf blocked; echo, python3, git allowed
7. **Network blocking** -- npmjs.org allowed; metadata (169.254.169.254), evil.com, private networks blocked
8. **Environment policy** -- AWS/ANTHROPIC/SECRET vars filtered; HOME, PATH present; BASH_ENV set
9. **File I/O** -- workspace and /tmp writes allowed; /etc, /usr/bin writes blocked via FUSE; symlink escape blocked
10. **Multi-context blocking** -- sudo blocked via env, xargs, find -exec, Python subprocess, and os.system
11. **Credential blocking** -- ~/.ssh/id_rsa, ~/.aws/credentials, /proc/1/environ blocked

## How It Works

exe.dev provides no SDK -- VMs are accessed purely over SSH. The `exe.ts` wrapper translates API calls into SSH commands against the `exe.dev` gateway host:

```
npx tsx setup.ts
       |
       v
ssh exe.dev new --name=agentsh-test   # create VM
       |
       v
ssh root@<vm-host> apt-get install …  # install deps
       |
       v
ssh root@<vm-host> dpkg -i agentsh.deb
       |
       v
scp config.yaml default.yaml -> /etc/agentsh/
       |
       v
ssh root@<vm-host> agentsh server &   # start policy engine
       |
       v
ssh root@<vm-host> agentsh shim install-shell  # replace /bin/bash
```

Once the shell shim is installed, every command that runs on the VM passes through the agentsh policy engine -- no explicit `agentsh exec` calls needed. The shim intercepts at the bash level so all shells, subshells, and script invocations are covered.

```
ssh root@<vm> "sudo whoami"
                   |
                   v
          +-------------------+
          |  Shell Shim       |  /bin/bash -> agentsh-shell-shim
          |  (intercepts)     |
          +--------+----------+
                   |
                   v
          +-------------------+
          |  agentsh server   |  Policy evaluation + seccomp
          |  (port 18080)     |  + FUSE file interception
          +--------+----------+
                   |
             +-----+------+
             v            v
       +----------+  +----------+
       |  ALLOW   |  |  BLOCK   |
       | exit: 0  |  | exit: 126|
       +----------+  +----------+
```

Unlike E2B or similar platforms, agentsh is not baked into a custom image. It is installed at runtime on a fresh `ubuntu:22.04` VM by `setup.ts`, making the setup fully reproducible and independent of any sandbox-specific tooling.

## Configuration

Security policy is defined in two files:

- **`config.yaml`** -- Server configuration: network interception, [DLP patterns](https://www.agentsh.org/docs/#llm-proxy), LLM proxy, [FUSE settings](https://www.agentsh.org/docs/#fuse), [seccomp](https://www.agentsh.org/docs/#seccomp), resource limits
- **`default.yaml`** -- [Policy rules](https://www.agentsh.org/docs/#policy-reference): [command rules](https://www.agentsh.org/docs/#command-rules), [network rules](https://www.agentsh.org/docs/#network-rules), [file rules](https://www.agentsh.org/docs/#file-rules), [environment policy](https://www.agentsh.org/docs/#environment-policy)

See the [agentsh documentation](https://www.agentsh.org/docs/) for the full policy reference.

## Project Structure

```
agentsh-exe.dev/
├── exe.ts               # SSH wrapper: createVM, destroyVM, run, copyToVM, waitForSSH
├── setup.ts             # Provisions a VM and installs agentsh end-to-end
├── test-agentsh.ts      # Security test suite (11 categories)
├── config.yaml          # agentsh server config (FUSE, seccomp, DLP, network proxy)
├── default.yaml         # Security policy (commands, network, files, env vars)
└── package.json
```

## Related Projects

- [agentsh](https://github.com/canyonroad/agentsh) -- Runtime security for AI agents ([docs](https://www.agentsh.org/docs/))
- [exe.dev](https://exe.dev) -- SSH-native cloud VM platform
- [agentsh + E2B](https://github.com/canyonroad/e2b-agentsh) -- The same governance layer on E2B sandboxes

## License

MIT
