# exe.dev + agentsh Integration Demo

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Demonstrate agentsh security governance running inside an exe.dev VM, matching the scope of the E2B demo but using exe.dev's SSH-based API.

**Architecture:** No SDK exists for exe.dev — all VM operations go through SSH commands (`ssh exe.dev new`, `ssh vmname.exe.xyz <cmd>`, `ssh exe.dev cp`). We wrap these in a thin TypeScript helper that shells out via `child_process.execSync/exec`. agentsh is installed at runtime on a bare `ubuntu:22.04` image before anything else runs. Tests exercise the same security categories as the E2B demo: installation, server health, shell shim, policy evaluation, security diagnostics, command blocking, network policy, environment filtering, file I/O enforcement, multi-context blocking, and FUSE soft-delete.

**Tech Stack:** TypeScript, tsx, dotenv, Node.js `child_process` (no external SSH library — just shells out to `ssh`/`scp`)

**Reference files:**
- E2B demo: `/home/eran/work/canyonroad/e2b-agentsh/test-template.ts` (test patterns)
- E2B startup: `/home/eran/work/canyonroad/e2b-agentsh/agentsh-startup.sh` (server boot sequence)
- E2B config: `/home/eran/work/canyonroad/e2b-agentsh/config.yaml`
- E2B policy: `/home/eran/work/canyonroad/e2b-agentsh/default.yaml`
- Daytona demo: `/home/eran/work/canyonroad/daytona-test/example.py`

---

## File Structure

```
agentsh-exe.dev/
├── package.json              # deps: dotenv, tsx, typescript
├── tsconfig.json             # TypeScript config
├── .env.example              # documents required env vars (none for exe.dev — uses SSH keys)
├── .gitignore                # node_modules, .env, dist
├── config.yaml               # agentsh server config (adapted from E2B version for exe.dev)
├── default.yaml              # agentsh security policy (adapted from E2B — replace E2B-specific rules with exe.dev equivalents)
├── exe.ts                    # thin wrapper: create/destroy VM, run commands, copy files via SSH
├── setup.ts                  # installs agentsh on a fresh VM (deps, deb, config, server start, shim)
├── test-agentsh.ts           # security test suite (port of E2B's test-template.ts)
└── README.md                 # documentation
```

---

### Task 1: Project Scaffolding

**Files:**
- Create: `package.json`
- Create: `tsconfig.json`
- Create: `.gitignore`
- Create: `.env.example`

- [ ] **Step 1: Create package.json**

```json
{
  "name": "agentsh-exe-dev",
  "private": true,
  "type": "module",
  "scripts": {
    "test": "npx tsx test-agentsh.ts",
    "setup": "npx tsx setup.ts"
  },
  "dependencies": {
    "dotenv": "^17.2.3",
    "tsx": "^4.21.0",
    "typescript": "^5.9.3"
  }
}
```

- [ ] **Step 2: Create tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "outDir": "dist"
  },
  "include": ["*.ts"]
}
```

- [ ] **Step 3: Create .gitignore**

```
node_modules/
dist/
.env
```

- [ ] **Step 4: Create .env.example**

```bash
# exe.dev uses your SSH key for auth — no API key needed.
# Optional: override VM name (default: agentsh-test)
# EXE_VM_NAME=agentsh-test
```

- [ ] **Step 5: Install dependencies**

Run: `cd /home/eran/work/canyonroad/agentsh-exe.dev && npm install`

- [ ] **Step 6: Commit**

```bash
git add package.json tsconfig.json .gitignore .env.example
git commit -m "chore: scaffold exe.dev agentsh demo project"
```

---

### Task 2: exe.dev SSH Wrapper (`exe.ts`)

**Files:**
- Create: `exe.ts`

This is the thin wrapper over exe.dev's SSH-based API. It provides:
- `createVM(name, image)` — runs `ssh exe.dev new --name=X --image=Y --command=none --json`
- `destroyVM(name)` — runs `ssh exe.dev rm X`
- `run(vm, cmd)` — runs `ssh root@<vm>.exe.xyz <cmd>` and returns `{exitCode, stdout, stderr}`
- `copyToVM(vm, localPath, remotePath)` — runs `scp localPath root@<vm>.exe.xyz:remotePath`
- `waitForSSH(vm)` — polls until SSH is reachable

- [ ] **Step 1: Write exe.ts**

```typescript
import { execSync, ExecSyncOptionsWithStringEncoding } from 'child_process'

export interface VMInfo {
  vm_name: string
  ssh_dest: string
  https_url: string
  status: string
  region: string
}

export interface ExecResult {
  exitCode: number
  stdout: string
  stderr: string
}

const SSH_OPTS = '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR'
const EXEC_OPTS: ExecSyncOptionsWithStringEncoding = { encoding: 'utf-8', timeout: 120_000 }

function sshExeDev(args: string): string {
  return execSync(`ssh ${SSH_OPTS} exe.dev ${args}`, { ...EXEC_OPTS, timeout: 60_000 }).trim()
}

export function createVM(name: string, image: string = 'ubuntu:22.04'): VMInfo {
  const raw = sshExeDev(`new --name=${name} --image=${image} --command=none --json`)
  return JSON.parse(raw)
}

export function destroyVM(name: string): void {
  try {
    sshExeDev(`rm ${name}`)
  } catch {
    // ignore — VM may already be gone
  }
}

export function listVMs(): VMInfo[] {
  const raw = sshExeDev('ls --json')
  return JSON.parse(raw)
}

export function run(sshDest: string, cmd: string, timeoutMs: number = 120_000): ExecResult {
  try {
    const stdout = execSync(
      `ssh ${SSH_OPTS} root@${sshDest} ${JSON.stringify(cmd)}`,
      { ...EXEC_OPTS, timeout: timeoutMs, stdio: ['pipe', 'pipe', 'pipe'] }
    )
    return { exitCode: 0, stdout: stdout.toString(), stderr: '' }
  } catch (err: any) {
    return {
      exitCode: err.status ?? 1,
      stdout: (err.stdout ?? '').toString(),
      stderr: (err.stderr ?? '').toString(),
    }
  }
}

export function copyToVM(sshDest: string, localPath: string, remotePath: string): void {
  execSync(
    `scp ${SSH_OPTS} ${localPath} root@${sshDest}:${remotePath}`,
    { ...EXEC_OPTS, timeout: 60_000 }
  )
}

export function waitForSSH(sshDest: string, maxAttempts: number = 30, intervalMs: number = 2000): void {
  for (let i = 1; i <= maxAttempts; i++) {
    const r = run(sshDest, 'echo ssh-ready', 10_000)
    if (r.exitCode === 0 && r.stdout.includes('ssh-ready')) return
    if (i < maxAttempts) {
      console.log(`  Waiting for SSH... (${i}/${maxAttempts})`)
      execSync(`sleep ${intervalMs / 1000}`)
    }
  }
  throw new Error(`SSH not reachable after ${maxAttempts} attempts`)
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd /home/eran/work/canyonroad/agentsh-exe.dev && npx tsx -e "import './exe.ts'; console.log('ok')"`
Expected: `ok`

- [ ] **Step 3: Commit**

```bash
git add exe.ts
git commit -m "feat: add exe.dev SSH wrapper (create, destroy, run, copy)"
```

---

### Task 3: agentsh Policy Files (`config.yaml`, `default.yaml`)

**Files:**
- Create: `config.yaml` — adapt from E2B version (`/home/eran/work/canyonroad/e2b-agentsh/config.yaml`), replacing E2B-specific settings
- Create: `default.yaml` — adapt from E2B version (`/home/eran/work/canyonroad/e2b-agentsh/default.yaml`), replacing E2B-specific rules with exe.dev equivalents

Key changes from E2B:
- `config.yaml`: workspace paths use `/root` instead of `/home/user`; remove E2B-specific cgroups/seccomp references
- `default.yaml`: replace `block-e2b-internals` and `block-e2b-interference` rules with `block-exe-dev-internals` (block shelley/envd if present); workspace paths `/root` and `/workspace`; user is `root`

- [ ] **Step 1: Create config.yaml**

Copy from `/home/eran/work/canyonroad/e2b-agentsh/config.yaml` and adapt:
- Change comments from "E2B sandbox" to "exe.dev VM"
- Keep all functional settings the same (FUSE deferred, seccomp, network interception, DLP)
- The config is provider-agnostic — minimal changes needed

- [ ] **Step 2: Create default.yaml**

Copy from `/home/eran/work/canyonroad/e2b-agentsh/default.yaml` and adapt:
- Replace `block-e2b-internals` with `block-exe-dev-internals` (block `/usr/bin/shelley`, exe.dev-specific paths)
- Replace `block-e2b-interference` with `block-exe-dev-interference`
- Replace `block-e2b-internal` network rule with equivalent for exe.dev
- Update workspace paths: add `/root` alongside `/workspace` and `${PROJECT_ROOT}`
- Update description to mention exe.dev

- [ ] **Step 3: Commit**

```bash
git add config.yaml default.yaml
git commit -m "feat: add agentsh config and policy for exe.dev"
```

---

### Task 4: Setup Script (`setup.ts`)

**Files:**
- Create: `setup.ts`

This script creates a VM and fully installs agentsh before anything else runs. The sequence mirrors the E2B template build + startup script:

1. Create VM with `--command=none` (nothing auto-starts)
2. Wait for SSH
3. Install apt dependencies (curl, jq, libseccomp2, fuse3, sudo, python3)
4. Download + install agentsh deb
5. Create directories
6. Copy config.yaml and default.yaml
7. Start agentsh server
8. Wait for health check
9. Install shell shim
10. Print ready message

- [ ] **Step 1: Write setup.ts**

```typescript
import 'dotenv/config'
import { createVM, destroyVM, run, copyToVM, waitForSSH, type VMInfo } from './exe.ts'
import path from 'path'

const AGENTSH_VERSION = 'v0.16.5'
const AGENTSH_REPO = 'erans/agentsh'
const DEB_ARCH = 'amd64'
const VM_NAME = process.env.EXE_VM_NAME || 'agentsh-test'
const IMAGE = 'ubuntu:22.04'

function step(msg: string) { console.log(`\n>>> ${msg}`) }

export async function setupAgentsh(vmName: string = VM_NAME): Promise<VMInfo> {
  step(`Creating exe.dev VM: ${vmName} (image: ${IMAGE})`)
  const vm = createVM(vmName, IMAGE)
  const dest = vm.ssh_dest
  console.log(`  VM created: ${vm.vm_name} (${vm.ssh_dest})`)

  step('Waiting for SSH...')
  waitForSSH(dest)

  step('Installing dependencies...')
  const r1 = run(dest, 'apt-get update && apt-get install -y --no-install-recommends ca-certificates curl jq libseccomp2 sudo fuse3 python3 && rm -rf /var/lib/apt/lists/*', 180_000)
  if (r1.exitCode !== 0) throw new Error(`apt install failed: ${r1.stderr}`)

  step(`Downloading agentsh ${AGENTSH_VERSION}...`)
  const version = AGENTSH_VERSION.replace(/^v/, '')
  const deb = `agentsh_${version}_linux_${DEB_ARCH}.deb`
  const url = `https://github.com/${AGENTSH_REPO}/releases/download/${AGENTSH_VERSION}/${deb}`
  const r2 = run(dest, `curl -fsSL -L "${url}" -o /tmp/agentsh.deb && dpkg -i /tmp/agentsh.deb && rm -f /tmp/agentsh.deb && agentsh --version`, 120_000)
  if (r2.exitCode !== 0) throw new Error(`agentsh install failed: ${r2.stderr}`)
  console.log(`  ${r2.stdout.trim()}`)

  step('Creating directories...')
  run(dest, 'mkdir -p /etc/agentsh/policies /var/lib/agentsh/quarantine /var/lib/agentsh/sessions /var/log/agentsh')

  step('Copying config and policy files...')
  const dir = path.dirname(new URL(import.meta.url).pathname)
  copyToVM(dest, path.join(dir, 'config.yaml'), '/etc/agentsh/config.yaml')
  copyToVM(dest, path.join(dir, 'default.yaml'), '/etc/agentsh/policies/default.yaml')

  step('Configuring FUSE...')
  run(dest, 'chmod 600 /dev/fuse 2>/dev/null || true')
  run(dest, 'echo "user_allow_other" >> /etc/fuse.conf')

  step('Starting agentsh server...')
  run(dest, 'agentsh server >> /var/log/agentsh/server.log 2>&1 & disown')

  step('Waiting for server health...')
  let healthy = false
  for (let i = 1; i <= 15; i++) {
    const r = run(dest, 'curl -sf http://127.0.0.1:18080/health', 5_000)
    if (r.exitCode === 0 && r.stdout.includes('ok')) { healthy = true; break }
    console.log(`  Health check ${i}/15...`)
    run(dest, 'sleep 1')
  }
  if (!healthy) throw new Error('agentsh server did not become healthy')

  step('Installing shell shim...')
  const r3 = run(dest, 'agentsh shim install-shell --root / --shim /usr/bin/agentsh-shell-shim --bash --i-understand-this-modifies-the-host')
  if (r3.exitCode !== 0) throw new Error(`shim install failed: ${r3.stderr}`)

  step('Warming up shim...')
  run(dest, '/bin/bash -c "echo shim-warmup-ok" 2>/dev/null || true')

  step('agentsh is ready!')
  console.log(`  SSH: ssh root@${dest}`)
  console.log(`  HTTPS: ${vm.https_url}`)

  return vm
}

// Run directly
if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('setup.ts')) {
  setupAgentsh().catch(err => {
    console.error('Setup failed:', err)
    process.exit(1)
  })
}
```

- [ ] **Step 2: Test that setup.ts compiles**

Run: `cd /home/eran/work/canyonroad/agentsh-exe.dev && npx tsx -e "import './setup.ts'; console.log('compiles ok')"`
Expected: `compiles ok` (won't actually create a VM — just verifies imports)

- [ ] **Step 3: Commit**

```bash
git add setup.ts
git commit -m "feat: add agentsh setup script for exe.dev VMs"
```

---

### Task 5: Test Suite (`test-agentsh.ts`)

**Files:**
- Create: `test-agentsh.ts`

Ports the E2B test suite (`/home/eran/work/canyonroad/e2b-agentsh/test-template.ts`) to use exe.dev. Key differences:
- Uses `exe.ts` wrapper instead of E2B SDK
- Runs setup first (or connects to existing VM)
- User is `root` (exe.dev default for ubuntu:22.04) instead of `user`
- Uses `run()` for direct SSH commands and agentsh session API via curl (same pattern as E2B)
- No attack simulation (deferred per user request)

Test categories (matching E2B):
1. Installation — agentsh binary, version
2. Server & Configuration — health, process, policy/config files, FUSE/seccomp config
3. Shell Shim — statically linked, bash.real preserved, echo/python through shim
4. Policy Evaluation — static `agentsh debug policy-test` for sudo/echo/workspace/tmp/credentials
5. Security Diagnostics — `agentsh detect` for seccomp, cgroups_v2, landlock, ebpf
6. Command Blocking — sudo/su/ssh/kill/rm-rf blocked, echo/python3/git allowed
7. Network Policy — npm allowed, metadata/evil.com/private-networks/github.com blocked
8. Environment Policy — sensitive vars filtered, safe vars present
9. File I/O — workspace/tmp writes allowed, /etc/usr writes blocked, credential paths blocked
10. Multi-Context Blocking — env sudo, xargs sudo, find -exec sudo, python subprocess sudo
11. FUSE Soft Delete — create/delete/trash-list/restore

- [ ] **Step 1: Write test-agentsh.ts**

The structure follows E2B's test-template.ts exactly but replaces `sbx.commands.run()` with `run(sshDest, cmd)`. The `exec()` and `execSh()` helpers work identically — they hit the agentsh session API via curl inside the VM.

Key adaptations:
- Workspace path: `/root` instead of `/home/user`
- SSH dest comes from `vm.ssh_dest`
- Setup is called at start, or connects to existing VM via `EXE_VM_NAME` env var
- Cleanup destroys VM unless `KEEP_VM=1` is set

Full code: port all 12 test sections from E2B's test-template.ts, adapting paths and using `run()` from `exe.ts`.

- [ ] **Step 2: Verify it compiles**

Run: `cd /home/eran/work/canyonroad/agentsh-exe.dev && npx tsx --no-warnings -e "import './test-agentsh.ts'"`
Note: This will attempt to run — verify at least the imports resolve.

- [ ] **Step 3: Commit**

```bash
git add test-agentsh.ts
git commit -m "feat: add agentsh security test suite for exe.dev"
```

---

### Task 6: README

**Files:**
- Create: `README.md`

Cover:
- What this is (agentsh + exe.dev defense-in-depth demo)
- Architecture diagram (same as E2B README style)
- Prerequisites (Node.js, SSH key registered with exe.dev, exe.dev account)
- Quick start (`npm install`, `npx tsx setup.ts`, `npx tsx test-agentsh.ts`)
- What the tests cover
- Cleanup (`ssh exe.dev rm agentsh-test`)

- [ ] **Step 1: Write README.md**
- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add README for exe.dev agentsh demo"
```

---

### Task 7: End-to-End Verification

- [ ] **Step 1: Run setup against real exe.dev**

Run: `cd /home/eran/work/canyonroad/agentsh-exe.dev && npx tsx setup.ts`
Expected: VM created, agentsh installed, server healthy, shim installed, "agentsh is ready!"

- [ ] **Step 2: Run test suite**

Run: `cd /home/eran/work/canyonroad/agentsh-exe.dev && npx tsx test-agentsh.ts`
Expected: All tests pass (or document any exe.dev-specific differences)

- [ ] **Step 3: Fix any failures**

Iterate on config.yaml, default.yaml, or test assertions based on actual exe.dev behavior.

- [ ] **Step 4: Cleanup test VM**

Run: `ssh exe.dev rm agentsh-test`

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "fix: address exe.dev-specific test adjustments"
```
