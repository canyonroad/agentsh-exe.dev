import 'dotenv/config'
import { createVM, run, copyToVM, waitForSSH, type VMInfo } from './exe.ts'
import path from 'path'

const AGENTSH_VERSION = 'v0.16.8'
const AGENTSH_REPO = 'erans/agentsh'
const DEB_ARCH = 'amd64'
const VM_NAME = process.env.EXE_VM_NAME || 'agentsh-test'
const IMAGE = 'ubuntu:22.04'

function step(msg: string) { console.log(`\n>>> ${msg}`) }

export async function setupAgentsh(vmName: string = VM_NAME): Promise<VMInfo> {
  step(`Creating exe.dev VM: ${vmName} (image: ${IMAGE})`)
  const vm = createVM(vmName, IMAGE)
  console.log(`  VM created: ${vm.vm_name} (${vm.ssh_dest})`)

  step('Waiting for SSH...')
  waitForSSH(vmName)

  step('Installing dependencies...')
  const r1 = run(vmName, 'apt-get update && apt-get install -y --no-install-recommends ca-certificates curl jq libseccomp2 sudo fuse3 python3 file findutils git && rm -rf /var/lib/apt/lists/*', 180_000)
  if (r1.exitCode !== 0) throw new Error(`apt install failed: ${r1.stderr}`)

  step(`Downloading agentsh ${AGENTSH_VERSION}...`)
  const version = AGENTSH_VERSION.replace(/^v/, '')
  const deb = `agentsh_${version}_linux_${DEB_ARCH}.deb`
  const url = `https://github.com/${AGENTSH_REPO}/releases/download/${AGENTSH_VERSION}/${deb}`
  const r2 = run(vmName, `curl -fsSL -L "${url}" -o /tmp/agentsh.deb && dpkg -i /tmp/agentsh.deb && rm -f /tmp/agentsh.deb && agentsh --version`, 120_000)
  if (r2.exitCode !== 0) throw new Error(`agentsh install failed: ${r2.stderr}`)
  console.log(`  ${r2.stdout.trim()}`)

  step('Creating directories...')
  run(vmName, 'mkdir -p /etc/agentsh/policies /var/lib/agentsh/quarantine /var/lib/agentsh/sessions /var/log/agentsh')

  step('Copying config and policy files...')
  const dir = path.dirname(new URL(import.meta.url).pathname)
  copyToVM(vmName, path.join(dir, 'config.yaml'), '/etc/agentsh/config.yaml')
  copyToVM(vmName, path.join(dir, 'default.yaml'), '/etc/agentsh/policies/default.yaml')

  step('Configuring FUSE...')
  run(vmName, 'chmod 600 /dev/fuse 2>/dev/null || true')
  run(vmName, 'echo "user_allow_other" >> /etc/fuse.conf')

  step('Starting agentsh server...')
  run(vmName, 'agentsh server >> /var/log/agentsh/server.log 2>&1 & disown')

  step('Waiting for server health...')
  let healthy = false
  for (let i = 1; i <= 15; i++) {
    const r = run(vmName, 'curl -sf http://127.0.0.1:18080/health', 5_000)
    if (r.exitCode === 0 && r.stdout.includes('ok')) { healthy = true; break }
    console.log(`  Health check ${i}/15...`)
    run(vmName, 'sleep 1')
  }
  if (!healthy) throw new Error('agentsh server did not become healthy')

  step('Installing shell shim...')
  const r3 = run(vmName, 'agentsh shim install-shell --root / --shim /usr/bin/agentsh-shell-shim --bash --i-understand-this-modifies-the-host')
  if (r3.exitCode !== 0) throw new Error(`shim install failed: ${r3.stderr}`)

  step('Configuring shim enforcement...')
  // Write /etc/agentsh/shim.conf so the shim enforces policy even without a TTY.
  // This is read by the shim at startup — no env vars needed.
  run(vmName, 'mkdir -p /etc/agentsh && echo "force=true" > /etc/agentsh/shim.conf')

  step('Warming up shim...')
  run(vmName, '/bin/bash -c "echo shim-warmup-ok" 2>/dev/null || true')

  step('agentsh is ready!')
  console.log(`  SSH: ssh exe.dev ssh ${vmName}`)
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
