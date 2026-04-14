import { execSync, ExecSyncOptionsWithStringEncoding } from 'child_process'
import { readFileSync } from 'fs'

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

function sshExeDev(args: string, timeoutMs: number = 60_000): string {
  return execSync(`ssh ${SSH_OPTS} exe.dev ${args}`, { ...EXEC_OPTS, timeout: timeoutMs }).trim()
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
  const parsed = JSON.parse(raw)
  return parsed.vms ?? parsed
}

/**
 * Run a command on an exe.dev VM via `ssh exe.dev ssh <vmName> <cmd>`.
 * The vmName parameter is the VM name (not the ssh_dest hostname).
 */
// Strip agentsh wrapper debug messages that SSH mixes into stdout.
function stripAgentshDebug(s: string): string {
  return s.split('\n').filter(l =>
    !l.startsWith('landlock: restrictions applied') &&
    !l.startsWith('agentsh: secure agent shell') &&
    !l.startsWith('agentsh: auto-starting') &&
    !l.startsWith('agentsh: blocked by policy') &&
    !l.startsWith('agentsh: hint:') &&
    !l.startsWith('agentsh: command failed') &&
    !l.startsWith('blocked by policy') &&
    // Server log lines that leak through the shim (timestamp-prefixed)
    !l.match(/^\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2} /) &&
    // Go server startup messages
    !l.startsWith('listen tcp') &&
    !l.startsWith('server unreachable') &&
    // Kernel ptrace warnings from v0.16.9+
    !l.startsWith('PR_SET_PTRACER') &&
    // Yama-aware ptrace notice from v0.18.0+ (when Yama LSM isn't loaded)
    !l.startsWith('yama:')
  ).join('\n')
}

/**
 * Run a command on the VM via SSH (goes through the shell shim when installed).
 */
export function run(vmName: string, cmd: string, timeoutMs: number = 120_000): ExecResult {
  return runRaw(vmName, cmd, timeoutMs)
}

/**
 * Run a command bypassing the shell shim. Only works for simple agentsh CLI
 * commands (no pipes, no chaining) — the shim's isAgentshCommand() auto-bypasses these.
 * For commands with pipes or that connect to localhost:18080, there is no bypass
 * available on exe.dev's SSH gateway.
 */
export const runBypass = run

function runRaw(vmName: string, cmd: string, timeoutMs: number = 120_000): ExecResult {
  try {
    const stdout = execSync(
      `ssh ${SSH_OPTS} exe.dev ssh ${vmName} ${JSON.stringify(cmd)}`,
      { ...EXEC_OPTS, timeout: timeoutMs, stdio: ['pipe', 'pipe', 'pipe'] }
    )
    return { exitCode: 0, stdout: stripAgentshDebug(stdout.toString()), stderr: '' }
  } catch (err: any) {
    return {
      exitCode: err.status ?? 1,
      stdout: stripAgentshDebug((err.stdout ?? '').toString()),
      stderr: (err.stderr ?? '').toString(),
    }
  }
}

/**
 * Write string content to a file on the VM using base64 encoding.
 * This avoids quoting issues across the double SSH hop (local → exe.dev → VM).
 */
export function writeFile(vmName: string, remotePath: string, content: string): void {
  const b64 = Buffer.from(content).toString('base64')
  const r = runRaw(vmName, `echo ${b64} | base64 -d > ${remotePath}`, 30_000)
  if (r.exitCode !== 0) throw new Error(`writeFile failed: ${r.stderr}`)
}

/**
 * Copy a local file to an exe.dev VM using base64 encoding over SSH.
 * exe.dev doesn't support direct scp — files are transferred via:
 *   echo <base64> | base64 -d > remotePath
 */
export function copyToVM(vmName: string, localPath: string, remotePath: string): void {
  const content = readFileSync(localPath)
  const b64 = content.toString('base64')
  const r = runRaw(vmName, `echo ${b64} | base64 -d > ${remotePath}`, 60_000)
  if (r.exitCode !== 0) throw new Error(`copyToVM failed: ${r.stderr}`)
}

/**
 * Wait for SSH to be reachable on an exe.dev VM.
 * Uses `ssh exe.dev ssh <vmName>` which tunnels through the exe.dev gateway.
 */
export function waitForSSH(vmName: string, maxAttempts: number = 30, intervalMs: number = 3000): void {
  for (let i = 1; i <= maxAttempts; i++) {
    try {
      const r = runRaw(vmName, 'echo ssh-ready', 10_000)
      if (r.exitCode === 0 && r.stdout.includes('ssh-ready')) return
    } catch {
      // SSH handshake may fail while VM is booting
    }
    if (i < maxAttempts) {
      console.log(`  Waiting for SSH... (${i}/${maxAttempts})`)
      execSync(`sleep ${intervalMs / 1000}`)
    }
  }
  throw new Error(`SSH not reachable after ${maxAttempts} attempts`)
}
