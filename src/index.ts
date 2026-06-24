#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { Client, ClientChannel, SFTPWrapper } from 'ssh2';
import { z } from 'zod';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { resolveSshConfig, discoverDefaultSshKey } from './ssh-config-parser.js';
import { readFile, writeFile, readdir, mkdir, stat } from 'fs/promises';
import { join, dirname } from 'path';
import { userInfo } from 'os';

// Example usage: node build/index.js --host=root@1.2.3.4 --port=22 --password=pass --key=path/to/key --jump=admin@gateway.com:2222 --timeout=5000 --disableSudo
function parseArgv() {
  const args = process.argv.slice(2);
  const config: Record<string, string | null> = {};
  for (const arg of args) {
    if (arg.startsWith('--')) {
      const equalIndex = arg.indexOf('=');
      if (equalIndex === -1) {
        // Flag without value
        config[arg.slice(2)] = null;
      } else {
        // Key=value pair
        config[arg.slice(2, equalIndex)] = arg.slice(equalIndex + 1);
      }
    }
  }
  return config;
}

export interface JumpHost {
  user?: string;
  host: string;
  port: number;
}

export function parseJumpHosts(raw: string): JumpHost[] {
  return raw.split(',').map(entry => {
    const trimmed = entry.trim();
    if (!trimmed) return null;

    let user: string | undefined;
    let host = trimmed;
    let port = 22;

    const atIndex = trimmed.lastIndexOf('@');
    if (atIndex !== -1) {
      user = trimmed.slice(0, atIndex);
      host = trimmed.slice(atIndex + 1);
    }

    const colonIndex = host.lastIndexOf(':');
    if (colonIndex !== -1) {
      const portStr = host.slice(colonIndex + 1);
      const parsedPort = parseInt(portStr, 10);
      if (!isNaN(parsedPort) && parsedPort > 0) {
        port = parsedPort;
        host = host.slice(0, colonIndex);
      }
    }

    return { user, host, port } as JumpHost;
  }).filter((j): j is JumpHost => j !== null && !!j.host);
}
const isTestMode = process.env.SSH_MCP_TEST === '1';
const isCliEnabled = process.env.SSH_MCP_DISABLE_MAIN !== '1';
const argvConfig = (isCliEnabled || isTestMode) ? parseArgv() : {} as Record<string, string>;

const HOST = argvConfig.host;
const PASSWORD = argvConfig.password;
const SUPASSWORD = argvConfig.suPassword;
const SUDOPASSWORD = argvConfig.sudoPassword;
const DISABLE_SUDO = argvConfig.disableSudo !== undefined;
const KEY = argvConfig.key;
const JUMP_RAW = argvConfig.jump;
const JUMP_HOSTS = JUMP_RAW ? parseJumpHosts(JUMP_RAW) : [];
const DEFAULT_TIMEOUT = argvConfig.timeout ? parseInt(argvConfig.timeout) : 60000; // 60 seconds default timeout
// Max characters configuration:
// - Default: 1000 characters
// - When set via --maxChars:
//   * a positive integer enforces that limit
//   * 0 or a negative value disables the limit (no max)
//   * the string "none" (case-insensitive) disables the limit (no max)
const MAX_CHARS_RAW = argvConfig.maxChars;
const MAX_CHARS = (() => {
  if (typeof MAX_CHARS_RAW === 'string') {
    const lowered = MAX_CHARS_RAW.toLowerCase();
    if (lowered === 'none') return Infinity;
    const parsed = parseInt(MAX_CHARS_RAW);
    if (isNaN(parsed)) return 1000;
    if (parsed <= 0) return Infinity;
    return parsed;
  }
  return 1000;
})();

// Parse user@host from --host (same format as ssh/scp)
let PARSED_HOST: string | undefined;
let PARSED_USER: string | undefined;
if (HOST) {
  const atIndex = HOST.lastIndexOf('@');
  if (atIndex !== -1) {
    PARSED_USER = HOST.slice(0, atIndex);
    PARSED_HOST = HOST.slice(atIndex + 1);
  } else {
    PARSED_HOST = HOST;
  }
}

// SSH config resolution — fills in missing values from ~/.ssh/config
// Use bare hostname (without user) for SSH config matching
const NO_SSH_CONFIG = argvConfig.noConfig !== undefined;
const SSH_CONFIG_FILE = argvConfig.configFile;

let SSH_CONFIG_HOSTNAME: string | undefined;
let SSH_CONFIG_USER: string | undefined;
let SSH_CONFIG_PORT: number | undefined;
let SSH_CONFIG_KEY: string | undefined;

if (!NO_SSH_CONFIG && PARSED_HOST) {
  try {
    const entry = resolveSshConfig(PARSED_HOST, SSH_CONFIG_FILE || undefined);
    if (entry) {
      SSH_CONFIG_HOSTNAME = entry.hostName;
      SSH_CONFIG_USER = entry.user;
      SSH_CONFIG_PORT = entry.port;
      SSH_CONFIG_KEY = entry.identityFile;
    }
  } catch (e) {
    console.error('Warning: Failed to parse SSH config:', e);
  }
}

// Resolved connection parameters:
// - host:   SSH config HostName → CLI --host (bare hostname part)
// - port:   CLI --port → SSH config Port → default 22
// - user:   user@host in --host → SSH config User → current OS user
// - key:    CLI --key → SSH config IdentityFile → auto-discovery
const CONN_HOST = SSH_CONFIG_HOSTNAME ?? PARSED_HOST;
const CONN_PORT = argvConfig.port ? parseInt(argvConfig.port) : (SSH_CONFIG_PORT ?? 22);
const CONN_USER = PARSED_USER ?? SSH_CONFIG_USER ?? userInfo().username;
const CONN_KEY = KEY ?? SSH_CONFIG_KEY;

function validateConfig(config: Record<string, string | null>) {
  const errors = [];
  if (!config.host) errors.push('Missing required --host');
  if (config.port && isNaN(Number(config.port))) errors.push('Invalid --port');
  if (errors.length > 0) {
    throw new Error('Configuration error:\n' + errors.join('\n'));
  }
}

if (isCliEnabled) {
  validateConfig(argvConfig);
}

// Command sanitization and validation
export function sanitizeCommand(command: string): string {
  if (typeof command !== 'string') {
    throw new McpError(ErrorCode.InvalidParams, 'Command must be a string');
  }

  const trimmedCommand = command.trim();
  if (!trimmedCommand) {
    throw new McpError(ErrorCode.InvalidParams, 'Command cannot be empty');
  }

  // Length check
  if (Number.isFinite(MAX_CHARS) && trimmedCommand.length > (MAX_CHARS as number)) {
    throw new McpError(
      ErrorCode.InvalidParams,
      `Command is too long (max ${MAX_CHARS} characters)`
    );
  }

  return trimmedCommand;
}

function sanitizePassword(password: string | undefined): string | undefined {
  if (typeof password !== 'string') return undefined;
  // minimal check, do not log or modify content
  if (password.length === 0) return undefined;
  return password;
}

async function buildSshConfig(extras?: {
  suPassword?: string | null;
  sudoPassword?: string | null;
}): Promise<SSHConfig> {
  if (!CONN_HOST) {
    throw new McpError(ErrorCode.InvalidParams, 'Missing required host');
  }
  if (!CONN_USER) {
    throw new McpError(ErrorCode.InvalidParams, 'Missing required username');
  }

  const config: SSHConfig = {
    host: CONN_HOST,
    port: CONN_PORT,
    username: CONN_USER,
  };

  if (PASSWORD) {
    config.password = PASSWORD;
  } else {
    const keyPath = CONN_KEY || discoverDefaultSshKey();
    if (keyPath) {
      const fs = await import('fs/promises');
      config.privateKey = await fs.readFile(keyPath, 'utf8');
    } else {
      throw new McpError(
        ErrorCode.InvalidParams,
        'No authentication method available. Provide --password or --key, or ensure an SSH key exists at ~/.ssh/ (id_ed25519, id_ecdsa, id_rsa, id_dsa)',
      );
    }
  }

  if (extras?.suPassword !== undefined && extras?.suPassword !== null) {
    config.suPassword = sanitizePassword(extras.suPassword);
  }
  if (extras?.sudoPassword !== undefined && extras?.sudoPassword !== null) {
    config.sudoPassword = sanitizePassword(extras.sudoPassword);
  }

  if (JUMP_HOSTS.length > 0) {
    config.jumpHosts = JUMP_HOSTS;
  }

  return config;
}

// Escape command for use in shell contexts (like pkill)
export function escapeCommandForShell(command: string): string {
  // Replace single quotes with escaped single quotes
  return command.replace(/'/g, "'\"'\"'");
}

// SSH Connection Manager to maintain persistent connection
export interface SSHConfig {
  host: string;
  port: number;
  username: string;
  password?: string;
  privateKey?: string;
  suPassword?: string;
  sudoPassword?: string;  // Password for sudo commands specifically (if different from suPassword)
  jumpHosts?: JumpHost[];
}

export class SSHConnectionManager {
  private conn: Client | null = null;
  private sshConfig: SSHConfig;
  private isConnecting = false;
  private connectionPromise: Promise<void> | null = null;
  private suShell: any = null;  // Store the elevated shell session
  private suPromise: Promise<void> | null = null;
  private isElevated = false;  // Track if we're in su mode
  private sftpSession: SFTPWrapper | null = null;
  private sftpPromise: Promise<SFTPWrapper> | null = null;
  private intermediateConns: Client[] = [];  // Jump host intermediate connections

  constructor(config: SSHConfig) {
    this.sshConfig = config;
  }

  async connect(): Promise<void> {
    if (this.conn && this.isConnected()) {
      return; // Already connected
    }

    if (this.isConnecting && this.connectionPromise) {
      return this.connectionPromise; // Wait for ongoing connection
    }

    this.isConnecting = true;

    if (this.sshConfig.jumpHosts && this.sshConfig.jumpHosts.length > 0) {
      this.connectionPromise = this.connectThroughJumpHosts();
    } else {
      this.connectionPromise = this.connectDirect();
    }

    return this.connectionPromise;
  }

  private connectDirect(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.conn = new Client();

      const timeoutId = setTimeout(() => {
        this.conn?.end();
        this.conn = null;
        this.isConnecting = false;
        this.connectionPromise = null;
        reject(new McpError(ErrorCode.InternalError, 'SSH connection timeout'));
      }, 30000); // 30 seconds connection timeout

      this.conn.on('ready', async () => {
        clearTimeout(timeoutId);
        this.isConnecting = false;

        // In test mode, don't wait for su elevation during connection setup, as it
        // may cause JSON-RPC server initialization to hang. Instead, elevation will
        // be triggered on-demand when a command is executed.
        // In production, elevation during connection is desirable for robustness.
        if (this.sshConfig.suPassword && !process.env.SSH_MCP_TEST) {
          try {
            await this.ensureElevated();
          } catch (err) {
            // Do not reject the connection; just log the error. Subsequent commands
            // will either use the su shell if available or fall back to normal execution.
          }
        }

        resolve();
      });

      this.conn.on('error', (err: Error) => {
        clearTimeout(timeoutId);
        this.conn = null;
        this.isConnecting = false;
        this.connectionPromise = null;
        reject(new McpError(ErrorCode.InternalError, `SSH connection error: ${err.message}`));
      });

      this.conn.on('end', () => {
        console.error('SSH connection ended');
        this.conn = null;
        this.isConnecting = false;
        this.connectionPromise = null;
      });

      this.conn.on('close', () => {
        console.error('SSH connection closed');
        this.conn = null;
        this.isConnecting = false;
        this.connectionPromise = null;
      });

      this.conn.connect(this.sshConfig);
    });
  }

  private async connectThroughJumpHosts(): Promise<void> {
    const jumps = this.sshConfig.jumpHosts!;
    const auth = {
      password: this.sshConfig.password,
      privateKey: this.sshConfig.privateKey,
    };

    // Build the full hop chain: [jump1, jump2, ..., target]
    const targetHop = {
      user: this.sshConfig.username,
      host: this.sshConfig.host,
      port: this.sshConfig.port,
    };
    const chain = [...jumps, targetHop];

    let currentConn: Client | null = null;
    let currentSock: any = null;

    for (let i = 0; i < chain.length; i++) {
      const hop = chain[i];
      const isLast = i === chain.length - 1;

      // Resolve username for this hop: user@host → SSH config → current OS user
      let hopUser = hop.user;
      let hopHost = hop.host;
      let hopPort = hop.port;

      if (!hopUser) {
        // Try SSH config for this host
        try {
          const entry = resolveSshConfig(hopHost, undefined);
          if (entry) {
            if (!hopUser && entry.user) hopUser = entry.user;
            if (entry.hostName) hopHost = entry.hostName;
            if (entry.port) hopPort = entry.port;
          }
        } catch (e) {
          // Ignore SSH config errors for jump hosts
        }
        if (!hopUser) hopUser = userInfo().username;
      }

      const conn = new Client();

      await new Promise<void>((resolve, reject) => {
        const timeoutId = setTimeout(() => {
          conn.end();
          reject(new McpError(ErrorCode.InternalError, `SSH connection timeout at hop ${i + 1} (${hopHost}:${hopPort})`));
        }, 30000);

        conn.on('ready', () => {
          clearTimeout(timeoutId);
          resolve();
        });

        conn.on('error', (err: Error) => {
          clearTimeout(timeoutId);
          reject(new McpError(ErrorCode.InternalError, `SSH connection error at hop ${i + 1} (${hopHost}:${hopPort}): ${err.message}`));
        });

        const connectConfig: any = {
          host: hopHost,
          port: hopPort,
          username: hopUser,
        };
        if (auth.password) connectConfig.password = auth.password;
        if (auth.privateKey) connectConfig.privateKey = auth.privateKey;
        if (currentSock) connectConfig.sock = currentSock;

        conn.connect(connectConfig);
      });

      if (isLast) {
        // This is the target — store as the main connection
        this.conn = conn;

        // Set up event handlers for connection lifecycle tracking
        conn.on('end', () => {
          console.error('SSH connection ended');
          this.conn = null;
          this.isConnecting = false;
          this.connectionPromise = null;
        });
        conn.on('close', () => {
          console.error('SSH connection closed');
          this.conn = null;
          this.isConnecting = false;
          this.connectionPromise = null;
        });

        // Handle su elevation if needed
        if (this.sshConfig.suPassword && !process.env.SSH_MCP_TEST) {
          try {
            await this.ensureElevated();
          } catch (err) {
            // Non-fatal: fall back to normal execution
          }
        }
      } else {
        // Intermediate hop — save connection and create tunnel to next hop
        this.intermediateConns.push(conn);

        const nextHop = chain[i + 1];
        let nextHost = nextHop.host;
        let nextPort = nextHop.port;

        // Resolve next hop's actual hostname/port via SSH config
        if (!nextHop.user) {
          try {
            const entry = resolveSshConfig(nextHost, undefined);
            if (entry) {
              if (entry.hostName) nextHost = entry.hostName;
              if (entry.port) nextPort = entry.port;
            }
          } catch (e) {
            // Ignore
          }
        }

        currentSock = await new Promise<ClientChannel>((resolve, reject) => {
          conn.forwardOut('127.0.0.1', 0, nextHost, nextPort, (err, stream) => {
            if (err) {
              reject(new McpError(ErrorCode.InternalError, `Failed to tunnel through hop ${i + 1} to ${nextHost}:${nextPort}: ${err.message}`));
            } else {
              resolve(stream);
            }
          });
        });

        currentConn = conn;
      }
    }

    this.isConnecting = false;
  }

  isConnected(): boolean {
    return this.conn !== null && (this.conn as any)._sock && !(this.conn as any)._sock.destroyed;
  }

  getSudoPassword(): string | undefined {
    return this.sshConfig.sudoPassword;
  }

  getSuPassword(): string | undefined {
    return this.sshConfig.suPassword;
  }

  async setSuPassword(pwd?: string): Promise<void> {
    this.sshConfig.suPassword = pwd;
    if (pwd) {
      try {
        await this.ensureElevated();
      } catch (err) {
        console.error('setSuPassword: failed to elevate to su shell:', err);
      }
    } else {
      // If clearing suPassword, drop any existing suShell
      if (this.suShell) {
        try { this.suShell.end(); } catch (e) { /* ignore */ }
        this.suShell = null;
        this.isElevated = false;
      }
    }
  }

  private async ensureElevated(): Promise<void> {
    if (this.isElevated && this.suShell) return;
    if (!this.sshConfig.suPassword) return;

    if (this.suPromise) return this.suPromise;

    this.suPromise = new Promise((resolve, reject) => {
      const conn = this.getConnection();

      // Add a safety timeout so elevation doesn't hang forever
      const timeoutId = setTimeout(() => {
        this.suPromise = null;
        reject(new McpError(ErrorCode.InternalError, 'su elevation timed out'));
      }, 10000);  // 10 second timeout for elevation

      conn.shell({ term: 'xterm', cols: 80, rows: 24 }, (err: Error | undefined, stream: ClientChannel) => {
        if (err) {
          clearTimeout(timeoutId);
          this.suPromise = null;
          reject(new McpError(ErrorCode.InternalError, `Failed to start interactive shell for su: ${err.message}`));
          return;
        }

        let buffer = '';
        let passwordSent = false;
        const cleanup = () => {
          try { stream.removeAllListeners('data'); } catch (e) { /* ignore */ }
        };

        const onData = (data: Buffer) => {
          const text = data.toString();
          buffer += text;

          // If we haven't sent the password yet, look for the password prompt
          if (!passwordSent && /password[: ]/i.test(buffer)) {
            passwordSent = true;
            stream.write(this.sshConfig.suPassword + '\n');
            // Don't return; keep looking for root prompt
          }

          // After password is sent, look for any root indicator
          // Look for '#' which indicates root prompt (may be followed by spaces, escape codes, etc)
          if (passwordSent) {
            if (/#/.test(buffer)) {
              clearTimeout(timeoutId);
              cleanup();
              this.suShell = stream;
              this.isElevated = true;
              this.suPromise = null;
              resolve();
              return;
            }
          }

          // Detect authentication failure messages
          if (/authentication failure|incorrect password|su: .*failed|su: failure/i.test(buffer)) {
            clearTimeout(timeoutId);
            cleanup();
            this.suPromise = null;
            reject(new McpError(ErrorCode.InternalError, `su authentication failed: ${buffer}`));
            return;
          }
        };

        stream.on('data', onData);

        stream.on('close', () => {
          clearTimeout(timeoutId);
          if (!this.isElevated) {
            this.suPromise = null;
            reject(new McpError(ErrorCode.InternalError, 'su shell closed before elevation completed'));
          }
        });

        // Kick off the su command
        stream.write('su -\n');
      });
    });

    return this.suPromise;
  }

  async ensureConnected(): Promise<void> {
    if (!this.isConnected()) {
      await this.connect();
    }
  }

  getConnection(): Client {
    if (!this.conn) {
      throw new McpError(ErrorCode.InternalError, 'SSH connection not established');
    }
    return this.conn;
  }

  async sftp(): Promise<SFTPWrapper> {
    if (this.sftpSession) return this.sftpSession;
    if (this.sftpPromise) return this.sftpPromise;

    this.sftpPromise = new Promise((resolve, reject) => {
      this.getConnection().sftp((err, sftp) => {
        if (err) {
          this.sftpPromise = null;
          reject(new McpError(ErrorCode.InternalError, `SFTP session error: ${err.message}`));
          return;
        }
        this.sftpSession = sftp;
        this.sftpPromise = null;
        resolve(sftp);
      });
    });

    return this.sftpPromise;
  }

  async uploadFile(localPath: string, remotePath: string): Promise<number> {
    const sftp = await this.sftp();
    const { size } = await stat(localPath);

    return new Promise((resolve, reject) => {
      sftp.fastPut(localPath, remotePath, (err) => {
        if (err) {
          reject(new McpError(ErrorCode.InternalError, `Upload failed: ${err.message}`));
          return;
        }
        resolve(size);
      });
    });
  }

  async uploadDirectory(localPath: string, remotePath: string): Promise<number> {
    const sftp = await this.sftp();
    let totalBytes = 0;

    const ensureRemoteDir = async (dir: string): Promise<void> => {
      await new Promise<void>((resolve, reject) => {
        sftp.mkdir(dir, (err) => {
          if (err && (err as any).code !== 4) { // 4 = EEXIST
            reject(new McpError(ErrorCode.InternalError, `Failed to create remote dir ${dir}: ${err.message}`));
            return;
          }
          resolve();
        });
      });
    };

    const walk = async (localDir: string, remoteDir: string): Promise<void> => {
      await ensureRemoteDir(remoteDir);
      const entries = await readdir(localDir, { withFileTypes: true });

      for (const entry of entries) {
        const localEntry = join(localDir, entry.name);
        const remoteEntry = remoteDir + '/' + entry.name;

        if (entry.isDirectory()) {
          await walk(localEntry, remoteEntry);
        } else if (entry.isFile()) {
          const size = await this.uploadFile(localEntry, remoteEntry);
          totalBytes += size;
        }
      }
    };

    await walk(localPath, remotePath);
    return totalBytes;
  }

  async downloadFile(remotePath: string, localPath: string): Promise<number> {
    const sftp = await this.sftp();

    const size = await new Promise<number>((resolve, reject) => {
      sftp.stat(remotePath, (err, stats) => {
        if (err) {
          reject(new McpError(ErrorCode.InternalError, `Remote file stat failed: ${err.message}`));
          return;
        }
        resolve(stats.size);
      });
    });

    await mkdir(dirname(localPath), { recursive: true });

    return new Promise((resolve, reject) => {
      sftp.fastGet(remotePath, localPath, (err) => {
        if (err) {
          reject(new McpError(ErrorCode.InternalError, `Download failed: ${err.message}`));
          return;
        }
        resolve(size);
      });
    });
  }

  async downloadDirectory(remotePath: string, localPath: string): Promise<number> {
    const sftp = await this.sftp();
    let totalBytes = 0;

    const walk = async (remoteDir: string, localDir: string): Promise<void> => {
      await mkdir(localDir, { recursive: true });

      const entries = await new Promise<{ filename: string; longname: string; attrs: any }[]>((resolve, reject) => {
        sftp.readdir(remoteDir, (err, list) => {
          if (err) {
            reject(new McpError(ErrorCode.InternalError, `Failed to read remote dir ${remoteDir}: ${err.message}`));
            return;
          }
          resolve(list);
        });
      });

      for (const entry of entries) {
        if (entry.filename === '.' || entry.filename === '..') continue;
        const remoteEntry = remoteDir + '/' + entry.filename;
        const localEntry = join(localDir, entry.filename);

        if (entry.attrs.isDirectory()) {
          totalBytes += await this.downloadDirectory(remoteEntry, localEntry);
        } else {
          const size = await this.downloadFile(remoteEntry, localEntry);
          totalBytes += size;
        }
      }
    };

    await walk(remotePath, localPath);
    return totalBytes;
  }

  close(): void {
    if (this.sftpSession) {
      try { this.sftpSession.end(); } catch (e) { /* ignore */ }
      this.sftpSession = null;
      this.sftpPromise = null;
    }
    if (this.conn) {
      if (this.suShell) {
        try { this.suShell.end(); } catch (e) { /* ignore */ }
        this.suShell = null;
        this.isElevated = false;
      }
      this.conn.end();
      this.conn = null;
    }
    // Close intermediate jump host connections (in reverse order)
    for (let i = this.intermediateConns.length - 1; i >= 0; i--) {
      try { this.intermediateConns[i].end(); } catch (e) { /* ignore */ }
    }
    this.intermediateConns = [];
  }
}

let connectionManager: SSHConnectionManager | null = null;

const server = new McpServer(
  {
    name: 'SSH MCP Server',
    version: '1.7.0',
  },
  {
    capabilities: {
      resources: {},
      tools: {},
    },
  },
);

server.registerTool("exec", {
  description: "Execute a shell command on the remote SSH server and return the output.",
  inputSchema: {
    command: z.string().describe("Shell command to execute on the remote SSH server"),
    description: z.string().optional().describe("Optional description of what this command will do"),
  },
}, async ({ command, description }) => {
    // Sanitize command input
    const sanitizedCommand = sanitizeCommand(command);

    try {
      // Initialize connection manager if not already done
      if (!connectionManager) {
        connectionManager = new SSHConnectionManager(
          await buildSshConfig({
            suPassword: SUPASSWORD,
          }),
        );
      }

      // Ensure connection is active (reconnect if needed)
      await connectionManager.ensureConnected();

      // If a suPassword was provided, explicitly wait for elevation before executing.
      // This is critical: ensureElevated is idempotent and will return immediately if
      // already elevated, so this ensures we have a su shell before we try to use it.
      if ((connectionManager as any).getSuPassword && (connectionManager as any).getSuPassword()) {
        try {
          const elevationPromise = (connectionManager as any).ensureElevated();
          // Add a short timeout for elevation to complete
          await Promise.race([
            elevationPromise,
            new Promise((_, reject) => setTimeout(() => reject(new Error('Elevation timeout')), 5000))
          ]);
        } catch (err) {
          // Log but don't fail; fall back to non-elevated execution if elevation times out
        }
      }

      // Append description as comment if provided
      const commandWithDescription = description
        ? `${sanitizedCommand} # ${description.replace(/#/g, '\\#')}`
        : sanitizedCommand;

      const result = await execSshCommandWithConnection(connectionManager, commandWithDescription);
      return result;
    } catch (err: any) {
      // Wrap unexpected errors
      if (err instanceof McpError) throw err;
      throw new McpError(ErrorCode.InternalError, `Unexpected error: ${err?.message || err}`);
    }
  }
);

// Expose sudo-exec tool unless explicitly disabled
if (!DISABLE_SUDO) {
  server.registerTool("sudo-exec", {
    description: "Execute a shell command on the remote SSH server using sudo. Will use sudo password if provided, otherwise assumes passwordless sudo.",
    inputSchema: {
      command: z.string().describe("Shell command to execute with sudo on the remote SSH server"),
      description: z.string().optional().describe("Optional description of what this command will do"),
    },
  }, async ({ command, description }) => {
      const sanitizedCommand = sanitizeCommand(command);

      try {
        if (!connectionManager) {
          connectionManager = new SSHConnectionManager(
            await buildSshConfig({
              suPassword: SUPASSWORD,
              sudoPassword: SUDOPASSWORD,
            }),
          );
        }

        await connectionManager.ensureConnected();

        // If suPassword or sudoPassword were provided on this call but the
        // existing connection manager was created earlier without them,
        // update the manager's values so the subsequent sudo-exec call uses
        // the latest passwords.
        if (SUPASSWORD !== null && SUPASSWORD !== undefined) {
          await connectionManager.setSuPassword(sanitizePassword(SUPASSWORD));
        }
        if (SUDOPASSWORD !== null && SUDOPASSWORD !== undefined) {
          // update sudoPassword on the manager instance
          (connectionManager as any).sshConfig = { ...(connectionManager as any).sshConfig, sudoPassword: sanitizePassword(SUDOPASSWORD) };
        }

        let wrapped: string;
        const sudoPassword = connectionManager.getSudoPassword();

        // Append description as comment if provided
        const commandWithDescription = description
          ? `${sanitizedCommand} # ${description.replace(/#/g, '\\#')}`
          : sanitizedCommand;

        if (!sudoPassword) {
          // No password provided, use -n to fail if sudo requires a password
          wrapped = `sudo -n sh -c '${commandWithDescription.replace(/'/g, "'\\''")}'`;
        } else {
          // Password provided — pipe it into sudo using printf. This avoids complex
          // PTY/stdin handling on the SSH channel and is simpler and more reliable.
          const pwdEscaped = sudoPassword.replace(/'/g, "'\\''");
          wrapped = `printf '%s\\n' '${pwdEscaped}' | sudo -p "" -S sh -c '${commandWithDescription.replace(/'/g, "'\\''")}'`;
        }

        return await execSshCommandWithConnection(connectionManager, wrapped);
      } catch (err: any) {
        if (err instanceof McpError) throw err;
        throw new McpError(ErrorCode.InternalError, `Unexpected error: ${err?.message || err}`);
      }
    }
  );
}

async function initConnectionManagerIfNeeded(): Promise<SSHConnectionManager> {
  if (!connectionManager) {
    connectionManager = new SSHConnectionManager(
      await buildSshConfig({
        suPassword: SUPASSWORD,
        sudoPassword: SUDOPASSWORD,
      }),
    );
  }
  return connectionManager;
}

server.registerTool("upload", {
  description: "Upload a file or directory to the remote SSH server via SFTP. Directories are uploaded recursively automatically.",
  inputSchema: {
    source: z.string().describe("Local file path or directory path"),
    destination: z.string().describe("Remote destination path"),
  },
}, async ({ source, destination }) => {
  if (!source || !destination) {
    throw new McpError(ErrorCode.InvalidParams, 'source and destination are required');
  }

  const localPath = source;
  const remotePath = destination;

  let localStats;
  try {
    localStats = await stat(localPath);
  } catch (e: any) {
    throw new McpError(ErrorCode.InvalidParams, `Local path not accessible: ${e.message}`);
  }

  const mgr = await initConnectionManagerIfNeeded();
  await mgr.ensureConnected();

  let totalBytes: number;
  if (localStats.isDirectory()) {
    totalBytes = await mgr.uploadDirectory(localPath, remotePath);
  } else {
    totalBytes = await mgr.uploadFile(localPath, remotePath);
  }

  return {
    content: [{ type: 'text', text: `Uploaded ${totalBytes} bytes to ${remotePath}` }],
  };
});

server.registerTool("download", {
  description: "Download a file or directory from the remote SSH server via SFTP. Directories are downloaded recursively automatically.",
  inputSchema: {
    source: z.string().describe("Remote file path or directory path"),
    destination: z.string().describe("Local destination path"),
  },
}, async ({ source, destination }) => {
  if (!source || !destination) {
    throw new McpError(ErrorCode.InvalidParams, 'source and destination are required');
  }

  const remotePath = source;
  const localPath = destination;

  const mgr = await initConnectionManagerIfNeeded();
  await mgr.ensureConnected();

  const sftp = await mgr.sftp();

  const remoteStats = await new Promise<any>((resolve, reject) => {
    sftp.stat(remotePath, (err, stats) => {
      if (err) {
        reject(new McpError(ErrorCode.InvalidParams, `Remote path not accessible: ${err.message}`));
        return;
      }
      resolve(stats);
    });
  });

  let totalBytes: number;
  if (remoteStats.isDirectory()) {
    totalBytes = await mgr.downloadDirectory(remotePath, localPath);
  } else {
    totalBytes = await mgr.downloadFile(remotePath, localPath);
  }

  return {
    content: [{ type: 'text', text: `Downloaded ${totalBytes} bytes to ${localPath}` }],
  };
});

// New function that uses persistent connection
export async function execSshCommandWithConnection(manager: SSHConnectionManager, command: string, stdin?: string): Promise<{ [x: string]: unknown; content: ({ [x: string]: unknown; type: "text"; text: string; } | { [x: string]: unknown; type: "image"; data: string; mimeType: string; } | { [x: string]: unknown; type: "audio"; data: string; mimeType: string; } | { [x: string]: unknown; type: "resource"; resource: any; })[] }> {
  return new Promise((resolve, reject) => {
    let timeoutId: NodeJS.Timeout;
    let isResolved = false;

    const conn = manager.getConnection();
    const shell = (manager as any).suShell;  // Use su shell if available

    // Set up timeout
    timeoutId = setTimeout(() => {
      if (!isResolved) {
        isResolved = true;
        reject(new McpError(ErrorCode.InternalError, `Command execution timed out after ${DEFAULT_TIMEOUT}ms`));
      }
    }, DEFAULT_TIMEOUT);

    // If we have an active su shell, use it directly (commands run as root in session)
    if (shell) {
      let buffer = '';

      const dataHandler = (data: Buffer) => {
        const text = data.toString();
        buffer += text;

        // Wait for root prompt (#) to know command is complete
        // Match # which indicates root prompt (may be followed by spaces, escape codes, etc)
        if (/#/.test(buffer)) {
          if (!isResolved) {
            isResolved = true;
            clearTimeout(timeoutId);

            // Extract output: remove the command echo and final prompt
            const lines = buffer.split('\n');
            // First line is often the echoed command; last line is the prompt
            let output = lines.slice(1, -1).join('\n');

            resolve({
              content: [{
                type: 'text',
                text: output + (output ? '\n' : ''),
              }],
            });
          }
          shell.removeListener('data', dataHandler);
        }
      };

      shell.on('data', dataHandler);
      // Send command immediately; shell is ready after elevation
      shell.write(command + '\n');
      return;
    }

    // No persistent su shell; use normal exec with optional password piping
    conn.exec(command, (err: Error | undefined, stream: ClientChannel) => {
      if (err) {
        if (!isResolved) {
          isResolved = true;
          clearTimeout(timeoutId);
          reject(new McpError(ErrorCode.InternalError, `SSH exec error: ${err.message}`));
        }
        return;
      }

      let stdout = '';
      let stderr = '';

      // If stdin provided (e.g., sudo password), write it
      if (stdin && stdin.length > 0) {
        try {
          stream.write(stdin);
        } catch (e) {
          console.error('Error writing to stdin:', e);
        }
      }
      try { stream.end(); } catch (e) { /* ignore */ }

      stream.on('data', (data: Buffer) => {
        stdout += data.toString();
      });

      stream.stderr.on('data', (data: Buffer) => {
        stderr += data.toString();
      });

      stream.on('close', (code: number, signal: string) => {
        if (!isResolved) {
          isResolved = true;
          clearTimeout(timeoutId);
          if (stderr) {
            reject(new McpError(ErrorCode.InternalError, `Error (code ${code}):\n${stderr}`));
          } else {
            resolve({
              content: [{
                type: 'text',
                text: stdout,
              }],
            });
          }
        }
      });
    });
  });
}

// Keep the old function for backward compatibility (used in tests)
export async function execSshCommand(sshConfig: any, command: string, stdin?: string): Promise<{ [x: string]: unknown; content: ({ [x: string]: unknown; type: "text"; text: string; } | { [x: string]: unknown; type: "image"; data: string; mimeType: string; } | { [x: string]: unknown; type: "audio"; data: string; mimeType: string; } | { [x: string]: unknown; type: "resource"; resource: any; })[] }> {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    let timeoutId: NodeJS.Timeout;
    let isResolved = false;

    // Set up timeout
    timeoutId = setTimeout(() => {
      if (!isResolved) {
        isResolved = true;
        // Try to abort the running command before closing connection
        const abortTimeout = setTimeout(() => {
          // If abort command itself times out, force close connection
          conn.end();
        }, 5000); // 5 second timeout for abort command

        conn.exec('timeout 3s pkill -f \'' + escapeCommandForShell(command) + '\' 2>/dev/null || true', (err: Error | undefined, abortStream: ClientChannel | undefined) => {
          if (abortStream) {
            abortStream.on('close', () => {
              clearTimeout(abortTimeout);
              conn.end();
            });
          } else {
            clearTimeout(abortTimeout);
            conn.end();
          }
        });
        reject(new McpError(ErrorCode.InternalError, `Command execution timed out after ${DEFAULT_TIMEOUT}ms`));
      }
    }, DEFAULT_TIMEOUT);

    conn.on('ready', () => {
      conn.exec(command, (err: Error | undefined, stream: ClientChannel) => {
        if (err) {
          if (!isResolved) {
            isResolved = true;
            clearTimeout(timeoutId);
            reject(new McpError(ErrorCode.InternalError, `SSH exec error: ${err.message}`));
          }
          conn.end();
          return;
        }
        // If stdin provided, write it to the stream and end stdin
        if (stdin && stdin.length > 0) {
          try {
            stream.write(stdin);
          } catch (e) {
            // ignore
          }
        }
        try { stream.end(); } catch (e) { /* ignore */ }
        let stdout = '';
        let stderr = '';
        stream.on('close', (code: number, signal: string) => {
          if (!isResolved) {
            isResolved = true;
            clearTimeout(timeoutId);
            conn.end();
            if (stderr) {
              reject(new McpError(ErrorCode.InternalError, `Error (code ${code}):\n${stderr}`));
            } else {
              resolve({
                content: [{
                  type: 'text',
                  text: stdout,
                }],
              });
            }
          }
        });
        stream.on('data', (data: Buffer) => {
          stdout += data.toString();
        });
        stream.stderr.on('data', (data: Buffer) => {
          stderr += data.toString();
        });
      });
    });
    conn.on('error', (err: Error) => {
      if (!isResolved) {
        isResolved = true;
        clearTimeout(timeoutId);
        reject(new McpError(ErrorCode.InternalError, `SSH connection error: ${err.message}`));
      }
    });
    conn.connect(sshConfig);
  });
}

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("SSH MCP Server running on stdio");

  // Handle graceful shutdown
  const cleanup = () => {
    console.error("Shutting down SSH MCP Server...");
    if (connectionManager) {
      connectionManager.close();
      connectionManager = null;
    }
    process.exit(0);
  };

  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
  process.on('exit', () => {
    if (connectionManager) {
      connectionManager.close();
    }
  });
}

// Initialize server in test mode for automated tests
if (isTestMode) {
  const transport = new StdioServerTransport();
  server.connect(transport).catch(error => {
    console.error("Fatal error connecting server:", error);
    process.exit(1);
  });
}
// Start server in CLI mode
else if (isCliEnabled) {
  main().catch((error) => {
    console.error("Fatal error in main():", error);
    if (connectionManager) {
      connectionManager.close();
    }
    process.exit(1);
  });
}

export { parseArgv, validateConfig };