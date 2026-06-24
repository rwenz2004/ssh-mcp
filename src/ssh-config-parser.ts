import { readFileSync, existsSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';

const DEFAULT_KEY_NAMES = ['id_ed25519', 'id_ecdsa', 'id_rsa', 'id_dsa'];

export function discoverDefaultSshKey(): string | undefined {
  const sshDir = join(homedir(), '.ssh');
  for (const name of DEFAULT_KEY_NAMES) {
    const keyPath = join(sshDir, name);
    if (existsSync(keyPath)) {
      return keyPath;
    }
  }
  return undefined;
}

export interface SshConfigEntry {
  hostName?: string;
  user?: string;
  port?: number;
  identityFile?: string;
  strictHostKeyChecking?: boolean;
}

interface SshConfigBlock {
  patterns: string[];
  config: Record<string, string>;
}

function expandPath(path: string): string {
  if (path.startsWith('~/')) {
    return join(homedir(), path.slice(2));
  }
  return path;
}

function patternMatches(pattern: string, host: string): boolean {
  if (pattern === '*' || pattern === host) {
    return true;
  }
  if (pattern.includes('*') || pattern.includes('?')) {
    const regexStr = '^' + pattern
      .replace(/\./g, '\\.')
      .replace(/\*/g, '.*')
      .replace(/\?/g, '.') + '$';
    return new RegExp(regexStr).test(host);
  }
  return false;
}

function getPatternScore(pattern: string): number {
  if (!pattern.includes('*') && !pattern.includes('?')) {
    return 2;
  }
  if (pattern === '*') {
    return 0;
  }
  return 1;
}

export function parseSshConfigFile(configPath: string): SshConfigBlock[] {
  const blocks: SshConfigBlock[] = [];
  const expandedPath = expandPath(configPath);

  if (!existsSync(expandedPath)) {
    return blocks;
  }

  const content = readFileSync(expandedPath, 'utf-8');
  let currentBlock: SshConfigBlock | null = null;

  for (const rawLine of content.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) {
      continue;
    }

    // Remove inline comments
    const noComment = line.replace(/\s+#.*$/, '').trim();
    if (!noComment) continue;

    // Match Host directive (case-insensitive)
    const hostMatch = noComment.match(/^Host\s+(.+)$/i);
    if (hostMatch) {
      if (currentBlock) {
        blocks.push(currentBlock);
      }
      const patterns = hostMatch[1].split(/\s+/).filter(Boolean);
      currentBlock = { patterns, config: {} };
      continue;
    }

    if (!currentBlock) continue;

    const kvMatch = noComment.match(/^(\w+)\s+(.+)$/);
    if (kvMatch) {
      const key = kvMatch[1].toLowerCase();
      const value = kvMatch[2].trim();
      // Remove quotes if present
      const cleanValue = value.replace(/^["']|["']$/g, '');
      currentBlock.config[key] = cleanValue;
    }
  }

  if (currentBlock) {
    blocks.push(currentBlock);
  }

  return blocks;
}

export function resolveSshConfig(
  hostAlias: string,
  configPath?: string,
): SshConfigEntry | null {
  const path = configPath || join(homedir(), '.ssh', 'config');
  const blocks = parseSshConfigFile(path);

  let matchedPatterns: Array<{ block: SshConfigBlock; score: number }> = [];

  for (const block of blocks) {
    for (const pattern of block.patterns) {
      if (patternMatches(pattern, hostAlias)) {
        matchedPatterns.push({ block, score: getPatternScore(pattern) });
      }
    }
  }

  if (matchedPatterns.length === 0) {
    return null;
  }

  // Sort by score descending (exact > wildcard > *)
  matchedPatterns.sort((a, b) => b.score - a.score);

  // Merge all matched configs, highest score first, then file order
  // Properties from higher-score patterns take priority
  const merged: Record<string, string> = {};
  for (const { block } of matchedPatterns) {
    for (const [key, value] of Object.entries(block.config)) {
      if (!(key in merged)) {
        merged[key] = value;
      }
    }
  }

  const entry: SshConfigEntry = {};

  if (merged.hostname) {
    entry.hostName = merged.hostname;
  }
  if (merged.user) {
    entry.user = merged.user;
  }
  if (merged.port) {
    entry.port = parseInt(merged.port, 10);
  }
  if (merged.identityfile) {
    entry.identityFile = expandPath(merged.identityfile);
  }
  if (merged.stricthostkeychecking) {
    const val = merged.stricthostkeychecking.toLowerCase();
    entry.strictHostKeyChecking = val === 'yes' || val === 'true' || val === 'accept-new';
  }

  return entry;
}
