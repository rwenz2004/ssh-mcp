import { describe, it, expect } from 'vitest';
import { resolveSshConfig, parseSshConfigFile } from '../src/ssh-config-parser';
import { writeFileSync, unlinkSync, mkdirSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

function withTempConfig(content: string, fn: (path: string) => void) {
  const tmpDir = join(tmpdir(), 'ssh-mcp-test');
  mkdirSync(tmpDir, { recursive: true });
  const path = join(tmpDir, `config_${Date.now()}_${Math.random().toString(36).slice(2)}`);
  writeFileSync(path, content, 'utf-8');
  try {
    fn(path);
  } finally {
    try { unlinkSync(path); } catch { /* ignore */ }
  }
}

describe('SSH config parser', () => {
  it('parses exact Host match', () => {
    withTempConfig(`
Host myserver
    HostName 192.168.1.100
    User ubuntu
    Port 2222
`, (path) => {
      const entry = resolveSshConfig('myserver', path);
      expect(entry).not.toBeNull();
      expect(entry!.hostName).toBe('192.168.1.100');
      expect(entry!.user).toBe('ubuntu');
      expect(entry!.port).toBe(2222);
    });
  });

  it('returns null for unknown host', () => {
    withTempConfig(`
Host knownhost
    HostName 10.0.0.1
`, (path) => {
      const entry = resolveSshConfig('unknown', path);
      expect(entry).toBeNull();
    });
  });

  it('matches wildcard patterns', () => {
    withTempConfig(`
Host *.example.com
    User devuser
    Port 2222
`, (path) => {
      const entry = resolveSshConfig('foo.example.com', path);
      expect(entry).not.toBeNull();
      expect(entry!.user).toBe('devuser');
    });
  });

  it('Host * matches everything', () => {
    withTempConfig(`
Host *
    User defaultuser
    Port 22
`, (path) => {
      const entry = resolveSshConfig('anything', path);
      expect(entry).not.toBeNull();
      expect(entry!.user).toBe('defaultuser');
    });
  });

  it('exact match takes priority over wildcard', () => {
    withTempConfig(`
Host *
    User defaultuser
Host specific
    User specificuser
`, (path) => {
      const entry = resolveSshConfig('specific', path);
      expect(entry).not.toBeNull();
      expect(entry!.user).toBe('specificuser');
    });
  });

  it('parses IdentityFile with ~ expansion', () => {
    withTempConfig(`
Host testhost
    IdentityFile ~/.ssh/test_key
`, (path) => {
      const entry = resolveSshConfig('testhost', path);
      expect(entry).not.toBeNull();
      expect(entry!.identityFile).toContain('/.ssh/test_key');
      expect(entry!.identityFile).not.toContain('~');
    });
  });

  it('parses StrictHostKeyChecking', () => {
    withTempConfig(`
Host checkhost
    StrictHostKeyChecking no
`, (path) => {
      const entry = resolveSshConfig('checkhost', path);
      expect(entry).not.toBeNull();
      expect(entry!.strictHostKeyChecking).toBe(false);
    });
  });

  it('handles multi-value Host directive', () => {
    withTempConfig(`
Host alias1 alias2
    User shareduser
`, (path) => {
      const entry1 = resolveSshConfig('alias1', path);
      const entry2 = resolveSshConfig('alias2', path);
      expect(entry1).not.toBeNull();
      expect(entry2).not.toBeNull();
      expect(entry1!.user).toBe('shareduser');
      expect(entry2!.user).toBe('shareduser');
    });
  });

  it('parses comments and blank lines correctly', () => {
    withTempConfig(`
# This is a comment
Host commenthost

    # Indented comment
    HostName 10.0.0.1
    User testuser
`, (path) => {
      const entry = resolveSshConfig('commenthost', path);
      expect(entry).not.toBeNull();
      expect(entry!.hostName).toBe('10.0.0.1');
      expect(entry!.user).toBe('testuser');
    });
  });

  it('handles inline comments', () => {
    withTempConfig(`
Host inlinehost
    HostName 10.0.0.5 # this is the real host
    User myuser
`, (path) => {
      const entry = resolveSshConfig('inlinehost', path);
      expect(entry).not.toBeNull();
      expect(entry!.hostName).toBe('10.0.0.5');
    });
  });

  it('returns empty blocks for empty config file', () => {
    withTempConfig('', (path) => {
      const blocks = parseSshConfigFile(path);
      expect(blocks).toEqual([]);
    });
  });

  it('returns empty blocks for non-existent file', () => {
    const blocks = parseSshConfigFile('/nonexistent/path/config');
    expect(blocks).toEqual([]);
  });
});
