import { describe, it, expect } from 'vitest';
import { sanitizeCommand } from '../src/index';

describe('Upload tool input validation', () => {
  it('rejects empty source', () => {
    expect(() => sanitizeCommand('')).toThrow('Command cannot be empty');
  });

  it('rejects command over max chars', () => {
    const long = 'x'.repeat(1001);
    expect(() => sanitizeCommand(long)).toThrow('Command is too long');
  });
});
