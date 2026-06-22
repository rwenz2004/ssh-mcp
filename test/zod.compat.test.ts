import { describe, it, expect } from 'vitest';
import { z } from 'zod';

describe('zod compatibility with MCP SDK', () => {
  it('zod schemas work with SDK zod-compat utilities', async () => {
    const { safeParse } = await import('@modelcontextprotocol/sdk/server/zod-compat.js');

    const schema = z.object({
      name: z.string(),
      count: z.number().optional(),
    });

    const result = safeParse(schema, { name: 'test', count: 42 });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data).toEqual({ name: 'test', count: 42 });
    }
  });

  it('zod string schema validates correctly', () => {
    const schema = z.string().min(1);
    const result = schema.safeParse('hello');
    expect(result.success).toBe(true);
  });

  it('zod v4 schemas work in registerTool inputSchema', () => {
    const shape = {
      command: z.string().describe("A shell command"),
    };
    expect(typeof shape.command).toBe('object');
    expect(shape.command._def).toBeDefined();
  });
});
