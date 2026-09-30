import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Miniflare } from 'miniflare';
import type { D1Database } from '@cloudflare/workers-types';

let mf: Miniflare;
let db: D1Database;
const migrationDir = resolve(process.cwd(), 'migrations');

async function executeMigration(sql: string): Promise<void> {
  const cleaned = sql.replace(/^--.*$/gm, '');
  const protectedTriggers = cleaned.replace(/CREATE TRIGGER\b[\s\S]*?\bEND;/gi, (trigger) => trigger.replace(/;/g, '\u0000'));
  const statements = protectedTriggers.split(';').map((statement) => statement.replace(/\u0000/g, ';').trim()).filter(Boolean);
  for (const statement of statements) await db.prepare(statement).run();
}

beforeAll(async () => {
  mf = new Miniflare({
    script: 'export default { fetch() { return new Response(); } }',
    modules: true,
    d1Databases: ['AUDIT_DB'],
  });
  db = await mf.getD1Database('AUDIT_DB');
});

afterAll(async () => { await mf?.dispose(); });

describe('user-control D1 migration', () => {
  it('applies, enforces append-only audit integrity, and rolls back cleanly', async () => {
    const up = await readFile(resolve(migrationDir, '0001_user_controls.up.sql'), 'utf8');
    const down = await readFile(resolve(migrationDir, '0001_user_controls.down.sql'), 'utf8');
    await executeMigration(up);

    await db.prepare(
      'INSERT INTO user_control_audit(actor_user_id,target_user_id,action,details_json,created_at) VALUES(1,2,\'user_disabled\',\'{"enabled":false}\',1800000000000)',
    ).run();
    await expect(
      db.prepare('UPDATE user_control_audit SET action = \'user_enabled\' WHERE id = 1').run(),
    ).rejects.toThrow(/append-only/i);
    await expect(
      db.prepare('DELETE FROM user_control_audit WHERE id = 1').run(),
    ).rejects.toThrow(/append-only/i);
    await expect(
      db.prepare("INSERT INTO user_control_audit(actor_user_id,target_user_id,action,details_json,created_at) VALUES(1,2,'user_updated','not-json',1800000000001)").run(),
    ).rejects.toThrow();

    const intact = await db.prepare(
      'SELECT actor_user_id,target_user_id,action,details_json,created_at FROM user_control_audit WHERE id=1',
    ).first<{ actor_user_id: number; target_user_id: number; action: string; details_json: string; created_at: number }>();
    expect(intact).toEqual({
      actor_user_id: 1,
      target_user_id: 2,
      action: 'user_disabled',
      details_json: '{"enabled":false}',
      created_at: 1800000000000,
    });

    await executeMigration(down);
    const remaining = await db.prepare(
      "SELECT COUNT(*) AS count FROM sqlite_master WHERE name IN ('user_control_audit','user_control_throttle','idx_user_control_audit_target','user_control_audit_no_update','user_control_audit_no_delete')",
    ).first<{ count: number }>();
    expect(remaining?.count).toBe(0);
  });
});
