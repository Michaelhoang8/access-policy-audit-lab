import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Evaluator } from '../src/evaluator.ts';
import type { Policy, Request } from '../src/schema.ts';

test('role closure matches enumeration of every path in all five-role ordered DAGs', () => {
  const names = ['alpha', 'bravo', 'charlie', 'delta', 'echo'];
  const edges: Array<[number, number]> = [];
  for (let from = 0; from < names.length; from++) {
    for (let to = from + 1; to < names.length; to++) edges.push([from, to]);
  }
  for (let mask = 0; mask < 1 << edges.length; mask++) {
    const roles = names.map(id => ({ id, inherits: [] as string[] }));
    edges.forEach(([from, to], bit) => { if (mask & (1 << bit)) roles[from].inherits.push(names[to]); });
    const evaluator = new Evaluator({ version: 1, roles, rules: [] });
    for (let assigned = 0; assigned < 1 << names.length; assigned++) {
      const selected = names.filter((_, bit) => assigned & (1 << bit));
      const allPaths: string[][] = [];
      const enumerate = (path: string[]) => {
        allPaths.push(path);
        for (const next of roles.find(role => role.id === path.at(-1))!.inherits) enumerate([...path, next]);
      };
      selected.forEach(role => enumerate([role]));
      const expected = new Map<string, string[]>();
      for (const role of names) {
        const candidates = allPaths.filter(path => path.at(-1) === role);
        candidates.sort((a, b) => a.length - b.length || (a.join('/') < b.join('/') ? -1 : a.join('/') > b.join('/') ? 1 : 0));
        if (candidates.length) expected.set(role, candidates[0]);
      }
      const actual = evaluator.effectiveRoles({ id: 'alice', tenant: 'first', roles: selected });
      assert.deepEqual([...actual].sort(), [...expected].sort(), `graph=${mask}, assigned=${assigned}`);
    }
  }
});

test('wildcard tenant deny applies without roles and cannot be overridden by a broad allow', () => {
  const policy: Policy = { version: 1, roles: [{ id: 'reader', inherits: [] }], rules: [
    { id: 'permit-read', effect: 'allow', roles: ['*'], actions: ['read'], resourceKinds: ['*'], conditions: [] },
    { id: 'tenant-boundary', effect: 'deny', roles: ['*'], actions: ['*'], resourceKinds: ['*'],
      conditions: [{ left: 'subject.tenant', op: 'neq', right: { attribute: 'resource.tenant' } }] },
  ] };
  const evaluator = new Evaluator(policy);
  const outcomes: string[] = [];
  for (const tenant of ['first', 'second']) for (const action of ['read', 'write'] as const) {
    const request: Request = { subject: { id: 'alice', tenant: 'first', roles: [] }, action,
      resource: { id: 'report', tenant, kind: 'document', classification: 'public', ownerId: 'bob' },
      context: { id: 'remote', network: 'public', mfa: false } };
    const result = evaluator.evaluate(request);
    outcomes.push(result.reason);
    assert.equal(result.allowed, tenant === 'first' && action === 'read');
    assert.deepEqual(result.effectiveRoles, []);
  }
  assert.deepEqual(outcomes, ['allow-rule', 'default-deny', 'explicit-deny', 'explicit-deny']);
});
