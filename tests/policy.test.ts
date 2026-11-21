import { test } from 'node:test';
import assert from 'node:assert/strict';
import { baselinePolicy, policies, requestDomain } from '../src/fixtures.ts';
import { validatePolicy, validateDomain, parseJson, requests } from '../src/schema.ts';
import type { Request, Policy } from '../src/schema.ts';
import { Evaluator } from '../src/evaluator.ts';
import { auditPolicy, difference } from '../src/audit.ts';
const pick = (user: string, action: string, resource: string, context: string) => requests(requestDomain())
  .find(request => request.subject.id === user && request.action === action && request.resource.id === resource && request.context.id === context)!;

test('default deny applies when no allow or deny rule matches', () => {
  const result = new Evaluator(baselinePolicy()).evaluate(pick('guest', 'read', 'alpha-public-doc', 'corp-mfa'));
  assert.equal(result.allowed, false); assert.equal(result.reason, 'default-deny');
  assert.deepEqual(result.allowRules, []); assert.deepEqual(result.denyRules, []);
});
test('explicit deny wins even when inherited allow rules match', () => {
  const result = new Evaluator(baselinePolicy()).evaluate(pick('blair', 'read', 'beta-public-doc', 'corp-mfa'));
  assert.equal(result.reason, 'explicit-deny'); assert.ok(result.allowRules.includes('allow-view'));
  assert.ok(result.denyRules.includes('deny-tenant-boundary')); assert.equal(result.allowed, false);
  assert.deepEqual(result.rolePaths['allow-view'], [['editor', 'viewer']]);
});
test('rule order, role declaration order and assigned-role order do not change the decision', () => {
  const policy = baselinePolicy(); const reversed = structuredClone(policy); reversed.rules.reverse(); reversed.roles.reverse();
  const request = pick('blair', 'write', 'alpha-internal-doc', 'corp-mfa');
  request.subject.roles = ['editor', 'viewer'];
  const first = new Evaluator(policy).evaluate(request); request.subject.roles.reverse();
  assert.deepEqual(new Evaluator(reversed).evaluate(request), first);
});
test('multiple inheritance picks shortest then lexicographically smallest explanation path', () => {
  const policy: Policy = { version: 1, roles: [{ id: 'top', inherits: ['right', 'left'] }, { id: 'left', inherits: ['viewer'] },
    { id: 'right', inherits: ['viewer'] }, { id: 'viewer', inherits: [] }], rules: [{ id: 'read', effect: 'allow', roles: ['viewer'], actions: ['read'], resourceKinds: ['*'], conditions: [] }] };
  const request = pick('alex', 'read', 'alpha-public-doc', 'corp-mfa'); request.subject.roles = ['top'];
  assert.deepEqual(new Evaluator(policy).evaluate(request).rolePaths.read, [['top', 'left', 'viewer']]);
});
test('typed attribute predicates distinguish MFA false from invalid string values', () => {
  const evaluator = new Evaluator(baselinePolicy());
  assert.equal(evaluator.evaluate(pick('blair', 'write', 'alpha-public-doc', 'corp-no-mfa')).allowed, false);
  assert.equal(evaluator.evaluate(pick('blair', 'write', 'alpha-public-doc', 'corp-mfa')).allowed, true);
  const invalid = pick('blair', 'write', 'alpha-public-doc', 'corp-mfa');
  (invalid.context as unknown as Record<string, unknown>).mfa = 'true';
  assert.throws(() => evaluator.evaluate(invalid));
});
test('missing or unknown request fields fail before an authorization result is returned', () => {
  const evaluator = new Evaluator(baselinePolicy());
  const invalid = pick('blair', 'write', 'alpha-public-doc', 'corp-no-mfa');
  delete (invalid.context as unknown as Record<string, unknown>).mfa;
  assert.throws(() => evaluator.evaluate(invalid));
  assert.throws(() => evaluator.evaluate({} as Request));
});
test('unknown roles, cycles, duplicate IDs, mixed wildcard selectors and wrong condition types are rejected', () => {
  const unknown = baselinePolicy(); unknown.roles[1].inherits = ['missing']; assert.throws(() => validatePolicy(unknown));
  const cyclic = baselinePolicy(); cyclic.roles[0].inherits = ['editor']; assert.throws(() => validatePolicy(cyclic), /cycle/);
  const duplicate = baselinePolicy(); duplicate.rules.push(structuredClone(duplicate.rules[0])); assert.throws(() => validatePolicy(duplicate));
  const wildcard = baselinePolicy(); wildcard.rules[0].roles = ['*', 'viewer']; assert.throws(() => validatePolicy(wildcard));
  const type = baselinePolicy(); type.rules[0].conditions = [{ left: 'context.mfa', op: 'eq', right: { value: 'true' } }]; assert.throws(() => validatePolicy(type));
});
test('strict JSON parsing permits formatting but rejects duplicate keys and alternate token encoding', () => {
  assert.deepEqual(parseJson(JSON.stringify(baselinePolicy(), null, 2)), baselinePolicy());
  assert.throws(() => parseJson('{"version":1,"version":1}'));
  assert.throws(() => parseJson('{"version":1e0}'));
  assert.throws(() => parseJson(Buffer.from([0xff])));
  assert.throws(() => parseJson('x'.repeat(65537)));
});
test('all five complete domains reconcile with the independent reference evaluator', () => {
  for (const policy of Object.values(policies())) {
    const audit = auditPolicy(policy, requestDomain());
    assert.equal(audit.counts.requests, 1152); assert.equal(audit.counts.referenceComparisons, 1152);
  }
});
test('proposed change has the independently counted two grants and sixteen revocations', () => {
  const all = policies(); const baseline = auditPolicy(all.baseline, requestDomain()); const proposed = auditPolicy(all.proposed, requestDomain());
  const diff = difference(baseline.matrix, proposed.matrix);
  assert.equal(diff.newlyAllowed.length, 2); assert.equal(diff.newlyDenied.length, 16);
  assert.equal(proposed.counts.isolationViolations, 0); assert.equal(proposed.counts.selfApprovalViolations, 0); assert.equal(proposed.counts.roleConflicts, 0);
});
test('mutants expose tenant isolation and static/dynamic separation-of-duty failures separately', () => {
  const all = policies(); const domain = requestDomain();
  assert.ok(auditPolicy(all['unsafe-no-tenant-deny'], domain).counts.isolationViolations > 0);
  const inherited = auditPolicy(all['unsafe-inherited-approval'], domain);
  assert.equal(inherited.counts.roleConflicts, 2); assert.equal(inherited.counts.selfApprovalViolations, 0);
  const unsafe = auditPolicy(all['unsafe-self-approval'], domain);
  assert.equal(unsafe.counts.roleConflicts, 2); assert.equal(unsafe.counts.selfApprovalViolations, 2);
});
test('policies and explanation objects cannot mutate the compiled evaluator', () => {
  const policy = baselinePolicy(); const evaluator = new Evaluator(policy);
  const request = pick('blair', 'write', 'alpha-public-doc', 'corp-no-mfa');
  policy.rules = []; policy.roles[1].inherits = [];
  const explanation = evaluator.explain(request) as { rules: Array<{ conditions: Array<{ right: { value?: unknown } }> }> };
  for (const rule of explanation.rules) for (const condition of rule.conditions) condition.right.value = true;
  assert.equal(evaluator.evaluate(request).allowed, false);
});
test('domain violations and mismatched matrix comparisons are rejected', () => {
  const domain = requestDomain(); domain.resources[0].ownerId = 'erin'; assert.throws(() => validateDomain(domain, baselinePolicy()));
  const audit = auditPolicy(baselinePolicy(), requestDomain());
  assert.throws(() => difference(audit.matrix, [...audit.matrix].reverse()));
});
