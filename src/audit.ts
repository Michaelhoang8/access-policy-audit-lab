import { performance } from 'node:perf_hooks';
import assert from 'node:assert/strict';
import { validatePolicy, validateDomain, requests, requestId } from './schema.ts';
import type { Policy, Domain } from './schema.ts';
import { Evaluator } from './evaluator.ts';
import type { Decision } from './evaluator.ts';
import { referenceEvaluate } from './reference.ts';
export type MatrixRow = { requestId: string; user: string; action: string; resource: string; context: string; decision: Decision };
export type RoleConflict = { user: string; pair: [string, string]; paths: string[][] };
export function auditPolicy(rawPolicy: Policy, rawDomain: Domain) {
  const policy = validatePolicy(rawPolicy); const domain = validateDomain(rawDomain, policy);
  const all = requests(domain); const evaluator = new Evaluator(policy);
  const start = performance.now();
  const matrix: MatrixRow[] = all.map(request => ({ requestId: requestId(request), user: request.subject.id, action: request.action,
    resource: request.resource.id, context: request.context.id, decision: evaluator.evaluate(request) }));
  const evaluationMs = performance.now() - start;
  const referenceStart = performance.now();
  all.forEach((request, index) => assert.deepEqual(matrix[index].decision, referenceEvaluate(policy, request)));
  const referenceAndComparisonMs = performance.now() - referenceStart;
  const isolation = all.filter((request, index) => domain.constraints.isolateTenants && matrix[index].decision.allowed && request.subject.tenant !== request.resource.tenant).map(requestId);
  const selfApproval = all.filter((request, index) => domain.constraints.prohibitSelfApproval && matrix[index].decision.allowed
    && request.action === 'approve' && request.subject.id === request.resource.ownerId).map(requestId);
  const roleConflicts: RoleConflict[] = [];
  for (const user of [...domain.users].sort((a, b) => a.id < b.id ? -1 : 1)) {
    const effective = evaluator.effectiveRoles(user);
    for (const pair of domain.constraints.exclusiveRolePairs) if (pair.every(role => effective.has(role))) {
      roleConflicts.push({ user: user.id, pair, paths: pair.map(role => effective.get(role)!) });
    }
  }
  const counts = { requests: matrix.length, allowed: matrix.filter(row => row.decision.allowed).length,
    explicitDeny: matrix.filter(row => row.decision.reason === 'explicit-deny').length,
    defaultDeny: matrix.filter(row => row.decision.reason === 'default-deny').length,
    allowAndDenyMatches: matrix.filter(row => row.decision.allowRules.length > 0 && row.decision.denyRules.length > 0).length,
    isolationViolations: isolation.length, selfApprovalViolations: selfApproval.length, roleConflicts: roleConflicts.length,
    referenceComparisons: matrix.length, evaluationMs, referenceAndComparisonMs };
  assert.equal(counts.allowed + counts.explicitDeny + counts.defaultDeny, counts.requests);
  return { counts, matrix, findings: { isolation, selfApproval, roleConflicts } };
}
export function difference(before: MatrixRow[], after: MatrixRow[]) {
  if (before.length !== after.length || before.some((row, index) => row.requestId !== after[index].requestId)) throw new Error('Cannot compare different ordered request domains');
  const newlyAllowed: string[] = []; const newlyDenied: string[] = [];
  const reasonChanged: string[] = [];
  before.forEach((row, index) => {
    if (!row.decision.allowed && after[index].decision.allowed) newlyAllowed.push(row.requestId);
    if (row.decision.allowed && !after[index].decision.allowed) newlyDenied.push(row.requestId);
    if (row.decision.reason !== after[index].decision.reason) reasonChanged.push(row.requestId);
  });
  return { newlyAllowed, newlyDenied, reasonChanged };
}
