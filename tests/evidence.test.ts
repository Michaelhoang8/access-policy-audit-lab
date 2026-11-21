import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { parseJson, validatePolicy, validateDomain, requests, requestId } from '../src/schema.ts';
import { auditPolicy, difference } from '../src/audit.ts';
import type { MatrixRow } from '../src/audit.ts';
import { Evaluator } from '../src/evaluator.ts';
const read = (file: string) => readFileSync(new URL(`../${file}`, import.meta.url), 'utf8').replace(/\r\n/g, '\n');
const json = <T>(file: string): T => JSON.parse(read(file)) as T;
type Summary = { domain: { requestsPerPolicy: number }; totalReferenceComparisons: number; policies: Array<{ policy: string; matrixSha256: string; [key: string]: string | number }> };
const summary = json<Summary>('results/summary.json');
const environment = json<{ inputSha256: Record<string, string>; sourceSha256: Record<string, string> }>('results/environment.json');

test('preserved source and policy/domain input hashes match the audited files', () => {
  for (const [file, expected] of Object.entries({ ...environment.inputSha256, ...environment.sourceSha256 })) {
    assert.equal(createHash('sha256').update(read(file)).digest('hex'), expected, file);
  }
});

test('every preserved matrix row, finding and delta reproduces over the exact complete domain', () => {
  const domainInput = parseJson(read('data/domain.json'));
  const all = Object.fromEntries(summary.policies.map(row => {
    const policy = validatePolicy(parseJson(read(`data/policies/${row.policy}.json`)));
    const audit = auditPolicy(policy, validateDomain(domainInput, policy));
    const text = read(`results/matrices/${row.policy}.jsonl`);
    assert.equal(createHash('sha256').update(text).digest('hex'), row.matrixSha256);
    const matrix = text.trim().split('\n').map(line => JSON.parse(line) as MatrixRow);
    assert.equal(matrix.length, summary.domain.requestsPerPolicy);
    assert.equal(new Set(matrix.map(item => item.requestId)).size, matrix.length);
    assert.deepEqual(matrix, audit.matrix);
    assert.deepEqual(json(`results/findings-${row.policy}.json`), audit.findings);
    for (const key of ['requests', 'allowed', 'explicitDeny', 'defaultDeny', 'allowAndDenyMatches', 'isolationViolations', 'selfApprovalViolations', 'roleConflicts', 'referenceComparisons'] as const) {
      assert.equal(row[key], audit.counts[key]);
    }
    return [row.policy, audit];
  }));
  assert.equal(summary.totalReferenceComparisons, summary.policies.length * summary.domain.requestsPerPolicy);
  for (const row of summary.policies) {
    const diff = difference(all.baseline.matrix, all[row.policy].matrix);
    assert.deepEqual(json(`results/diffs/${row.policy}.json`), { baseline: 'baseline', candidate: row.policy, ...diff });
    assert.equal(row.newlyAllowed, diff.newlyAllowed.length); assert.equal(row.newlyDenied, diff.newlyDenied.length);
    assert.equal(row.reasonChanged, diff.reasonChanged.length);
  }
});

test('stored witnesses are the first actual findings and their explanations replay exactly', () => {
  const index = json<Array<{ policy: string; category: string; requestId?: string; user?: string; file: string }>>('results/witness-index.json');
  const baseline = validatePolicy(parseJson(read('data/policies/baseline.json')));
  const input = parseJson(read('data/domain.json')); const baseDomain = validateDomain(input, baseline);
  const before = auditPolicy(baseline, baseDomain); const requestMap = new Map(requests(baseDomain).map(request => [requestId(request), request]));
  for (const record of index) {
    const policy = validatePolicy(parseJson(read(`data/policies/${record.policy}.json`)));
    const current = auditPolicy(policy, validateDomain(input, policy)); const diff = difference(before.matrix, current.matrix);
    const witness = json<Record<string, unknown>>(`results/${record.file}`);
    if (record.category === 'role-conflict') {
      assert.equal(record.user, current.findings.roleConflicts[0].user);
      assert.deepEqual(witness.allConflicts, current.findings.roleConflicts);
      assert.deepEqual(witness.paths, current.findings.roleConflicts[0].paths);
    } else {
      const ids = record.category === 'newly-allowed' ? diff.newlyAllowed : record.category === 'newly-denied' ? diff.newlyDenied
        : record.category === 'tenant-isolation' ? current.findings.isolation : current.findings.selfApproval;
      assert.equal(record.requestId, ids[0]); assert.equal(witness.candidatesInDomain, ids.length);
      const request = requestMap.get(ids[0])!;
      assert.deepEqual(witness.baseline, new Evaluator(baseline).explain(request));
      assert.deepEqual(witness.candidate, new Evaluator(policy).explain(request));
    }
  }
});
