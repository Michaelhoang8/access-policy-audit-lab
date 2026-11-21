import { readFileSync, writeFileSync, mkdirSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { platform, arch } from 'node:os';
import assert from 'node:assert/strict';
import { parseJson, validatePolicy, validateDomain, requests, requestId, MAX_REQUESTS } from '../src/schema.ts';
import { auditPolicy, difference } from '../src/audit.ts';
import { Evaluator } from '../src/evaluator.ts';
const root = fileURLToPath(new URL('../', import.meta.url));
const args = process.argv.slice(2);
if (args.includes('--help')) { console.log('Usage: npm run audit -- [--output results-local]'); process.exit(0); }
if (args.length !== 0 && (args.length !== 2 || args[0] !== '--output' || !args[1])) { console.error('Use --output <directory>'); process.exit(2); }
const output = resolve(root, args[1] ?? 'results');
for (const directory of [output, join(output, 'matrices'), join(output, 'diffs'), join(output, 'witnesses')]) mkdirSync(directory, { recursive: true });
const normalized = (file: string) => readFileSync(join(root, file), 'utf8').replace(/\r\n/g, '\n');
const sha = (text: string) => createHash('sha256').update(text).digest('hex');
const json = (name: string, value: unknown) => writeFileSync(join(output, name), JSON.stringify(value, null, 2) + '\n');
const quote = (value: unknown) => `"${String(value).replace(/"/g, '""')}"`;
const domainInput = parseJson(normalized('data/domain.json'));
const names = readdirSync(join(root, 'data/policies')).filter(file => file.endsWith('.json')).map(file => file.slice(0, -5)).sort();
if (!names.includes('baseline')) throw new Error('Missing baseline policy');
const parsed = Object.fromEntries(names.map(name => [name, validatePolicy(parseJson(normalized(`data/policies/${name}.json`)))]));
const domain = validateDomain(domainInput, parsed.baseline);
const allRequests = requests(domain); const byId = new Map(allRequests.map(request => [requestId(request), request]));
const audited = Object.fromEntries(names.map(name => [name, auditPolicy(parsed[name], validateDomain(domainInput, parsed[name]))]));
const baseline = audited.baseline; const baselineEvaluator = new Evaluator(parsed.baseline);
const summaries = [];
const witnessIndex: Array<{ policy: string; category: string; requestId?: string; user?: string; file: string }> = [];
for (const name of names) {
  const result = audited[name]; const evaluator = new Evaluator(parsed[name]);
  assert.equal(result.counts.requests, domain.users.length * domain.actions.length * domain.resources.length * domain.contexts.length);
  const matrixText = result.matrix.map(row => JSON.stringify(row)).join('\n') + '\n';
  writeFileSync(join(output, 'matrices', `${name}.jsonl`), matrixText);
  const fields = ['request_id', 'user', 'action', 'resource', 'context', 'allowed', 'reason', 'allow_rules', 'deny_rules', 'effective_roles', 'role_paths'];
  const csv = fields.join(',') + '\n' + result.matrix.map(row => [row.requestId, row.user, row.action, row.resource, row.context,
    row.decision.allowed, row.decision.reason, JSON.stringify(row.decision.allowRules), JSON.stringify(row.decision.denyRules),
    JSON.stringify(row.decision.effectiveRoles), JSON.stringify(row.decision.rolePaths)].map(quote).join(',')).join('\n') + '\n';
  writeFileSync(join(output, 'matrices', `${name}.csv`), csv);
  const diff = difference(baseline.matrix, result.matrix);
  json(`diffs/${name}.json`, { baseline: 'baseline', candidate: name, ...diff });
  const categories: Array<[string, string[]]> = [['newly-allowed', diff.newlyAllowed], ['newly-denied', diff.newlyDenied],
    ['tenant-isolation', result.findings.isolation], ['self-approval', result.findings.selfApproval]];
  for (const [category, ids] of categories) {
    if (!ids.length) continue;
    const id = ids[0]; const request = byId.get(id)!; const file = `witnesses/${name}-${category}.json`;
    json(file, { category, policy: name, requestId: id, minimality: 'first request in subject/action/resource/context lexical tuple order',
      candidatesInDomain: ids.length, baseline: baselineEvaluator.explain(request), candidate: evaluator.explain(request) });
    witnessIndex.push({ policy: name, category, requestId: id, file });
  }
  if (result.findings.roleConflicts.length) {
    const conflict = result.findings.roleConflicts[0]; const file = `witnesses/${name}-role-conflict.json`;
    json(file, { category: 'role-conflict', policy: name, minimality: 'first user in lexical order; one configured exclusive pair',
      ...conflict, allConflicts: result.findings.roleConflicts });
    witnessIndex.push({ policy: name, category: 'role-conflict', user: conflict.user, file });
  }
  json(`findings-${name}.json`, result.findings);
  summaries.push({ policy: name, enumeration: 'complete', ...result.counts, newlyAllowed: diff.newlyAllowed.length,
    newlyDenied: diff.newlyDenied.length, reasonChanged: diff.reasonChanged.length, matrixSha256: sha(matrixText) });
  console.log(`${name}: ${result.counts.requests} requests; ${result.counts.allowed} allow; +${diff.newlyAllowed.length}/-${diff.newlyDenied.length}; isolation=${result.counts.isolationViolations}; role-conflicts=${result.counts.roleConflicts}; self-approval=${result.counts.selfApprovalViolations}`);
}
json('summary.json', { domain: { users: domain.users.length, actions: domain.actions.length, resources: domain.resources.length,
  contexts: domain.contexts.length, requestsPerPolicy: allRequests.length, implementationMaximumRequests: MAX_REQUESTS },
  policyCount: names.length, totalReferenceComparisons: names.length * allRequests.length,
  witnessOrder: 'subject ID, action name, resource ID, context ID; each ascending ASCII', policies: summaries });
json('witness-index.json', witnessIndex);
const inputs = ['data/domain.json', ...names.map(name => `data/policies/${name}.json`)];
const sources = ['src/schema.ts', 'src/evaluator.ts', 'src/reference.ts', 'src/audit.ts', 'src/fixtures.ts', 'scripts/audit.ts'];
json('environment.json', { measuredAt: new Date().toISOString(), node: process.version, platform: platform(), architecture: arch(),
  hashEncoding: 'UTF-8; CRLF normalized to LF', inputSha256: Object.fromEntries(inputs.map(file => [file, sha(normalized(file))])),
  sourceSha256: Object.fromEntries(sources.map(file => [file, sha(normalized(file))])),
  scope: 'Offline finite synthetic domain; custom policy language; no real accounts and no AWS/IAM compatibility claim.',
  provenance: 'AI-assisted authorization analysis study. Complete matrices, reference comparisons and witnesses are actual executions.' });
