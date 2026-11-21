import { readFileSync, statSync } from 'node:fs';
import { parseJson, validatePolicy, validateDomain, requests, requestId, MAX_DOCUMENT_BYTES } from '../src/schema.ts';
import { Evaluator } from '../src/evaluator.ts';
import { auditPolicy, difference } from '../src/audit.ts';
const help = `Usage: npm run cli -- <command> <arguments>
  validate <policy.json> <domain.json>
  explain <policy.json> <domain.json> <user/action/resource/context>
  compare <baseline.json> <candidate.json> <domain.json>
All analysis is offline over the supplied finite synthetic domain.
Exit 0: command completed (inspect decision/findings); exit 2: invalid input or failure.`;
const read = (file: string) => { if (statSync(file).size > MAX_DOCUMENT_BYTES) throw new Error('Document exceeds byte limit'); return parseJson(readFileSync(file)); };
function main(): void {
  const [command, ...args] = process.argv.slice(2);
  if (command === '--help' || command === '-h') { console.log(help); return; }
  try {
    if (command === 'validate' && args.length === 2) {
      const policy = validatePolicy(read(args[0])); const domain = validateDomain(read(args[1]), policy);
      console.log(JSON.stringify({ valid: true, roles: policy.roles.length, rules: policy.rules.length, requests: requests(domain).length }));
    } else if (command === 'explain' && args.length === 3) {
      const policy = validatePolicy(read(args[0])); const domain = validateDomain(read(args[1]), policy);
      const request = requests(domain).find(request => requestId(request) === args[2]);
      if (!request) throw new Error('Request is not in the allowed finite domain');
      console.log(JSON.stringify(new Evaluator(policy).explain(request), null, 2));
    } else if (command === 'compare' && args.length === 3) {
      const before = validatePolicy(read(args[0])); const after = validatePolicy(read(args[1])); const input = read(args[2]);
      const a = auditPolicy(before, validateDomain(input, before)); const b = auditPolicy(after, validateDomain(input, after));
      console.log(JSON.stringify({ baseline: a.counts, candidate: b.counts, changes: difference(a.matrix, b.matrix), findings: b.findings }, null, 2));
    } else throw new Error('Invalid command or arguments; use --help');
  } catch (error) { console.error(`Error: ${error instanceof Error ? error.message : 'unknown failure'}`); process.exitCode = 2; }
}
main();
