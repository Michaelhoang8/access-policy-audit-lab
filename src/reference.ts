import type { Policy, Request, Attribute } from './schema.ts';
import type { Decision } from './evaluator.ts';

// Deliberately straightforward reference: breadth-first role expansion and a full
// scan of every rule, with independent attribute lookup and predicate evaluation.
export function referenceEvaluate(policy: Policy, request: Request): Decision {
  const queue = [...request.subject.roles].sort().map(role => [role]);
  const paths = new Map<string, string[]>();
  while (queue.length) {
    queue.sort((a, b) => a.length - b.length || (a.join('/') < b.join('/') ? -1 : 1));
    const path = queue.shift()!; const role = path.at(-1)!;
    if (paths.has(role)) continue;
    const definition = policy.roles.find(candidate => candidate.id === role);
    if (!definition) throw new Error('Reference found unknown assigned role');
    paths.set(role, path);
    for (const parent of definition.inherits) queue.push([...path, parent]);
  }
  const attribute = (name: Attribute): string | boolean => {
    switch (name) {
      case 'subject.id': return request.subject.id;
      case 'subject.tenant': return request.subject.tenant;
      case 'resource.id': return request.resource.id;
      case 'resource.tenant': return request.resource.tenant;
      case 'resource.kind': return request.resource.kind;
      case 'resource.classification': return request.resource.classification;
      case 'resource.ownerId': return request.resource.ownerId;
      case 'context.network': return request.context.network;
      case 'context.mfa': return request.context.mfa;
    }
  };
  const matches = policy.rules.filter(rule => {
    if (!rule.actions.some(action => action === '*' || action === request.action)) return false;
    if (!rule.resourceKinds.some(kind => kind === '*' || kind === request.resource.kind)) return false;
    if (!rule.roles.some(role => role === '*' || paths.has(role))) return false;
    for (const condition of rule.conditions) {
      const a = attribute(condition.left);
      const b = 'value' in condition.right ? condition.right.value : attribute(condition.right.attribute);
      if (condition.op === 'eq' && a !== b || condition.op === 'neq' && a === b) return false;
    }
    return true;
  }).sort((a, b) => a.id < b.id ? -1 : 1);
  const allowRules = matches.filter(rule => rule.effect === 'allow').map(rule => rule.id);
  const denyRules = matches.filter(rule => rule.effect === 'deny').map(rule => rule.id);
  const rolePaths = Object.fromEntries(matches.map(rule => [rule.id, rule.roles.includes('*') ? []
    : rule.roles.filter(role => paths.has(role)).sort().map(role => paths.get(role)!)]));
  return { allowed: denyRules.length === 0 && allowRules.length > 0,
    reason: denyRules.length > 0 ? 'explicit-deny' : allowRules.length > 0 ? 'allow-rule' : 'default-deny',
    allowRules, denyRules, effectiveRoles: [...paths.keys()].sort(), rolePaths };
}
