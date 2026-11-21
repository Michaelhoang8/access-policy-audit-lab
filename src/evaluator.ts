import { validatePolicy, validateRequest, validateSubject } from './schema.ts';
import type { Policy, Rule, Request, Subject, Attribute } from './schema.ts';
export type Decision = { allowed: boolean; reason: 'explicit-deny' | 'allow-rule' | 'default-deny'; allowRules: string[]; denyRules: string[]; effectiveRoles: string[]; rolePaths: Record<string, string[][]> };
export function value(request: Request, attribute: Attribute): string | boolean {
  const [section, field] = attribute.split('.');
  return (request[section as 'subject' | 'resource' | 'context'] as unknown as Record<string, string | boolean>)[field];
}
const comparePath = (left: string[], right: string[]) => left.length - right.length || (left.join('/') < right.join('/') ? -1 : left.join('/') > right.join('/') ? 1 : 0);
export class Evaluator {
  #policy: Policy;
  #closures = new Map<string, Map<string, string[]>>();
  #byAction = new Map<string, Rule[]>();
  constructor(policy: Policy) {
    this.#policy = validatePolicy(policy); // Defensive copy; caller mutation cannot alter semantics.
    const roles = new Map(this.#policy.roles.map(role => [role.id, role]));
    const closure = (name: string): Map<string, string[]> => {
      const cached = this.#closures.get(name); if (cached) return cached;
      const paths = new Map<string, string[]>([[name, [name]]]);
      for (const parent of [...roles.get(name)!.inherits].sort()) for (const [ancestor, path] of closure(parent)) {
        const candidate = [name, ...path]; const current = paths.get(ancestor);
        if (!current || comparePath(candidate, current) < 0) paths.set(ancestor, candidate);
      }
      this.#closures.set(name, paths); return paths;
    };
    for (const role of roles.keys()) closure(role);
    this.#policy.rules.sort((a, b) => a.id < b.id ? -1 : 1);
    for (const action of ['read', 'write', 'submit', 'approve']) this.#byAction.set(action,
      this.#policy.rules.filter(rule => rule.actions.includes('*') || rule.actions.includes(action)));
  }
  effectiveRoles(subject: Subject): Map<string, string[]> {
    subject = validateSubject(subject, this.#policy.roles.map(role => role.id));
    const paths = new Map<string, string[]>();
    for (const role of [...subject.roles].sort()) {
      const inherited = this.#closures.get(role); if (!inherited) throw new Error('Subject has unknown assigned role');
      for (const [ancestor, path] of inherited) {
        const current = paths.get(ancestor);
        if (!current || comparePath(path, current) < 0) paths.set(ancestor, [...path]);
      }
    }
    return paths;
  }
  evaluate(request: Request): Decision {
    request = validateRequest(request, this.#policy.roles.map(role => role.id));
    const roles = this.effectiveRoles(request.subject);
    const allowRules: string[] = []; const denyRules: string[] = []; const rolePaths: Record<string, string[][]> = {};
    for (const rule of this.#byAction.get(request.action) ?? []) {
      if (!rule.resourceKinds.includes('*') && !rule.resourceKinds.includes(request.resource.kind)) continue;
      const matchingRoles = rule.roles.includes('*') ? [] : rule.roles.filter(role => roles.has(role)).sort();
      if (!rule.roles.includes('*') && matchingRoles.length === 0) continue;
      const matches = rule.conditions.every(condition => {
        const a = value(request, condition.left);
        const b = 'attribute' in condition.right ? value(request, condition.right.attribute) : condition.right.value;
        return condition.op === 'eq' ? a === b : a !== b;
      });
      if (!matches) continue;
      (rule.effect === 'deny' ? denyRules : allowRules).push(rule.id);
      rolePaths[rule.id] = matchingRoles.map(role => roles.get(role)!);
    }
    return { allowed: denyRules.length === 0 && allowRules.length > 0,
      reason: denyRules.length ? 'explicit-deny' : allowRules.length ? 'allow-rule' : 'default-deny', allowRules, denyRules,
      effectiveRoles: [...roles.keys()].sort(), rolePaths };
  }
  explain(request: Request): { request: Request; decision: Decision; rules: unknown[] } {
    request = validateRequest(request, this.#policy.roles.map(role => role.id));
    const roles = this.effectiveRoles(request.subject);
    return { request, decision: this.evaluate(request), rules: this.#policy.rules.map(rule => ({ ruleId: rule.id, effect: rule.effect,
      roleSelectorMatches: rule.roles.includes('*') || rule.roles.some(role => roles.has(role)),
      actionSelectorMatches: rule.actions.includes('*') || rule.actions.includes(request.action),
      resourceKindSelectorMatches: rule.resourceKinds.includes('*') || rule.resourceKinds.includes(request.resource.kind),
      conditions: rule.conditions.map(condition => {
        const leftValue = value(request, condition.left);
        const rightValue = 'attribute' in condition.right ? value(request, condition.right.attribute) : condition.right.value;
        return { ...condition, right: { ...condition.right }, leftValue, rightValue, passed: condition.op === 'eq' ? leftValue === rightValue : leftValue !== rightValue };
      }) })) };
  }
}
