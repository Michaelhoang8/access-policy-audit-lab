import type { Policy, Domain, Rule, Condition } from './schema.ts';
const literal = (left: Condition['left'], value: string | boolean, op: 'eq' | 'neq' = 'eq'): Condition => ({ left, op, right: { value } });
const attribute = (left: Condition['left'], right: Condition['left'], op: 'eq' | 'neq' = 'eq'): Condition => ({ left, op, right: { attribute: right } });
export function baselinePolicy(): Policy {
  const deny = (id: string, actions: string[], conditions: Condition[]): Rule => ({ id, effect: 'deny', roles: ['*'], actions, resourceKinds: ['*'], conditions });
  const allow = (id: string, role: string, actions: string[], kinds: string[]): Rule => ({ id, effect: 'allow', roles: [role], actions, resourceKinds: kinds, conditions: [] });
  return { version: 1, roles: [{ id: 'viewer', inherits: [] }, { id: 'editor', inherits: ['viewer'] },
    { id: 'requester', inherits: ['viewer'] }, { id: 'approver', inherits: ['viewer'] }], rules: [
    allow('allow-view', 'viewer', ['read'], ['*']),
    allow('allow-edit', 'editor', ['write'], ['document']),
    allow('allow-submit', 'requester', ['submit'], ['payment']),
    allow('allow-approve', 'approver', ['approve'], ['payment']),
    deny('deny-tenant-boundary', ['*'], [attribute('subject.tenant', 'resource.tenant', 'neq')]),
    deny('deny-mutation-without-mfa', ['write', 'submit', 'approve'], [literal('context.mfa', false)]),
    deny('deny-restricted-read-without-mfa', ['read'], [literal('resource.classification', 'restricted'), literal('context.mfa', false)]),
    deny('deny-public-approval', ['approve'], [literal('context.network', 'public')]),
    deny('deny-self-approval', ['approve'], [attribute('subject.id', 'resource.ownerId')]),
  ] };
}
export function policies(): Record<string, Policy> {
  const baseline = baselinePolicy();
  const proposed = baselinePolicy();
  proposed.rules = proposed.rules.filter(rule => rule.id !== 'deny-public-approval');
  proposed.rules.push({ id: 'deny-public-restricted-read', effect: 'deny', roles: ['*'], actions: ['read'], resourceKinds: ['*'],
    conditions: [literal('context.network', 'public'), literal('resource.classification', 'restricted')] });
  const tenant = baselinePolicy(); tenant.rules = tenant.rules.filter(rule => rule.id !== 'deny-tenant-boundary');
  const inherited = baselinePolicy(); inherited.roles.find(role => role.id === 'requester')!.inherits.push('approver');
  const self = structuredClone(inherited); self.rules = self.rules.filter(rule => rule.id !== 'deny-self-approval');
  return { baseline, proposed, 'unsafe-no-tenant-deny': tenant, 'unsafe-inherited-approval': inherited, 'unsafe-self-approval': self };
}
export function requestDomain(): Domain {
  return { version: 1, users: [
    { id: 'alex', tenant: 'alpha', roles: ['viewer'] }, { id: 'blair', tenant: 'alpha', roles: ['editor'] },
    { id: 'casey', tenant: 'alpha', roles: ['requester'] }, { id: 'drew', tenant: 'alpha', roles: ['approver'] },
    { id: 'erin', tenant: 'beta', roles: ['viewer'] }, { id: 'frank', tenant: 'beta', roles: ['editor'] },
    { id: 'gale', tenant: 'beta', roles: ['requester'] }, { id: 'harper', tenant: 'beta', roles: ['approver'] },
    { id: 'guest', tenant: 'alpha', roles: [] },
  ], actions: ['read', 'write', 'submit', 'approve'], resources: [
    { id: 'alpha-public-doc', tenant: 'alpha', kind: 'document', classification: 'public', ownerId: 'alex' },
    { id: 'alpha-internal-doc', tenant: 'alpha', kind: 'document', classification: 'internal', ownerId: 'blair' },
    { id: 'alpha-restricted-doc', tenant: 'alpha', kind: 'document', classification: 'restricted', ownerId: 'casey' },
    { id: 'alpha-payment', tenant: 'alpha', kind: 'payment', classification: 'restricted', ownerId: 'casey' },
    { id: 'beta-public-doc', tenant: 'beta', kind: 'document', classification: 'public', ownerId: 'erin' },
    { id: 'beta-internal-doc', tenant: 'beta', kind: 'document', classification: 'internal', ownerId: 'frank' },
    { id: 'beta-restricted-doc', tenant: 'beta', kind: 'document', classification: 'restricted', ownerId: 'gale' },
    { id: 'beta-payment', tenant: 'beta', kind: 'payment', classification: 'restricted', ownerId: 'gale' },
  ], contexts: [
    { id: 'corp-mfa', network: 'corporate', mfa: true }, { id: 'corp-no-mfa', network: 'corporate', mfa: false },
    { id: 'public-mfa', network: 'public', mfa: true }, { id: 'public-no-mfa', network: 'public', mfa: false },
  ], constraints: { isolateTenants: true, prohibitSelfApproval: true, exclusiveRolePairs: [['requester', 'approver']] } };
}
