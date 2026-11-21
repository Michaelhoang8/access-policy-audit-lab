export const ACTIONS = ['read', 'write', 'submit', 'approve'] as const;
export const KINDS = ['document', 'payment'] as const;
export const ATTRIBUTES = ['subject.id', 'subject.tenant', 'resource.id', 'resource.tenant', 'resource.kind', 'resource.classification', 'resource.ownerId', 'context.network', 'context.mfa'] as const;
export type Action = typeof ACTIONS[number];
export type Kind = typeof KINDS[number];
export type Attribute = typeof ATTRIBUTES[number];
export type Condition = { left: Attribute; op: 'eq' | 'neq'; right: { attribute: Attribute } | { value: string | boolean } };
export type Role = { id: string; inherits: string[] };
export type Rule = { id: string; effect: 'allow' | 'deny'; roles: string[]; actions: string[]; resourceKinds: string[]; conditions: Condition[] };
export type Policy = { version: 1; roles: Role[]; rules: Rule[] };
export type Subject = { id: string; tenant: string; roles: string[] };
export type Resource = { id: string; tenant: string; kind: Kind; classification: 'public' | 'internal' | 'restricted'; ownerId: string };
export type Context = { id: string; network: 'corporate' | 'public'; mfa: boolean };
export type Domain = { version: 1; users: Subject[]; actions: Action[]; resources: Resource[]; contexts: Context[];
  constraints: { isolateTenants: boolean; prohibitSelfApproval: boolean; exclusiveRolePairs: Array<[string, string]> } };
export type Request = { subject: Subject; action: Action; resource: Resource; context: Context };
export const MAX_DOCUMENT_BYTES = 65536;
export const MAX_REQUESTS = 4096;

function object(input: unknown, fields: string[]): Record<string, unknown> {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Expected an object');
  const row = input as Record<string, unknown>;
  if (Object.keys(row).sort().join(',') !== [...fields].sort().join(',')) throw new Error('Unexpected or missing fields');
  return row;
}
function id(value: unknown): string {
  if (typeof value !== 'string' || !/^[a-z][a-z0-9-]{0,47}$/.test(value)) throw new Error('Invalid identifier');
  return value;
}
function list<T>(input: unknown, maximum: number, parse: (value: unknown) => T, minimum = 0): T[] {
  if (!Array.isArray(input) || input.length < minimum || input.length > maximum) throw new Error('Invalid bounded array');
  return input.map(parse);
}
function unique(values: string[]): string[] {
  if (new Set(values).size !== values.length) throw new Error('Duplicate identifiers or selector values');
  return values;
}
function enumeration<T extends string>(input: unknown, values: readonly T[]): T {
  if (typeof input !== 'string' || !values.includes(input as T)) throw new Error('Unknown enum value');
  return input as T;
}
const boolean = (input: unknown): boolean => { if (typeof input !== 'boolean') throw new Error('Expected boolean'); return input; };
const attributeType = (attribute: Attribute) => attribute === 'context.mfa' ? 'boolean' : 'string';
function condition(input: unknown): Condition {
  const row = object(input, ['left', 'op', 'right']);
  const left = enumeration(row.left, ATTRIBUTES); const op = enumeration(row.op, ['eq', 'neq']);
  if (!row.right || typeof row.right !== 'object' || Array.isArray(row.right)) throw new Error('Invalid predicate operand');
  if ('attribute' in row.right) {
    const right = object(row.right, ['attribute']); const attribute = enumeration(right.attribute, ATTRIBUTES);
    if (attributeType(left) !== attributeType(attribute)) throw new Error('Predicate attribute types differ');
    return { left, op, right: { attribute } };
  }
  const right = object(row.right, ['value']);
  if (typeof right.value !== attributeType(left)) throw new Error('Predicate constant has wrong type');
  if (typeof right.value === 'string' && (Buffer.byteLength(right.value) > 64 || Buffer.from(right.value).toString('utf8') !== right.value)) throw new Error('Invalid predicate constant');
  return { left, op, right: { value: right.value as string | boolean } };
}
const selector = (input: unknown, allowed: string[]) => {
  const values = unique(list(input, Math.max(allowed.length, 1), value => enumeration(value, [...allowed, '*']), 1));
  if (values.includes('*') && values.length !== 1) throw new Error('Wildcard must be the only selector');
  return values;
};

export function validatePolicy(input: unknown): Policy {
  const row = object(input, ['version', 'roles', 'rules']); if (row.version !== 1) throw new Error('Unsupported policy version');
  const roles = list(row.roles, 16, value => {
    const role = object(value, ['id', 'inherits']);
    return { id: id(role.id), inherits: unique(list(role.inherits, 16, id)) };
  }, 1);
  const ids = unique(roles.map(role => role.id)); const byId = new Map(roles.map(role => [role.id, role]));
  for (const role of roles) for (const parent of role.inherits) if (!byId.has(parent)) throw new Error('Unknown inherited role');
  const visiting = new Set<string>(); const visited = new Set<string>();
  const visit = (role: string) => {
    if (visiting.has(role)) throw new Error('Role inheritance cycle');
    if (visited.has(role)) return;
    visiting.add(role); for (const parent of byId.get(role)!.inherits) visit(parent); visiting.delete(role); visited.add(role);
  };
  for (const role of ids) visit(role);
  const rules = list(row.rules, 32, value => {
    const rule = object(value, ['id', 'effect', 'roles', 'actions', 'resourceKinds', 'conditions']);
    return { id: id(rule.id), effect: enumeration(rule.effect, ['allow', 'deny']), roles: selector(rule.roles, ids),
      actions: selector(rule.actions, [...ACTIONS]), resourceKinds: selector(rule.resourceKinds, [...KINDS]),
      conditions: list(rule.conditions, 8, condition) };
  });
  unique(rules.map(rule => rule.id));
  return { version: 1, roles, rules };
}

export function validateDomain(input: unknown, policy: Policy): Domain {
  const row = object(input, ['version', 'users', 'actions', 'resources', 'contexts', 'constraints']);
  if (row.version !== 1) throw new Error('Unsupported domain version');
  const roleIds = policy.roles.map(role => role.id);
  const users = list(row.users, 16, value => {
    const user = object(value, ['id', 'tenant', 'roles']);
    return { id: id(user.id), tenant: id(user.tenant), roles: unique(list(user.roles, 16, role => enumeration(role, roleIds))) };
  }, 1);
  unique(users.map(user => user.id));
  const resources = list(row.resources, 16, value => {
    const resource = object(value, ['id', 'tenant', 'kind', 'classification', 'ownerId']);
    const owner = users.find(user => user.id === resource.ownerId);
    if (!owner || owner.tenant !== resource.tenant) throw new Error('Resource owner must exist in the same tenant');
    return { id: id(resource.id), tenant: id(resource.tenant), kind: enumeration(resource.kind, KINDS),
      classification: enumeration(resource.classification, ['public', 'internal', 'restricted']), ownerId: id(resource.ownerId) };
  }, 1);
  unique(resources.map(resource => resource.id));
  const actions = unique(list(row.actions, 4, action => enumeration(action, ACTIONS), 1)) as Action[];
  const contexts = list(row.contexts, 4, value => {
    const context = object(value, ['id', 'network', 'mfa']);
    return { id: id(context.id), network: enumeration(context.network, ['corporate', 'public']), mfa: boolean(context.mfa) };
  }, 1);
  unique(contexts.map(context => context.id)); unique(contexts.map(context => `${context.network}:${context.mfa}`));
  const constraints = object(row.constraints, ['isolateTenants', 'prohibitSelfApproval', 'exclusiveRolePairs']);
  const pairs = list(constraints.exclusiveRolePairs, 16, value => {
    const pair = unique(list(value, 2, role => enumeration(role, roleIds), 2));
    return [...pair].sort() as [string, string];
  });
  unique(pairs.map(pair => pair.join(':')));
  const domain: Domain = { version: 1, users, actions, resources, contexts, constraints: { isolateTenants: boolean(constraints.isolateTenants),
    prohibitSelfApproval: boolean(constraints.prohibitSelfApproval), exclusiveRolePairs: pairs } };
  if (users.length * actions.length * resources.length * contexts.length > MAX_REQUESTS) throw new Error('Request domain exceeds complete enumeration bound');
  return domain;
}

export function validateSubject(input: unknown, knownRoles: string[]): Subject {
  const subject = object(input, ['id', 'tenant', 'roles']);
  return { id: id(subject.id), tenant: id(subject.tenant), roles: unique(list(subject.roles, 16, role => enumeration(role, knownRoles))) };
}

export function validateRequest(input: unknown, knownRoles: string[]): Request {
  const row = object(input, ['subject', 'action', 'resource', 'context']);
  const resource = object(row.resource, ['id', 'tenant', 'kind', 'classification', 'ownerId']);
  const context = object(row.context, ['id', 'network', 'mfa']);
  return { subject: validateSubject(row.subject, knownRoles), action: enumeration(row.action, ACTIONS),
    resource: { id: id(resource.id), tenant: id(resource.tenant), kind: enumeration(resource.kind, KINDS),
      classification: enumeration(resource.classification, ['public', 'internal', 'restricted']), ownerId: id(resource.ownerId) },
    context: { id: id(context.id), network: enumeration(context.network, ['corporate', 'public']), mfa: boolean(context.mfa) } };
}

export function parseJson(bytes: Uint8Array | string): unknown {
  const buffer = typeof bytes === 'string' ? Buffer.from(bytes, 'utf8') : bytes;
  if (buffer.byteLength > MAX_DOCUMENT_BYTES) throw new Error('Document exceeds byte bound');
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(buffer);
  const parsed: unknown = JSON.parse(text);
  let compact = ''; let quoted = false; let escaped = false;
  for (const char of text) {
    if (quoted) {
      compact += char;
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') quoted = false;
    } else if (char === '"') { quoted = true; compact += char; }
    else if (!/\s/.test(char)) compact += char;
  }
  if (JSON.stringify(parsed) !== compact) throw new Error('Duplicate keys or noncanonical JSON token encoding');
  return parsed;
}

export function requests(domain: Domain): Request[] {
  const result: Request[] = [];
  const ordered = <T extends { id: string }>(values: T[]) => [...values].sort((a, b) => a.id < b.id ? -1 : 1);
  for (const subject of ordered(domain.users)) for (const action of [...domain.actions].sort())
    for (const resource of ordered(domain.resources)) for (const context of ordered(domain.contexts)) result.push({ subject, action, resource, context });
  return result;
}
export function requestId(request: Request): string { return [request.subject.id, request.action, request.resource.id, request.context.id].join('/'); }
