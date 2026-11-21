import { mkdirSync, writeFileSync } from 'node:fs';
import { policies, requestDomain } from '../src/fixtures.ts';
const data = new URL('../data/', import.meta.url);
mkdirSync(new URL('policies/', data), { recursive: true });
writeFileSync(new URL('domain.json', data), JSON.stringify(requestDomain(), null, 2) + '\n');
for (const [name, policy] of Object.entries(policies())) writeFileSync(new URL(`policies/${name}.json`, data), JSON.stringify(policy, null, 2) + '\n');
console.log('Generated five synthetic policy documents and the explicit finite request domain.');
