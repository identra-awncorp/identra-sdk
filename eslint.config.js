// ESLint flat config. The second block enforces the sdk-core boundary of ADR-0005 and
// docs/architecture.md section 1: no platform library, no platform global, no implicit clock or
// randomness. Only the webcrypto entry may touch globalThis.crypto.
import tseslint from 'typescript-eslint';

const PLATFORM_GLOBALS = ['crypto', 'Buffer', 'process', 'fetch', 'window', 'document'];
// Ways to reach the platform indirectly: `const g = globalThis; g.crypto`, `Reflect.construct(Date, [])`.
const INDIRECT_GLOBALS = ['globalThis', 'self', 'global', 'performance', 'Reflect'];

export default tseslint.config(
  { ignores: ['**/dist/**', '**/test-dist/**', '**/node_modules/**', '.pki/**'] },
  ...tseslint.configs.recommended,
  {
    files: ['packages/core/src/**/*.ts'],
    ignores: ['packages/core/src/webcrypto/**'],
    rules: {
      'no-restricted-imports': [
        'error',
        { patterns: ['node:*', 'jose', 'jose/*', 'expo-*', 'react-native', 'react-native/*', '@noble/*'] },
      ],
      'no-restricted-globals': ['error', ...PLATFORM_GLOBALS, ...INDIRECT_GLOBALS],
      'no-restricted-properties': [
        'error',
        ...PLATFORM_GLOBALS.map((property) => ({ object: 'globalThis', property })),
        { object: 'Date', property: 'now', message: 'The clock is injected.' },
        { object: 'Math', property: 'random', message: 'Randomness comes from RandomSource.' },
      ],
      'no-restricted-syntax': [
        'error',
        { selector: "NewExpression[callee.name='Date'][arguments.length=0]", message: 'The clock is injected.' },
        { selector: "CallExpression[callee.name='Date']", message: 'The clock is injected.' },
        { selector: 'ImportExpression', message: 'No dynamic import in sdk-core.' },
      ],
    },
  },
  // sdk-app runs on React Native / Hermes and Node: pure JS on @noble/*, everything else injected.
  {
    files: ['packages/app/src/**/*.ts'],
    rules: {
      'no-restricted-imports': [
        'error',
        { patterns: ['node:*', 'jose', 'jose/*', 'expo-*', 'react-native', 'react-native/*', '@identra/sdk-core/webcrypto'] },
      ],
      'no-restricted-globals': ['error', ...PLATFORM_GLOBALS],
      'no-restricted-properties': [
        'error',
        ...PLATFORM_GLOBALS.map((property) => ({ object: 'globalThis', property })),
        { object: 'Date', property: 'now', message: 'The clock is injected.' },
        { object: 'Math', property: 'random', message: 'Randomness comes from RandomSource.' },
      ],
      'no-restricted-syntax': [
        'error',
        { selector: "NewExpression[callee.name='Date'][arguments.length=0]", message: 'The clock is injected.' },
        { selector: "CallExpression[callee.name='Date']", message: 'The clock is injected.' },
      ],
    },
  },
);
