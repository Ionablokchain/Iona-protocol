/**
 * Iona TypeScript SDK
 * 
 * This SDK is automatically generated from the OpenAPI specification located at
 * `api/openapi.yaml`. The generated code is not committed to the repository;
 * instead, it is generated at build time or when setting up the development environment.
 * 
 * ## Generating the SDK
 * 
 * We recommend using [openapi-typescript-codegen](https://github.com/ferdikoomen/openapi-typescript-codegen)
 * to generate the client. Install it globally or as a dev dependency:
 * 
 * ```bash
 * npm install --save-dev openapi-typescript-codegen
 * ```
 * 
 * Then generate the SDK with:
 * 
 * ```bash
 * npx openapi-typescript-codegen --input ../../api/openapi.yaml --output ./generated --client axios
 * ```
 * 
 * After generation, the SDK will be available in the `./generated` folder.
 * You can then import it in your project:
 * 
 * ```typescript
 * import { IonaClient } from './generated';
 * 
 * const client = new IonaClient({ BASE: 'http://localhost:26657' });
 * 
 * async function example() {
 *   const status = await client.status.getStatus();
 *   console.log(status);
 * }
 * ```
 * 
 * For convenience, we export all generated types and services from this entry point.
 */

// After generating the SDK, uncomment the following line:
// export * from './generated';

// Placeholder for development – remove once SDK is generated.
console.warn(
  'Iona TypeScript SDK not generated. Run "npm run generate-sdk" to generate it from the OpenAPI spec.'
);
