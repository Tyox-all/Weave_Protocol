import type { Request } from 'express';

/**
 * A named route parameter as a string. Express 5 types every req.params
 * value as string | string[] (wildcard segments capture arrays); these
 * routes only use named segments, so join an array back into its path.
 */
export function param(req: Request, name: string): string {
  const value = req.params[name];
  return Array.isArray(value) ? value.join('/') : String(value ?? '');
}
