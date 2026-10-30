import { createHash, timingSafeEqual } from 'node:crypto';
/**
 * API Key Authentication Middleware
 */

import { Request, Response, NextFunction } from 'express';

/** Constant-time key comparison (hash first so lengths always match). */
function keyMatches(given: string, expected: string): boolean {
  if (!expected) return false;
  const a = createHash('sha256').update(given).digest();
  const b = createHash('sha256').update(expected).digest();
  return timingSafeEqual(a, b);
}

export function apiKeyAuth(req: Request, res: Response, next: NextFunction) {
  const apiKey = req.headers['x-api-key'] || req.headers['authorization']?.replace('Bearer ', '');
  
  if (!apiKey) {
    return res.status(401).json({ error: 'API key required' });
  }
  
  if (!keyMatches(String(apiKey), process.env.WEAVE_API_KEY ?? '')) {
    return res.status(403).json({ error: 'Invalid API key' });
  }
  
  next();
}

/**
 * Request Logger Middleware
 */

export function requestLogger(req: Request, _res: Response, next: NextFunction) {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.path}`);
  next();
}
