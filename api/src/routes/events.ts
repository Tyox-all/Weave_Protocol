/**
 * POST /api/v1/events  — a surface reports one enforcement decision
 * GET  /api/v1/events  — recent events, newest first (?limit=, max 500)
 *
 * Surfaces send these through Ward's reportEvent() when
 * WEAVE_DASHBOARD_URL points here. Auth is the API key like every route.
 */

import { Router, Request, Response } from 'express';
import { events } from '../services/events.js';

const router = Router();

router.post('/', (req: Request, res: Response) => {
  const result = events.add(req.body);
  if ('error' in result) return res.status(400).json(result);
  res.status(201).json({ id: result.id });
});

router.get('/', (req: Request, res: Response) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 500);
  res.json({ events: events.recent(limit), total: events.size });
});

export { router as eventsRoutes };
