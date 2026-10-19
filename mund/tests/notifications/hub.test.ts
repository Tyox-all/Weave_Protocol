import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NotificationHub } from '../../src/notifications/index.js';
import type { INotifier, NotificationConfig, NotificationPayload } from '../../src/types.js';
import { makeConfig, makeEvent } from '../helpers.js';

function hubWith(notifications: NotificationConfig): NotificationHub {
  return new NotificationHub(makeConfig({ notifications }));
}

class RecordingNotifier implements INotifier {
  payloads: NotificationPayload[] = [];
  constructor(public name: string, private result: boolean | Error = true) {}
  async send(payload: NotificationPayload): Promise<boolean> {
    this.payloads.push(payload);
    if (this.result instanceof Error) throw this.result;
    return this.result;
  }
}

describe('NotificationHub', () => {
  beforeEach(() => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  describe('wiring from config', () => {
    it('configures no notifiers for an empty config', () => {
      const hub = hubWith({});
      expect(hub.hasNotifiers()).toBe(false);
      expect(hub.getNotifierNames()).toEqual([]);
    });

    it('wires every configured channel in order', () => {
      const hub = hubWith({
        slack: { webhook_url: 'https://hooks.slack.test/x' },
        teams: { webhook_url: 'https://teams.test/x' },
        email: {
          smtp_host: 'smtp.example.test',
          smtp_port: 25,
          smtp_secure: false,
          from_address: 'a@example.test',
          to_addresses: ['b@example.test'],
        },
        webhooks: [
          { url: 'https://hook1.test', method: 'POST' },
          { url: 'https://hook2.test', method: 'PUT' },
        ],
      });
      expect(hub.getNotifierNames()).toEqual([
        'SlackNotifier',
        'TeamsNotifier',
        'EmailNotifier',
        'WebhookNotifier',
        'WebhookNotifier',
      ]);
    });

    it('skips channels missing their required field', () => {
      const hub = hubWith({
        slack: { webhook_url: '' },
        teams: { webhook_url: '' },
        email: {
          smtp_host: '',
          smtp_port: 25,
          smtp_secure: false,
          from_address: 'a@example.test',
          to_addresses: [],
        },
      });
      expect(hub.hasNotifiers()).toBe(false);
    });
  });

  describe('notify()', () => {
    it('succeeds trivially when nothing is configured', async () => {
      await expect(hubWith({}).notify(makeEvent())).resolves.toEqual({ success: true, results: [] });
    });

    it('sends a formatted payload to every notifier', async () => {
      const hub = hubWith({});
      const a = new RecordingNotifier('A');
      const b = new RecordingNotifier('B');
      hub.addNotifier(a);
      hub.addNotifier(b);

      const event = makeEvent({ severity: 'critical', rule_name: 'AWS Key', content_snippet: 'AKIA...' });
      const result = await hub.notify(event);

      expect(result.success).toBe(true);
      expect(result.results).toEqual([
        { notifier: 'A', success: true, error: undefined },
        { notifier: 'B', success: true, error: undefined },
      ]);
      expect(a.payloads[0].event).toBe(event);
      expect(a.payloads[0].formatted_message).toBe('[CRITICAL] AWS Key: AKIA...');
      expect(b.payloads).toHaveLength(1);
    });

    it('reports failures and thrown errors without stopping other notifiers', async () => {
      const hub = hubWith({});
      hub.addNotifier(new RecordingNotifier('Fails', false));
      hub.addNotifier(new RecordingNotifier('Throws', new Error('boom')));
      const ok = new RecordingNotifier('Ok');
      hub.addNotifier(ok);

      const result = await hub.notify(makeEvent());

      expect(result.success).toBe(false);
      expect(result.results).toEqual([
        { notifier: 'Fails', success: false, error: 'Failed to send notification' },
        { notifier: 'Throws', success: false, error: 'boom' },
        { notifier: 'Ok', success: true, error: undefined },
      ]);
      expect(ok.payloads).toHaveLength(1);
    });

    it('reports the email stub as a failed delivery', async () => {
      const hub = hubWith({
        email: {
          smtp_host: 'smtp.example.test',
          smtp_port: 25,
          smtp_secure: false,
          from_address: 'a@example.test',
          to_addresses: ['b@example.test'],
        },
      });
      const result = await hub.notify(makeEvent());
      expect(result).toEqual({
        success: false,
        results: [{ notifier: 'EmailNotifier', success: false, error: 'Failed to send notification' }],
      });
    });

    it('posts to a configured webhook via fetch', async () => {
      const fetchMock = vi.fn().mockResolvedValue(new Response('ok', { status: 200 }));
      vi.stubGlobal('fetch', fetchMock);

      const hub = hubWith({ webhooks: [{ url: 'https://hook.test/ingest', method: 'POST' }] });
      const result = await hub.notify(makeEvent());

      expect(result.success).toBe(true);
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(fetchMock.mock.calls[0][0]).toBe('https://hook.test/ingest');
    });
  });

  it('removeNotifier() removes all notifiers with that name', () => {
    const hub = hubWith({});
    hub.addNotifier(new RecordingNotifier('A'));
    hub.addNotifier(new RecordingNotifier('B'));
    hub.addNotifier(new RecordingNotifier('A'));
    hub.removeNotifier('A');
    expect(hub.getNotifierNames()).toEqual(['B']);
  });
});
