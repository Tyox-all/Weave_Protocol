import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EmailNotifier } from '../../src/notifications/email.js';
import type { EmailConfig } from '../../src/types.js';
import { makeConfig, makeEvent } from '../helpers.js';

const emailConfig: EmailConfig = {
  smtp_host: 'smtp.example.test',
  smtp_port: 587,
  smtp_secure: true,
  from_address: 'mund@example.test',
  to_addresses: ['ops@example.test'],
};

const payload = () => ({
  event: makeEvent(),
  config: makeConfig(),
  formatted_message: '[HIGH] Test Rule: AKIA****',
});

describe('EmailNotifier (stub)', () => {
  let warnSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('warns at construction that email is not implemented', () => {
    new EmailNotifier(emailConfig);
    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(String(warnSpy.mock.calls[0][0])).toMatch(/NOT IMPLEMENTED/);
  });

  it('keeps the config and notifier name', () => {
    const notifier = new EmailNotifier(emailConfig);
    expect(notifier.name).toBe('EmailNotifier');
    expect(notifier.config).toBe(emailConfig);
  });

  it('send() always returns false', async () => {
    const notifier = new EmailNotifier(emailConfig);
    await expect(notifier.send(payload())).resolves.toBe(false);
    await expect(notifier.send(payload())).resolves.toBe(false);
  });

  it('logs the send() error only once per instance', async () => {
    const notifier = new EmailNotifier(emailConfig);
    await notifier.send(payload());
    await notifier.send(payload());
    await notifier.send(payload());
    expect(errorSpy).toHaveBeenCalledTimes(1);
    expect(String(errorSpy.mock.calls[0][0])).toMatch(/Alert dropped/);
  });

  it('tracks the one-time warning per instance, not globally', async () => {
    const a = new EmailNotifier(emailConfig);
    const b = new EmailNotifier(emailConfig);
    await a.send(payload());
    await a.send(payload());
    await b.send(payload());
    expect(errorSpy).toHaveBeenCalledTimes(2);
  });
});
