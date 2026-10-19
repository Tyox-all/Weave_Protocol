/**
 * Mund - The Guardian Protocol
 * Email Notifier - NOT IMPLEMENTED in v0.2.x.
 *
 * The nodemailer dependency was removed because it carried a
 * high-severity CVE and was never actually wired up (the previous
 * revision had only comments like "In a real implementation, use
 * nodemailer here"). Carrying a prod dep for a feature nobody uses
 * meant inheriting its CVE for no benefit.
 *
 * This stub keeps the INotifier contract so NotificationManager can
 * still wire it up when `notificationConfig.email.smtp_host` is set,
 * but every send() call returns false and logs a one-time warning,
 * so operators see email alerts aren't actually being delivered.
 *
 * When/if email notifications become a real feature:
 *   1. npm install nodemailer@^10 @types/nodemailer
 *   2. Replace this stub with a real implementation
 *   3. Add test fixtures under test/notifications/
 *   4. Remove the console.warn in the constructor
 */

import type { INotifier, NotificationPayload, EmailConfig } from '../types.js';

export class EmailNotifier implements INotifier {
  name = 'EmailNotifier';
  // Config is retained so a future real implementation can see what
  // shape to expect. Public (not private) because noUnusedLocals flags
  // unread private members even with an underscore prefix.
  readonly config: EmailConfig;
  private warned = false;

  constructor(config: EmailConfig) {
    this.config = config;
    console.warn(
      '[mund] EmailNotifier configured but NOT IMPLEMENTED in this version. ' +
        'Email alerts will be dropped. Use a webhook, Slack, or Teams notifier ' +
        'for actual delivery. Track at ' +
        'https://github.com/Tyox-all/Weave_Protocol/issues',
    );
  }

  async send(_payload: NotificationPayload): Promise<boolean> {
    if (!this.warned) {
      console.error(
        '[mund] EmailNotifier.send() called but email delivery is not ' +
          'implemented. Alert dropped. (This warning fires once per process.)',
      );
      this.warned = true;
    }
    return false;
  }
}

export default EmailNotifier;
