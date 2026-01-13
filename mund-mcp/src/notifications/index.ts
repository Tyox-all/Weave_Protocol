/**
 * Mund - The Guardian Protocol
 * Notifications Index - Notification hub and exports
 */

export { SlackNotifier } from './slack.js';
export { TeamsNotifier } from './teams.js';
export { EmailNotifier } from './email.js';
export { WebhookNotifier } from './webhook.js';

import { SlackNotifier } from './slack.js';
import { TeamsNotifier } from './teams.js';
import { EmailNotifier } from './email.js';
import { WebhookNotifier } from './webhook.js';
import type { 
  INotifier, 
  NotificationConfig, 
  NotificationPayload, 
  SecurityEvent,
  MundConfig 
} from '../types.js';

/**
 * Notification Hub - Manages and dispatches notifications to all configured channels
 */
export class NotificationHub {
  private notifiers: INotifier[] = [];
  private config: MundConfig;

  constructor(config: MundConfig) {
    this.config = config;
    this.initializeNotifiers(config.notifications);
  }

  private initializeNotifiers(notificationConfig: NotificationConfig): void {
    // Slack
    if (notificationConfig.slack?.webhook_url) {
      this.notifiers.push(new SlackNotifier(notificationConfig.slack));
    }

    // Teams
    if (notificationConfig.teams?.webhook_url) {
      this.notifiers.push(new TeamsNotifier(notificationConfig.teams));
    }

    // Email
    if (notificationConfig.email?.smtp_host) {
      this.notifiers.push(new EmailNotifier(notificationConfig.email));
    }

    // Webhooks
    if (notificationConfig.webhooks) {
      for (const webhookConfig of notificationConfig.webhooks) {
        this.notifiers.push(new WebhookNotifier(webhookConfig));
      }
    }
  }

  /**
   * Send notification to all configured channels
   */
  async notify(event: SecurityEvent): Promise<{ success: boolean; results: NotificationResult[] }> {
    if (this.notifiers.length === 0) {
      return { success: true, results: [] };
    }

    const payload: NotificationPayload = {
      event,
      config: this.config,
      formatted_message: this.formatMessage(event)
    };

    const results: NotificationResult[] = [];

    for (const notifier of this.notifiers) {
      try {
        const success = await notifier.send(payload);
        results.push({
          notifier: notifier.name,
          success,
          error: success ? undefined : 'Failed to send notification'
        });
      } catch (error) {
        results.push({
          notifier: notifier.name,
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    }

    const allSuccessful = results.every(r => r.success);
    return { success: allSuccessful, results };
  }

  /**
   * Format a human-readable message
   */
  private formatMessage(event: SecurityEvent): string {
    return `[${event.severity.toUpperCase()}] ${event.rule_name}: ${event.content_snippet}`;
  }

  /**
   * Add a notifier at runtime
   */
  addNotifier(notifier: INotifier): void {
    this.notifiers.push(notifier);
  }

  /**
   * Remove a notifier by name
   */
  removeNotifier(name: string): void {
    this.notifiers = this.notifiers.filter(n => n.name !== name);
  }

  /**
   * Get list of configured notifiers
   */
  getNotifierNames(): string[] {
    return this.notifiers.map(n => n.name);
  }

  /**
   * Check if any notifiers are configured
   */
  hasNotifiers(): boolean {
    return this.notifiers.length > 0;
  }
}

interface NotificationResult {
  notifier: string;
  success: boolean;
  error?: string;
}
