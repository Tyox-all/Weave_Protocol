/**
 * Mund - The Guardian Protocol
 * Webhook Notifier - Send alerts to generic webhooks
 */

import type { INotifier, NotificationPayload, WebhookConfig, Severity } from '../types.js';

export class WebhookNotifier implements INotifier {
  name = 'WebhookNotifier';
  private config: WebhookConfig;

  constructor(config: WebhookConfig) {
    this.config = config;
  }

  async send(payload: NotificationPayload): Promise<boolean> {
    const { event } = payload;

    // Check minimum severity
    if (this.config.min_severity && !this.meetsMinSeverity(event.severity, this.config.min_severity)) {
      return true; // Successfully skipped
    }

    const webhookPayload = this.formatPayload(payload);

    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        ...this.config.headers
      };

      const response = await fetch(this.config.url, {
        method: this.config.method,
        headers,
        body: JSON.stringify(webhookPayload)
      });

      if (!response.ok) {
        console.error(`Webhook notification failed: ${response.status} ${response.statusText}`);
        return false;
      }

      return true;
    } catch (error) {
      console.error('Failed to send webhook notification:', error);
      return false;
    }
  }

  private formatPayload(payload: NotificationPayload): object {
    const { event } = payload;

    return {
      source: 'mund',
      version: '1.0',
      event: {
        id: event.id,
        timestamp: event.timestamp.toISOString(),
        rule_id: event.rule_id,
        rule_name: event.rule_name,
        severity: event.severity,
        type: event.type,
        action_taken: event.action_taken,
        content_snippet: event.content_snippet,
        content_hash: event.full_content_hash,
        context: event.context,
        acknowledged: event.acknowledged
      }
    };
  }

  private meetsMinSeverity(eventSeverity: Severity, minSeverity: Severity): boolean {
    const order: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
    const eventIndex = order.indexOf(eventSeverity);
    const minIndex = order.indexOf(minSeverity);
    return eventIndex <= minIndex;
  }
}

export default WebhookNotifier;
