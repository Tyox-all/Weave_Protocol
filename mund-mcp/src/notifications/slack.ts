/**
 * Mund - The Guardian Protocol
 * Slack Notifier - Send alerts to Slack channels
 */

import type { INotifier, NotificationPayload, SlackConfig, Severity } from '../types.js';

interface SlackMessage {
  text: string;
  attachments?: SlackAttachment[];
  username?: string;
  icon_emoji?: string;
  channel?: string;
}

interface SlackAttachment {
  color: string;
  title: string;
  text: string;
  fields?: SlackField[];
  footer?: string;
  ts?: number;
}

interface SlackField {
  title: string;
  value: string;
  short: boolean;
}

export class SlackNotifier implements INotifier {
  name = 'SlackNotifier';
  private config: SlackConfig;

  constructor(config: SlackConfig) {
    this.config = config;
  }

  async send(payload: NotificationPayload): Promise<boolean> {
    const { event } = payload;

    // Check minimum severity
    if (this.config.min_severity && !this.meetsMinSeverity(event.severity, this.config.min_severity)) {
      return true; // Successfully skipped
    }

    const message = this.formatMessage(payload);

    try {
      const response = await fetch(this.config.webhook_url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(message)
      });

      if (!response.ok) {
        console.error(`Slack notification failed: ${response.status} ${response.statusText}`);
        return false;
      }

      return true;
    } catch (error) {
      console.error('Failed to send Slack notification:', error);
      return false;
    }
  }

  private formatMessage(payload: NotificationPayload): SlackMessage {
    const { event } = payload;
    
    const color = this.getSeverityColor(event.severity);
    const emoji = this.getSeverityEmoji(event.severity);

    const message: SlackMessage = {
      text: `${emoji} *Mund Security Alert* - ${event.rule_name}`,
      attachments: [
        {
          color,
          title: `${event.severity.toUpperCase()}: ${event.rule_name}`,
          text: `\`\`\`${event.content_snippet}\`\`\``,
          fields: [
            {
              title: 'Type',
              value: event.type,
              short: true
            },
            {
              title: 'Action',
              value: event.action_taken,
              short: true
            },
            {
              title: 'Rule ID',
              value: event.rule_id,
              short: true
            },
            {
              title: 'Event ID',
              value: event.id,
              short: true
            }
          ],
          footer: 'Mund Guardian Protocol',
          ts: Math.floor(event.timestamp.getTime() / 1000)
        }
      ]
    };

    // Add context fields if available
    if (event.context.tool_name) {
      message.attachments![0].fields!.push({
        title: 'Tool',
        value: event.context.tool_name,
        short: true
      });
    }

    if (event.context.agent_id) {
      message.attachments![0].fields!.push({
        title: 'Agent',
        value: event.context.agent_id,
        short: true
      });
    }

    // Apply custom settings
    if (this.config.username) {
      message.username = this.config.username;
    }
    if (this.config.icon_emoji) {
      message.icon_emoji = this.config.icon_emoji;
    }
    if (this.config.channel) {
      message.channel = this.config.channel;
    }

    return message;
  }

  private getSeverityColor(severity: Severity): string {
    const colors: Record<Severity, string> = {
      critical: '#dc3545', // Red
      high: '#fd7e14',     // Orange
      medium: '#ffc107',   // Yellow
      low: '#17a2b8',      // Cyan
      info: '#6c757d'      // Gray
    };
    return colors[severity] || colors.info;
  }

  private getSeverityEmoji(severity: Severity): string {
    const emojis: Record<Severity, string> = {
      critical: '🚨',
      high: '⚠️',
      medium: '⚡',
      low: 'ℹ️',
      info: '📝'
    };
    return emojis[severity] || '📝';
  }

  private meetsMinSeverity(eventSeverity: Severity, minSeverity: Severity): boolean {
    const order: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
    const eventIndex = order.indexOf(eventSeverity);
    const minIndex = order.indexOf(minSeverity);
    return eventIndex <= minIndex;
  }
}

export default SlackNotifier;
