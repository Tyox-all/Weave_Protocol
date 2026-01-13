/**
 * Mund - The Guardian Protocol
 * Teams Notifier - Send alerts to Microsoft Teams channels
 */

import type { INotifier, NotificationPayload, TeamsConfig, Severity } from '../types.js';

interface TeamsAdaptiveCard {
  type: string;
  attachments: TeamsAttachment[];
}

interface TeamsAttachment {
  contentType: string;
  content: AdaptiveCardContent;
}

interface AdaptiveCardContent {
  $schema: string;
  type: string;
  version: string;
  body: AdaptiveCardElement[];
  actions?: AdaptiveCardAction[];
}

interface AdaptiveCardElement {
  type: string;
  text?: string;
  size?: string;
  weight?: string;
  color?: string;
  wrap?: boolean;
  spacing?: string;
  items?: AdaptiveCardElement[];
  columns?: AdaptiveCardColumn[];
  facts?: AdaptiveCardFact[];
}

interface AdaptiveCardColumn {
  type: string;
  width: string;
  items: AdaptiveCardElement[];
}

interface AdaptiveCardFact {
  title: string;
  value: string;
}

interface AdaptiveCardAction {
  type: string;
  title: string;
  url?: string;
}

export class TeamsNotifier implements INotifier {
  name = 'TeamsNotifier';
  private config: TeamsConfig;

  constructor(config: TeamsConfig) {
    this.config = config;
  }

  async send(payload: NotificationPayload): Promise<boolean> {
    const { event } = payload;

    // Check minimum severity
    if (this.config.min_severity && !this.meetsMinSeverity(event.severity, this.config.min_severity)) {
      return true; // Successfully skipped
    }

    const card = this.formatAdaptiveCard(payload);

    try {
      const response = await fetch(this.config.webhook_url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(card)
      });

      if (!response.ok) {
        console.error(`Teams notification failed: ${response.status} ${response.statusText}`);
        return false;
      }

      return true;
    } catch (error) {
      console.error('Failed to send Teams notification:', error);
      return false;
    }
  }

  private formatAdaptiveCard(payload: NotificationPayload): TeamsAdaptiveCard {
    const { event } = payload;
    const color = this.getSeverityColor(event.severity);
    const emoji = this.getSeverityEmoji(event.severity);

    const facts: AdaptiveCardFact[] = [
      { title: 'Severity', value: event.severity.toUpperCase() },
      { title: 'Type', value: event.type },
      { title: 'Action', value: event.action_taken },
      { title: 'Rule ID', value: event.rule_id },
      { title: 'Event ID', value: event.id },
      { title: 'Time', value: event.timestamp.toISOString() }
    ];

    if (event.context.tool_name) {
      facts.push({ title: 'Tool', value: event.context.tool_name });
    }
    if (event.context.agent_id) {
      facts.push({ title: 'Agent', value: event.context.agent_id });
    }

    return {
      type: 'message',
      attachments: [
        {
          contentType: 'application/vnd.microsoft.card.adaptive',
          content: {
            $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
            type: 'AdaptiveCard',
            version: '1.4',
            body: [
              {
                type: 'Container',
                items: [
                  {
                    type: 'TextBlock',
                    text: `${emoji} Mund Security Alert`,
                    size: 'Large',
                    weight: 'Bolder',
                    color: color
                  },
                  {
                    type: 'TextBlock',
                    text: event.rule_name,
                    size: 'Medium',
                    weight: 'Bolder',
                    wrap: true
                  }
                ]
              },
              {
                type: 'Container',
                items: [
                  {
                    type: 'TextBlock',
                    text: 'Detected Content:',
                    weight: 'Bolder',
                    spacing: 'Medium'
                  },
                  {
                    type: 'TextBlock',
                    text: `\`${event.content_snippet}\``,
                    wrap: true
                  }
                ]
              },
              {
                type: 'FactSet',
                facts
              }
            ]
          }
        }
      ]
    };
  }

  private getSeverityColor(severity: Severity): 'attention' | 'warning' | 'good' | 'default' {
    const colors: Record<Severity, 'attention' | 'warning' | 'good' | 'default'> = {
      critical: 'attention',
      high: 'attention',
      medium: 'warning',
      low: 'good',
      info: 'default'
    };
    return colors[severity] || 'default';
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

export default TeamsNotifier;
