/**
 * Mund - The Guardian Protocol
 * Email Notifier - Send alerts via email
 */

import type { INotifier, NotificationPayload, EmailConfig, Severity } from '../types.js';

// Note: In production, use nodemailer
// For now, we'll implement a basic interface that can be extended

export class EmailNotifier implements INotifier {
  name = 'EmailNotifier';
  private config: EmailConfig;

  constructor(config: EmailConfig) {
    this.config = config;
  }

  async send(payload: NotificationPayload): Promise<boolean> {
    const { event } = payload;

    // Check minimum severity
    if (this.config.min_severity && !this.meetsMinSeverity(event.severity, this.config.min_severity)) {
      return true; // Successfully skipped
    }

    const emailContent = this.formatEmail(payload);

    try {
      // In a real implementation, use nodemailer here
      // For now, we'll log the email content
      console.log('Email notification would be sent:');
      console.log('To:', this.config.to_addresses.join(', '));
      console.log('Subject:', emailContent.subject);
      console.log('Body:', emailContent.html.substring(0, 500) + '...');
      
      // Uncomment when nodemailer is configured:
      // const transporter = nodemailer.createTransport({
      //   host: this.config.smtp_host,
      //   port: this.config.smtp_port,
      //   secure: this.config.smtp_secure,
      //   auth: this.config.smtp_user ? {
      //     user: this.config.smtp_user,
      //     pass: this.config.smtp_pass
      //   } : undefined
      // });
      //
      // await transporter.sendMail({
      //   from: this.config.from_address,
      //   to: this.config.to_addresses.join(', '),
      //   subject: emailContent.subject,
      //   html: emailContent.html,
      //   text: emailContent.text
      // });

      return true;
    } catch (error) {
      console.error('Failed to send email notification:', error);
      return false;
    }
  }

  private formatEmail(payload: NotificationPayload): { subject: string; html: string; text: string } {
    const { event } = payload;
    const severityEmoji = this.getSeverityEmoji(event.severity);
    const severityColor = this.getSeverityColor(event.severity);

    const subject = `${severityEmoji} [Mund ${event.severity.toUpperCase()}] ${event.rule_name}`;

    const html = `
<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { background: ${severityColor}; color: white; padding: 20px; border-radius: 8px 8px 0 0; }
    .content { background: #f8f9fa; padding: 20px; border: 1px solid #dee2e6; border-top: none; border-radius: 0 0 8px 8px; }
    .snippet { background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 4px; font-family: monospace; overflow-x: auto; }
    .details { margin-top: 20px; }
    .detail-row { display: flex; border-bottom: 1px solid #dee2e6; padding: 8px 0; }
    .detail-label { font-weight: bold; width: 120px; flex-shrink: 0; }
    .detail-value { color: #495057; }
    .footer { margin-top: 20px; padding-top: 20px; border-top: 1px solid #dee2e6; font-size: 12px; color: #6c757d; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1 style="margin: 0;">${severityEmoji} Mund Security Alert</h1>
      <p style="margin: 10px 0 0 0; opacity: 0.9;">${event.rule_name}</p>
    </div>
    <div class="content">
      <h3>Detected Content</h3>
      <div class="snippet">${this.escapeHtml(event.content_snippet)}</div>
      
      <div class="details">
        <h3>Event Details</h3>
        <div class="detail-row">
          <span class="detail-label">Severity:</span>
          <span class="detail-value">${event.severity.toUpperCase()}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Type:</span>
          <span class="detail-value">${event.type}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Action:</span>
          <span class="detail-value">${event.action_taken}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Rule ID:</span>
          <span class="detail-value">${event.rule_id}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Event ID:</span>
          <span class="detail-value">${event.id}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Timestamp:</span>
          <span class="detail-value">${event.timestamp.toISOString()}</span>
        </div>
        ${event.context.tool_name ? `
        <div class="detail-row">
          <span class="detail-label">Tool:</span>
          <span class="detail-value">${event.context.tool_name}</span>
        </div>
        ` : ''}
        ${event.context.agent_id ? `
        <div class="detail-row">
          <span class="detail-label">Agent:</span>
          <span class="detail-value">${event.context.agent_id}</span>
        </div>
        ` : ''}
      </div>
      
      <div class="footer">
        This alert was generated by Mund - The Guardian Protocol.<br>
        Review and acknowledge this alert in your security dashboard.
      </div>
    </div>
  </div>
</body>
</html>`;

    const text = `
MUND SECURITY ALERT
====================

${event.severity.toUpperCase()}: ${event.rule_name}

Detected Content:
${event.content_snippet}

Event Details:
- Severity: ${event.severity.toUpperCase()}
- Type: ${event.type}
- Action: ${event.action_taken}
- Rule ID: ${event.rule_id}
- Event ID: ${event.id}
- Timestamp: ${event.timestamp.toISOString()}
${event.context.tool_name ? `- Tool: ${event.context.tool_name}` : ''}
${event.context.agent_id ? `- Agent: ${event.context.agent_id}` : ''}

---
This alert was generated by Mund - The Guardian Protocol.
`;

    return { subject, html, text };
  }

  private escapeHtml(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  private getSeverityColor(severity: Severity): string {
    const colors: Record<Severity, string> = {
      critical: '#dc3545',
      high: '#fd7e14',
      medium: '#ffc107',
      low: '#17a2b8',
      info: '#6c757d'
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

export default EmailNotifier;
