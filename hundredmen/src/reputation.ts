/**
 * Reputation Manager
 * @weave_protocol/hundredmen
 * 
 * Tracks and scores MCP server trustworthiness
 */

import { randomUUID } from 'crypto';
import {
  ServerReputation,
  ScoreHistoryEntry,
  ReputationReport,
  ReportType,
  ReportStatus,
  ReputationAlert,
} from './types.js';

// ============================================================================
// Known Server Registry
// ============================================================================

const KNOWN_TRUSTED_SERVERS: Record<string, Partial<ServerReputation>> = {
  'anthropic/filesystem': { verified: true, trustScore: 95 },
  'anthropic/github': { verified: true, trustScore: 95 },
  'anthropic/slack': { verified: true, trustScore: 90 },
  'anthropic/google-drive': { verified: true, trustScore: 90 },
  'modelcontextprotocol/server-filesystem': { verified: true, trustScore: 90 },
  'modelcontextprotocol/server-github': { verified: true, trustScore: 90 },
  'modelcontextprotocol/server-postgres': { verified: true, trustScore: 85 },
  'modelcontextprotocol/server-sqlite': { verified: true, trustScore: 85 },
};

const KNOWN_MALICIOUS_PATTERNS = [
  /hack/i,
  /exploit/i,
  /malware/i,
  /trojan/i,
  /backdoor/i,
  /keylog/i,
  /stealer/i,
];

// ============================================================================
// Reputation Manager
// ============================================================================

export class ReputationManager {
  private reputations: Map<string, ServerReputation> = new Map();
  private reports: Map<string, ReputationReport> = new Map();
  private alertCallbacks: ((alert: ReputationAlert) => void)[] = [];
  
  constructor() {
    // Initialize with known servers
    for (const [serverId, partial] of Object.entries(KNOWN_TRUSTED_SERVERS)) {
      this.reputations.set(serverId, this.createReputation(serverId, serverId, partial));
    }
  }
  
  // ==========================================================================
  // Core Methods
  // ==========================================================================
  
  getReputation(serverId: string): ServerReputation {
    let reputation = this.reputations.get(serverId);
    
    if (!reputation) {
      // Create new reputation for unknown server
      reputation = this.createReputation(serverId, serverId);
      this.reputations.set(serverId, reputation);
    }
    
    return reputation;
  }
  
  getScore(serverId: string): number {
    return this.getReputation(serverId).overallScore;
  }
  
  private createReputation(
    serverId: string,
    serverName: string,
    overrides: Partial<ServerReputation> = {}
  ): ServerReputation {
    const now = new Date();
    
    // Check for malicious patterns in name
    const isSuspicious = KNOWN_MALICIOUS_PATTERNS.some(p => p.test(serverName));
    
    // Calculate initial scores
    const baseScore = isSuspicious ? 10 : 50;
    
    return {
      serverId,
      serverName,
      overallScore: overrides.overallScore ?? baseScore,
      trustScore: overrides.trustScore ?? baseScore,
      securityScore: overrides.securityScore ?? baseScore,
      communityScore: overrides.communityScore ?? 50,
      totalCalls: 0,
      blockedCalls: 0,
      failedCalls: 0,
      avgResponseTime: 0,
      verified: overrides.verified ?? false,
      knownMalicious: isSuspicious,
      communityReports: 0,
      firstSeen: now,
      lastSeen: now,
      scoreHistory: [{
        timestamp: now,
        score: overrides.overallScore ?? baseScore,
        reason: 'Initial score',
      }],
      ...overrides,
    };
  }
  
  // ==========================================================================
  // Score Updates
  // ==========================================================================
  
  recordCall(serverId: string, success: boolean, responseTimeMs: number): void {
    const reputation = this.getReputation(serverId);
    
    reputation.totalCalls++;
    reputation.lastSeen = new Date();
    
    if (!success) {
      reputation.failedCalls++;
    }
    
    // Update average response time
    reputation.avgResponseTime = (
      (reputation.avgResponseTime * (reputation.totalCalls - 1) + responseTimeMs) /
      reputation.totalCalls
    );
    
    // Recalculate scores
    this.recalculateScores(serverId);
  }
  
  recordBlock(serverId: string, reason: string): void {
    const reputation = this.getReputation(serverId);
    
    reputation.blockedCalls++;
    reputation.lastSeen = new Date();
    
    // Decrease security score
    const penalty = reason.includes('critical') ? 15 : reason.includes('high') ? 10 : 5;
    reputation.securityScore = Math.max(0, reputation.securityScore - penalty);
    
    this.recalculateScores(serverId);
    this.checkForAlerts(serverId, 'score_drop');
  }
  
  private recalculateScores(serverId: string): void {
    const reputation = this.reputations.get(serverId);
    if (!reputation) return;
    
    // Calculate overall score from components
    const weights = {
      trust: 0.3,
      security: 0.4,
      community: 0.15,
      reliability: 0.15,
    };
    
    // Reliability score based on success rate
    const reliabilityScore = reputation.totalCalls > 0
      ? ((reputation.totalCalls - reputation.failedCalls - reputation.blockedCalls) / reputation.totalCalls) * 100
      : 50;
    
    const newScore = Math.round(
      reputation.trustScore * weights.trust +
      reputation.securityScore * weights.security +
      reputation.communityScore * weights.community +
      reliabilityScore * weights.reliability
    );
    
    const previousScore = reputation.overallScore;
    reputation.overallScore = Math.max(0, Math.min(100, newScore));
    
    // Record history if significant change
    if (Math.abs(reputation.overallScore - previousScore) >= 5) {
      reputation.scoreHistory.push({
        timestamp: new Date(),
        score: reputation.overallScore,
        reason: `Score changed from ${previousScore} to ${reputation.overallScore}`,
      });
      
      // Keep only last 100 entries
      if (reputation.scoreHistory.length > 100) {
        reputation.scoreHistory = reputation.scoreHistory.slice(-100);
      }
    }
  }
  
  // ==========================================================================
  // Community Reports
  // ==========================================================================
  
  submitReport(
    serverId: string,
    reportedBy: string,
    reportType: ReportType,
    description: string,
    evidence?: string
  ): ReputationReport {
    const report: ReputationReport = {
      id: randomUUID(),
      serverId,
      reportedBy,
      reportType,
      description,
      evidence,
      status: 'pending',
      createdAt: new Date(),
    };
    
    this.reports.set(report.id, report);
    
    // Update reputation
    const reputation = this.getReputation(serverId);
    reputation.communityReports++;
    
    // Decrease community score
    const penalty = reportType === 'malicious_behavior' ? 20 :
                    reportType === 'data_exfiltration' ? 25 :
                    reportType === 'prompt_injection' ? 15 :
                    reportType === 'unexpected_actions' ? 10 : 5;
    
    reputation.communityScore = Math.max(0, reputation.communityScore - penalty);
    this.recalculateScores(serverId);
    
    this.checkForAlerts(serverId, 'new_report');
    
    return report;
  }
  
  resolveReport(reportId: string, resolution: string, confirmed: boolean): ReputationReport | null {
    const report = this.reports.get(reportId);
    if (!report) return null;
    
    report.status = confirmed ? 'confirmed' : 'dismissed';
    report.resolvedAt = new Date();
    report.resolution = resolution;
    
    const reputation = this.getReputation(report.serverId);
    
    if (confirmed) {
      // Major penalty for confirmed malicious behavior
      if (report.reportType === 'malicious_behavior' || report.reportType === 'data_exfiltration') {
        reputation.knownMalicious = true;
        reputation.lastIncident = new Date();
        reputation.overallScore = Math.min(reputation.overallScore, 10);
        reputation.trustScore = 0;
        reputation.securityScore = 0;
        
        this.checkForAlerts(report.serverId, 'confirmed_malicious');
      } else {
        reputation.securityScore = Math.max(0, reputation.securityScore - 20);
        this.recalculateScores(report.serverId);
      }
    } else {
      // Restore some community score if dismissed
      reputation.communityScore = Math.min(100, reputation.communityScore + 5);
      this.recalculateScores(report.serverId);
    }
    
    return report;
  }
  
  getReports(serverId?: string): ReputationReport[] {
    let reports = Array.from(this.reports.values());
    if (serverId) {
      reports = reports.filter(r => r.serverId === serverId);
    }
    return reports.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }
  
  // ==========================================================================
  // Verification
  // ==========================================================================
  
  verifyServer(serverId: string, verifiedBy: string): void {
    const reputation = this.getReputation(serverId);
    
    if (!reputation.knownMalicious) {
      reputation.verified = true;
      reputation.trustScore = Math.max(reputation.trustScore, 80);
      this.recalculateScores(serverId);
      
      reputation.scoreHistory.push({
        timestamp: new Date(),
        score: reputation.overallScore,
        reason: `Verified by ${verifiedBy}`,
      });
    }
  }
  
  markMalicious(serverId: string, reason: string): void {
    const reputation = this.getReputation(serverId);
    
    reputation.knownMalicious = true;
    reputation.verified = false;
    reputation.lastIncident = new Date();
    reputation.overallScore = 0;
    reputation.trustScore = 0;
    reputation.securityScore = 0;
    reputation.communityScore = 0;
    
    reputation.scoreHistory.push({
      timestamp: new Date(),
      score: 0,
      reason: `Marked malicious: ${reason}`,
    });
    
    this.checkForAlerts(serverId, 'confirmed_malicious');
  }
  
  // ==========================================================================
  // Alerts
  // ==========================================================================
  
  onAlert(callback: (alert: ReputationAlert) => void): void {
    this.alertCallbacks.push(callback);
  }
  
  private checkForAlerts(serverId: string, alertType: ReputationAlert['alertType']): void {
    const reputation = this.reputations.get(serverId);
    if (!reputation) return;
    
    const alert: ReputationAlert = {
      serverId,
      serverName: reputation.serverName,
      alertType,
      currentScore: reputation.overallScore,
      message: this.getAlertMessage(alertType, reputation),
    };
    
    // Get previous score for comparison
    if (reputation.scoreHistory.length >= 2) {
      alert.previousScore = reputation.scoreHistory[reputation.scoreHistory.length - 2].score;
    }
    
    for (const callback of this.alertCallbacks) {
      try {
        callback(alert);
      } catch (err) {
        console.error('Alert callback error:', err);
      }
    }
  }
  
  private getAlertMessage(alertType: ReputationAlert['alertType'], reputation: ServerReputation): string {
    switch (alertType) {
      case 'score_drop':
        return `Server "${reputation.serverName}" reputation dropped to ${reputation.overallScore}`;
      case 'new_report':
        return `New community report filed against "${reputation.serverName}"`;
      case 'confirmed_malicious':
        return `⚠️ SERVER CONFIRMED MALICIOUS: "${reputation.serverName}" - Block all calls immediately`;
      case 'unusual_activity':
        return `Unusual activity detected from "${reputation.serverName}"`;
      default:
        return `Reputation alert for "${reputation.serverName}"`;
    }
  }
  
  // ==========================================================================
  // Query Methods
  // ==========================================================================
  
  getAllReputations(): ServerReputation[] {
    return Array.from(this.reputations.values())
      .sort((a, b) => b.overallScore - a.overallScore);
  }
  
  getLowReputationServers(threshold: number = 30): ServerReputation[] {
    return this.getAllReputations().filter(r => r.overallScore < threshold);
  }
  
  getMaliciousServers(): ServerReputation[] {
    return this.getAllReputations().filter(r => r.knownMalicious);
  }
  
  getVerifiedServers(): ServerReputation[] {
    return this.getAllReputations().filter(r => r.verified && !r.knownMalicious);
  }
  
  // ==========================================================================
  // Persistence (for external storage integration)
  // ==========================================================================
  
  export(): { reputations: ServerReputation[]; reports: ReputationReport[] } {
    return {
      reputations: Array.from(this.reputations.values()),
      reports: Array.from(this.reports.values()),
    };
  }
  
  import(data: { reputations: ServerReputation[]; reports: ReputationReport[] }): void {
    for (const rep of data.reputations) {
      this.reputations.set(rep.serverId, rep);
    }
    for (const report of data.reports) {
      this.reports.set(report.id, report);
    }
  }
}

export default ReputationManager;
