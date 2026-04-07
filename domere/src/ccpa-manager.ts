/**
 * CCPA/CPRA Compliance Manager
 * @weave_protocol/domere
 * 
 * Implements CCPA/CPRA compliance functionality including:
 * - Consumer request handling (45-day deadline)
 * - Opt-out management (sale/sharing)
 * - Personal information disclosure
 * - Financial incentive tracking
 * - Annual metrics reporting
 * - Checkpoint integration for audit trails
 */

import { createHash, randomUUID } from 'crypto';
import {
  Consumer,
  OptOutRecord,
  OptOutType,
  RequestSource,
  ConsumerRequest,
  ConsumerRequestType,
  ConsumerRequestStatus,
  ConsumerRequestResponse,
  ConsumerRequestAction,
  VerificationMethod,
  DenialReason,
  PersonalInfoCategory,
  SensitivePersonalInfo,
  Business,
  ServiceProvider,
  ServiceProviderPurpose,
  SaleDisclosure,
  ThirdPartyCategory,
  BusinessPurpose,
  FinancialIncentive,
  IncentiveType,
  IncentiveEnrollment,
  CCPAReport,
  CCPAReportType,
  CCPAReportSummary,
  AnnualMetrics,
  CCPACheckpoint,
  CCPACheckpointType,
} from './ccpa-types.js';

// ============================================================================
// Storage Interface
// ============================================================================

interface CCPAStorage {
  consumers: Map<string, Consumer>;
  optOuts: Map<string, OptOutRecord>;
  requests: Map<string, ConsumerRequest>;
  serviceProviders: Map<string, ServiceProvider>;
  saleDisclosures: Map<string, SaleDisclosure>;
  incentives: Map<string, FinancialIncentive>;
  enrollments: Map<string, IncentiveEnrollment>;
  checkpoints: Map<string, CCPACheckpoint>;
}

// ============================================================================
// CCPA Manager Class
// ============================================================================

export class CCPAManager {
  private storage: CCPAStorage;
  private business: Business;
  private requestDeadlineDays: number = 45; // CCPA requires response within 45 days
  private extensionDays: number = 45; // Can extend by additional 45 days

  constructor(business: Business) {
    this.business = business;
    this.storage = {
      consumers: new Map(),
      optOuts: new Map(),
      requests: new Map(),
      serviceProviders: new Map(),
      saleDisclosures: new Map(),
      incentives: new Map(),
      enrollments: new Map(),
      checkpoints: new Map(),
    };
  }

  // ==========================================================================
  // Consumer Management
  // ==========================================================================

  registerConsumer(data: Partial<Consumer>): Consumer {
    const consumer: Consumer = {
      id: data.id || randomUUID(),
      externalId: data.externalId,
      email: data.email,
      californiaResident: data.californiaResident ?? true,
      createdAt: new Date(),
      updatedAt: new Date(),
      metadata: data.metadata,
    };
    this.storage.consumers.set(consumer.id, consumer);
    return consumer;
  }

  getConsumer(consumerId: string): Consumer | undefined {
    return this.storage.consumers.get(consumerId);
  }

  findConsumerByEmail(email: string): Consumer | undefined {
    for (const consumer of this.storage.consumers.values()) {
      if (consumer.email === email) {
        return consumer;
      }
    }
    return undefined;
  }

  // ==========================================================================
  // Opt-Out Management (Do Not Sell / Do Not Share)
  // ==========================================================================

  recordOptOut(params: {
    consumerId: string;
    optOutType: OptOutType;
    source: RequestSource;
    globalPrivacyControl?: boolean;
    metadata?: Record<string, unknown>;
  }): OptOutRecord {
    const optOut: OptOutRecord = {
      id: randomUUID(),
      consumerId: params.consumerId,
      optOutType: params.optOutType,
      status: 'active',
      requestedAt: new Date(),
      effectiveAt: new Date(),
      source: params.source,
      globalPrivacyControl: params.globalPrivacyControl,
      metadata: params.metadata,
    };

    this.storage.optOuts.set(optOut.id, optOut);

    this.createCheckpoint({
      type: 'opt_out_recorded',
      actor: 'system',
      action: `Opt-out recorded: ${params.optOutType}`,
      consumerId: params.consumerId,
      details: { optOutId: optOut.id, type: params.optOutType, source: params.source },
    });

    return optOut;
  }

  withdrawOptOut(optOutId: string): OptOutRecord | undefined {
    const optOut = this.storage.optOuts.get(optOutId);
    if (!optOut) return undefined;

    optOut.status = 'withdrawn';
    optOut.withdrawnAt = new Date();

    this.createCheckpoint({
      type: 'opt_out_withdrawn',
      actor: 'system',
      action: `Opt-out withdrawn: ${optOut.optOutType}`,
      consumerId: optOut.consumerId,
      details: { optOutId },
    });

    return optOut;
  }

  getConsumerOptOuts(consumerId: string): OptOutRecord[] {
    const optOuts: OptOutRecord[] = [];
    for (const optOut of this.storage.optOuts.values()) {
      if (optOut.consumerId === consumerId) {
        optOuts.push(optOut);
      }
    }
    return optOuts;
  }

  hasActiveOptOut(consumerId: string, type: OptOutType): boolean {
    for (const optOut of this.storage.optOuts.values()) {
      if (optOut.consumerId === consumerId && 
          optOut.optOutType === type && 
          optOut.status === 'active') {
        return true;
      }
    }
    return false;
  }

  // Process Global Privacy Control signal
  processGPC(consumerId: string): OptOutRecord[] {
    const optOuts: OptOutRecord[] = [];
    
    // GPC signals opt-out of sale and sharing
    const saleOptOut = this.recordOptOut({
      consumerId,
      optOutType: 'sale',
      source: 'global_privacy_control',
      globalPrivacyControl: true,
    });
    optOuts.push(saleOptOut);

    const shareOptOut = this.recordOptOut({
      consumerId,
      optOutType: 'sharing',
      source: 'global_privacy_control',
      globalPrivacyControl: true,
    });
    optOuts.push(shareOptOut);

    return optOuts;
  }

  // ==========================================================================
  // Consumer Request Management
  // ==========================================================================

  submitRequest(params: {
    consumerId: string;
    type: ConsumerRequestType;
    source?: RequestSource;
    metadata?: Record<string, unknown>;
  }): ConsumerRequest {
    const now = new Date();
    const dueDate = new Date(now);
    dueDate.setDate(dueDate.getDate() + this.requestDeadlineDays);

    const request: ConsumerRequest = {
      id: randomUUID(),
      consumerId: params.consumerId,
      type: params.type,
      status: 'pending_verification',
      requestedAt: now,
      dueDate,
      metadata: params.metadata,
    };

    this.storage.requests.set(request.id, request);

    this.createCheckpoint({
      type: 'request_received',
      actor: 'system',
      action: `Consumer request received: ${params.type}`,
      consumerId: params.consumerId,
      details: { requestId: request.id, type: params.type },
    });

    return request;
  }

  verifyRequest(requestId: string, method: VerificationMethod): ConsumerRequest | undefined {
    const request = this.storage.requests.get(requestId);
    if (!request) return undefined;

    request.status = 'verified';
    request.verificationMethod = method;
    request.verifiedAt = new Date();

    this.createCheckpoint({
      type: 'request_verified',
      actor: 'system',
      action: `Request verified via ${method}`,
      consumerId: request.consumerId,
      details: { requestId, method },
    });

    return request;
  }

  extendRequest(requestId: string, reason: string): ConsumerRequest | undefined {
    const request = this.storage.requests.get(requestId);
    if (!request) return undefined;
    if (request.extendedDueDate) return undefined; // Can only extend once

    const extendedDueDate = new Date(request.dueDate);
    extendedDueDate.setDate(extendedDueDate.getDate() + this.extensionDays);

    request.status = 'extended';
    request.extendedDueDate = extendedDueDate;
    request.extensionReason = reason;

    return request;
  }

  completeRequest(requestId: string, response: Omit<ConsumerRequestResponse, 'id' | 'requestId' | 'respondedAt'>): ConsumerRequest | undefined {
    const request = this.storage.requests.get(requestId);
    if (!request) return undefined;

    const fullResponse: ConsumerRequestResponse = {
      id: randomUUID(),
      requestId,
      respondedAt: new Date(),
      ...response,
    };

    request.status = 'completed';
    request.completedAt = new Date();
    request.response = fullResponse;

    this.createCheckpoint({
      type: 'request_completed',
      actor: 'system',
      action: `Request completed: ${request.type}`,
      consumerId: request.consumerId,
      details: { requestId, actions: response.actions },
    });

    return request;
  }

  denyRequest(requestId: string, reason: DenialReason): ConsumerRequest | undefined {
    const request = this.storage.requests.get(requestId);
    if (!request) return undefined;

    request.status = 'denied';
    request.completedAt = new Date();
    request.response = {
      id: randomUUID(),
      requestId,
      respondedAt: new Date(),
      actions: [],
      denialReason: reason,
      format: 'json',
    };

    this.createCheckpoint({
      type: 'request_denied',
      actor: 'system',
      action: `Request denied: ${reason}`,
      consumerId: request.consumerId,
      details: { requestId, reason },
    });

    return request;
  }

  getRequest(requestId: string): ConsumerRequest | undefined {
    return this.storage.requests.get(requestId);
  }

  getConsumerRequests(consumerId: string): ConsumerRequest[] {
    const requests: ConsumerRequest[] = [];
    for (const request of this.storage.requests.values()) {
      if (request.consumerId === consumerId) {
        requests.push(request);
      }
    }
    return requests;
  }

  getPendingRequests(): ConsumerRequest[] {
    const pending: ConsumerRequest[] = [];
    for (const request of this.storage.requests.values()) {
      if (!['completed', 'denied'].includes(request.status)) {
        pending.push(request);
      }
    }
    return pending;
  }

  getOverdueRequests(): ConsumerRequest[] {
    const now = new Date();
    const overdue: ConsumerRequest[] = [];
    for (const request of this.storage.requests.values()) {
      if (!['completed', 'denied'].includes(request.status)) {
        const deadline = request.extendedDueDate || request.dueDate;
        if (deadline < now) {
          overdue.push(request);
        }
      }
    }
    return overdue;
  }

  // ==========================================================================
  // Service Provider Management
  // ==========================================================================

  registerServiceProvider(data: Omit<ServiceProvider, 'id'>): ServiceProvider {
    const provider: ServiceProvider = {
      id: randomUUID(),
      ...data,
    };
    this.storage.serviceProviders.set(provider.id, provider);
    return provider;
  }

  getServiceProviders(): ServiceProvider[] {
    return Array.from(this.storage.serviceProviders.values());
  }

  // ==========================================================================
  // Sale/Sharing Disclosure
  // ==========================================================================

  recordSaleDisclosure(data: Omit<SaleDisclosure, 'id' | 'createdAt'>): SaleDisclosure {
    const disclosure: SaleDisclosure = {
      id: randomUUID(),
      ...data,
      createdAt: new Date(),
    };
    this.storage.saleDisclosures.set(disclosure.id, disclosure);

    this.createCheckpoint({
      type: 'sale_recorded',
      actor: 'system',
      action: 'Sale/sharing disclosure recorded',
      details: { disclosureId: disclosure.id, period: data.period },
    });

    return disclosure;
  }

  getSaleDisclosures(period?: { start: Date; end: Date }): SaleDisclosure[] {
    const disclosures = Array.from(this.storage.saleDisclosures.values());
    if (!period) return disclosures;

    return disclosures.filter(d => 
      d.period.start >= period.start && d.period.end <= period.end
    );
  }

  // ==========================================================================
  // Financial Incentive Management
  // ==========================================================================

  createIncentive(data: Omit<FinancialIncentive, 'id' | 'createdAt' | 'updatedAt'>): FinancialIncentive {
    const incentive: FinancialIncentive = {
      id: randomUUID(),
      ...data,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.storage.incentives.set(incentive.id, incentive);
    return incentive;
  }

  enrollInIncentive(consumerId: string, incentiveId: string): IncentiveEnrollment | undefined {
    const incentive = this.storage.incentives.get(incentiveId);
    if (!incentive || !incentive.optInRequired) return undefined;

    const enrollment: IncentiveEnrollment = {
      id: randomUUID(),
      consumerId,
      incentiveId,
      enrolledAt: new Date(),
      status: 'active',
    };

    this.storage.enrollments.set(enrollment.id, enrollment);

    this.createCheckpoint({
      type: 'incentive_enrolled',
      actor: 'system',
      action: `Consumer enrolled in incentive: ${incentive.name}`,
      consumerId,
      details: { enrollmentId: enrollment.id, incentiveId },
    });

    return enrollment;
  }

  withdrawFromIncentive(enrollmentId: string): IncentiveEnrollment | undefined {
    const enrollment = this.storage.enrollments.get(enrollmentId);
    if (!enrollment) return undefined;

    enrollment.status = 'withdrawn';
    enrollment.withdrawnAt = new Date();

    this.createCheckpoint({
      type: 'incentive_withdrawn',
      actor: 'system',
      action: 'Consumer withdrew from incentive',
      consumerId: enrollment.consumerId,
      details: { enrollmentId },
    });

    return enrollment;
  }

  // ==========================================================================
  // Annual Metrics (Required Disclosure)
  // ==========================================================================

  generateAnnualMetrics(year: number): AnnualMetrics {
    const startDate = new Date(year, 0, 1);
    const endDate = new Date(year, 11, 31, 23, 59, 59);

    const requests = Array.from(this.storage.requests.values()).filter(r =>
      r.requestedAt >= startDate && r.requestedAt <= endDate
    );

    const calculateMetrics = (types: ConsumerRequestType[]) => {
      const filtered = requests.filter(r => types.includes(r.type));
      const completed = filtered.filter(r => r.status === 'completed');
      const denied = filtered.filter(r => r.status === 'denied');
      
      const responseTimes = completed
        .filter(r => r.completedAt)
        .map(r => (r.completedAt!.getTime() - r.requestedAt.getTime()) / (1000 * 60 * 60 * 24));
      
      const avgDays = responseTimes.length > 0 
        ? responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length 
        : 0;

      return {
        received: filtered.length,
        complied: completed.length,
        denied: denied.length,
        avgDaysToRespond: Math.round(avgDays * 10) / 10,
      };
    };

    return {
      year,
      requestsToKnow: calculateMetrics(['know_categories', 'know_specific']),
      requestsToDelete: calculateMetrics(['delete']),
      requestsToOptOut: calculateMetrics(['opt_out_sale', 'opt_out_sharing']),
      requestsToCorrect: calculateMetrics(['correct']),
    };
  }

  // ==========================================================================
  // Compliance Reporting
  // ==========================================================================

  generateReport(type: CCPAReportType, period: { start: Date; end: Date }): CCPAReport {
    const summary = this.calculateSummary(period);

    return {
      id: randomUUID(),
      type,
      generatedAt: new Date(),
      period,
      summary,
      details: this.getReportDetails(type, period),
      format: 'json',
    };
  }

  private calculateSummary(period: { start: Date; end: Date }): CCPAReportSummary {
    const requests = Array.from(this.storage.requests.values()).filter(r =>
      r.requestedAt >= period.start && r.requestedAt <= period.end
    );

    const completed = requests.filter(r => r.status === 'completed');
    const denied = requests.filter(r => r.status === 'denied');

    const responseTimes = completed
      .filter(r => r.completedAt)
      .map(r => (r.completedAt!.getTime() - r.requestedAt.getTime()) / (1000 * 60 * 60 * 24));

    const sortedTimes = [...responseTimes].sort((a, b) => a - b);
    const medianTime = sortedTimes.length > 0 
      ? sortedTimes[Math.floor(sortedTimes.length / 2)] 
      : 0;

    const avgTime = responseTimes.length > 0
      ? responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length
      : 0;

    const activeOptOuts = Array.from(this.storage.optOuts.values())
      .filter(o => o.status === 'active').length;

    const overdue = this.getOverdueRequests().length;
    const complianceScore = requests.length > 0
      ? Math.round(((completed.length / requests.length) * 100 - overdue * 5))
      : 100;

    return {
      totalConsumers: this.storage.consumers.size,
      requestsReceived: requests.length,
      requestsCompleted: completed.length,
      requestsDenied: denied.length,
      avgResponseTime: Math.round(avgTime * 10) / 10,
      medianResponseTime: Math.round(medianTime * 10) / 10,
      optOutsActive: activeOptOuts,
      salesDisclosed: this.storage.saleDisclosures.size,
      complianceScore: Math.max(0, Math.min(100, complianceScore)),
    };
  }

  private getReportDetails(type: CCPAReportType, period: { start: Date; end: Date }): Record<string, unknown> {
    switch (type) {
      case 'consumer_requests':
        return {
          requests: Array.from(this.storage.requests.values()).filter(r =>
            r.requestedAt >= period.start && r.requestedAt <= period.end
          ),
        };
      case 'opt_out_summary':
        return {
          optOuts: Array.from(this.storage.optOuts.values()),
        };
      case 'sale_disclosure':
        return {
          disclosures: this.getSaleDisclosures(period),
        };
      case 'service_providers':
        return {
          providers: this.getServiceProviders(),
        };
      case 'financial_incentives':
        return {
          incentives: Array.from(this.storage.incentives.values()),
          enrollments: Array.from(this.storage.enrollments.values()),
        };
      default:
        return {};
    }
  }

  // ==========================================================================
  // Checkpoint Management
  // ==========================================================================

  private createCheckpoint(params: {
    type: CCPACheckpointType;
    actor: string;
    action: string;
    consumerId?: string;
    details: Record<string, unknown>;
  }): CCPACheckpoint {
    const checkpoints = Array.from(this.storage.checkpoints.values());
    const lastCheckpoint = checkpoints[checkpoints.length - 1];

    const checkpoint: CCPACheckpoint = {
      id: randomUUID(),
      type: params.type,
      timestamp: new Date(),
      actor: params.actor,
      action: params.action,
      consumerId: params.consumerId,
      details: params.details,
      hash: '',
      previousHash: lastCheckpoint?.hash,
    };

    checkpoint.hash = this.computeCheckpointHash(checkpoint);
    this.storage.checkpoints.set(checkpoint.id, checkpoint);

    return checkpoint;
  }

  private computeCheckpointHash(checkpoint: Omit<CCPACheckpoint, 'hash'>): string {
    const data = JSON.stringify({
      id: checkpoint.id,
      type: checkpoint.type,
      timestamp: checkpoint.timestamp.toISOString(),
      actor: checkpoint.actor,
      action: checkpoint.action,
      consumerId: checkpoint.consumerId,
      details: checkpoint.details,
      previousHash: checkpoint.previousHash,
    });
    return createHash('sha256').update(data).digest('hex');
  }

  getCheckpoints(consumerId?: string): CCPACheckpoint[] {
    const checkpoints = Array.from(this.storage.checkpoints.values());
    if (!consumerId) return checkpoints;
    return checkpoints.filter(c => c.consumerId === consumerId);
  }

  verifyCheckpointChain(): { valid: boolean; brokenAt?: string } {
    const checkpoints = Array.from(this.storage.checkpoints.values())
      .sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

    for (let i = 1; i < checkpoints.length; i++) {
      if (checkpoints[i].previousHash !== checkpoints[i - 1].hash) {
        return { valid: false, brokenAt: checkpoints[i].id };
      }
    }

    return { valid: true };
  }

  // ==========================================================================
  // Export for Singleton Pattern
  // ==========================================================================

  getBusiness(): Business {
    return this.business;
  }
}

// Default export for convenience
export const createCCPAManager = (business: Business): CCPAManager => {
  return new CCPAManager(business);
};
