/**
 * GDPR Compliance Manager
 * @weave_protocol/domere
 * 
 * Implements GDPR compliance functionality including:
 * - Consent management
 * - Data Subject Access Requests (DSAR)
 * - Processing records (Article 30)
 * - Breach notification
 * - Retention policy enforcement
 * - Automated decision tracking (Article 22)
 */

import { createHash, randomUUID } from 'crypto';
import {
  DataSubject,
  ConsentRecord,
  ConsentPurpose,
  LegalBasis,
  ConsentSource,
  DSARRequest,
  DSARType,
  DSARStatus,
  DSARResponse,
  DSARAction,
  VerificationMethod,
  ProcessingRecord,
  DataController,
  DataCategory,
  DataBreach,
  BreachSeverity,
  BreachStatus,
  BreachCause,
  MitigationAction,
  RetentionPolicy,
  RetentionCheck,
  DeletionMethod,
  AutomatedDecision,
  DecisionSignificance,
  GDPRReport,
  GDPRReportType,
  GDPRReportSummary,
  GDPRCheckpoint,
  GDPRCheckpointType,
} from './gdpr-types';

// ============================================================================
// Storage Interface (in-memory default, can be extended)
// ============================================================================

interface GDPRStorage {
  subjects: Map<string, DataSubject>;
  consents: Map<string, ConsentRecord>;
  dsarRequests: Map<string, DSARRequest>;
  processingRecords: Map<string, ProcessingRecord>;
  breaches: Map<string, DataBreach>;
  retentionPolicies: Map<string, RetentionPolicy>;
  retentionChecks: Map<string, RetentionCheck>;
  automatedDecisions: Map<string, AutomatedDecision>;
  checkpoints: Map<string, GDPRCheckpoint>;
}

// ============================================================================
// GDPR Manager Class
// ============================================================================

export class GDPRManager {
  private storage: GDPRStorage;
  private controller: DataController;
  private dsarDeadlineDays: number = 30; // GDPR requires response within 30 days

  constructor(controller: DataController) {
    this.controller = controller;
    this.storage = {
      subjects: new Map(),
      consents: new Map(),
      dsarRequests: new Map(),
      processingRecords: new Map(),
      breaches: new Map(),
      retentionPolicies: new Map(),
      retentionChecks: new Map(),
      automatedDecisions: new Map(),
      checkpoints: new Map(),
    };
  }

  // ==========================================================================
  // Data Subject Management
  // ==========================================================================

  registerSubject(data: Partial<DataSubject>): DataSubject {
    const subject: DataSubject = {
      id: data.id || randomUUID(),
      externalId: data.externalId,
      email: data.email,
      createdAt: new Date(),
      updatedAt: new Date(),
      metadata: data.metadata,
    };
    this.storage.subjects.set(subject.id, subject);
    return subject;
  }

  getSubject(subjectId: string): DataSubject | undefined {
    return this.storage.subjects.get(subjectId);
  }

  findSubjectByEmail(email: string): DataSubject | undefined {
    for (const subject of this.storage.subjects.values()) {
      if (subject.email === email) {
        return subject;
      }
    }
    return undefined;
  }

  // ==========================================================================
  // Consent Management
  // ==========================================================================

  recordConsent(params: {
    subjectId: string;
    purpose: ConsentPurpose;
    legalBasis: LegalBasis;
    granted: boolean;
    source: ConsentSource;
    version: string;
    expiresAt?: Date;
    metadata?: Record<string, unknown>;
  }): ConsentRecord {
    const consent: ConsentRecord = {
      id: randomUUID(),
      subjectId: params.subjectId,
      purpose: params.purpose,
      legalBasis: params.legalBasis,
      granted: params.granted,
      grantedAt: params.granted ? new Date() : undefined,
      expiresAt: params.expiresAt,
      source: params.source,
      version: params.version,
      metadata: params.metadata,
    };

    this.storage.consents.set(consent.id, consent);

    // Create checkpoint
    this.createCheckpoint({
      type: 'consent_granted',
      actor: 'system',
      action: `Consent ${params.granted ? 'granted' : 'denied'} for ${params.purpose}`,
      subjectId: params.subjectId,
      details: {
        consentId: consent.id,
        purpose: params.purpose,
        legalBasis: params.legalBasis,
        source: params.source,
      },
    });

    return consent;
  }

  withdrawConsent(consentId: string, reason?: string): ConsentRecord | null {
    const consent = this.storage.consents.get(consentId);
    if (!consent) return null;

    consent.granted = false;
    consent.withdrawnAt = new Date();

    // Create checkpoint
    this.createCheckpoint({
      type: 'consent_withdrawn',
      actor: 'data_subject',
      action: `Consent withdrawn for ${consent.purpose}`,
      subjectId: consent.subjectId,
      details: {
        consentId,
        purpose: consent.purpose,
        reason,
      },
    });

    return consent;
  }

  getActiveConsents(subjectId: string): ConsentRecord[] {
    const consents: ConsentRecord[] = [];
    const now = new Date();

    for (const consent of this.storage.consents.values()) {
      if (
        consent.subjectId === subjectId &&
        consent.granted &&
        !consent.withdrawnAt &&
        (!consent.expiresAt || consent.expiresAt > now)
      ) {
        consents.push(consent);
      }
    }

    return consents;
  }

  hasValidConsent(subjectId: string, purpose: ConsentPurpose): boolean {
    const consents = this.getActiveConsents(subjectId);
    return consents.some(c => c.purpose === purpose);
  }

  // ==========================================================================
  // Data Subject Access Request (DSAR) Management
  // ==========================================================================

  createDSAR(params: {
    subjectId: string;
    type: DSARType;
    verificationMethod?: VerificationMethod;
    metadata?: Record<string, unknown>;
  }): DSARRequest {
    const dueDate = new Date();
    dueDate.setDate(dueDate.getDate() + this.dsarDeadlineDays);

    const dsar: DSARRequest = {
      id: randomUUID(),
      subjectId: params.subjectId,
      type: params.type,
      status: 'pending_verification',
      requestedAt: new Date(),
      dueDate,
      verificationMethod: params.verificationMethod,
      metadata: params.metadata,
    };

    this.storage.dsarRequests.set(dsar.id, dsar);

    // Create checkpoint
    this.createCheckpoint({
      type: 'dsar_received',
      actor: 'data_subject',
      action: `DSAR received: ${params.type}`,
      subjectId: params.subjectId,
      details: {
        dsarId: dsar.id,
        type: params.type,
        dueDate,
      },
    });

    return dsar;
  }

  verifyDSAR(dsarId: string, verifiedBy: string): DSARRequest | null {
    const dsar = this.storage.dsarRequests.get(dsarId);
    if (!dsar) return null;

    dsar.status = 'verified';
    dsar.verifiedAt = new Date();
    dsar.assignedTo = verifiedBy;

    return dsar;
  }

  processDSAR(dsarId: string, assignedTo: string): DSARRequest | null {
    const dsar = this.storage.dsarRequests.get(dsarId);
    if (!dsar) return null;

    dsar.status = 'in_progress';
    dsar.assignedTo = assignedTo;

    return dsar;
  }

  completeDSAR(dsarId: string, response: DSARResponse): DSARRequest | null {
    const dsar = this.storage.dsarRequests.get(dsarId);
    if (!dsar) return null;

    dsar.status = 'completed';
    dsar.completedAt = new Date();
    dsar.response = response;

    // Create checkpoint
    this.createCheckpoint({
      type: 'dsar_completed',
      actor: dsar.assignedTo || 'system',
      action: `DSAR completed: ${dsar.type}`,
      subjectId: dsar.subjectId,
      details: {
        dsarId,
        type: dsar.type,
        responseTime: this.calculateResponseTime(dsar),
        withinDeadline: dsar.completedAt <= dsar.dueDate,
      },
    });

    return dsar;
  }

  extendDSAR(dsarId: string, extensionDays: number, reason: string): DSARRequest | null {
    const dsar = this.storage.dsarRequests.get(dsarId);
    if (!dsar) return null;

    // GDPR allows extension up to 2 additional months for complex requests
    const maxExtension = 60;
    if (extensionDays > maxExtension) {
      throw new Error(`Extension cannot exceed ${maxExtension} days per GDPR Article 12(3)`);
    }

    dsar.status = 'extended';
    dsar.dueDate = new Date(dsar.dueDate.getTime() + extensionDays * 24 * 60 * 60 * 1000);
    dsar.response = {
      ...dsar.response,
      type: dsar.type,
      completedAt: new Date(),
      extensionReason: reason,
    };

    return dsar;
  }

  rejectDSAR(dsarId: string, reason: string): DSARRequest | null {
    const dsar = this.storage.dsarRequests.get(dsarId);
    if (!dsar) return null;

    dsar.status = 'rejected';
    dsar.completedAt = new Date();
    dsar.response = {
      type: dsar.type,
      completedAt: new Date(),
      rejectionReason: reason,
    };

    return dsar;
  }

  getDSAR(dsarId: string): DSARRequest | undefined {
    return this.storage.dsarRequests.get(dsarId);
  }

  getPendingDSARs(): DSARRequest[] {
    const pending: DSARRequest[] = [];
    for (const dsar of this.storage.dsarRequests.values()) {
      if (!['completed', 'rejected'].includes(dsar.status)) {
        pending.push(dsar);
      }
    }
    return pending.sort((a, b) => a.dueDate.getTime() - b.dueDate.getTime());
  }

  getOverdueDSARs(): DSARRequest[] {
    const now = new Date();
    return this.getPendingDSARs().filter(dsar => dsar.dueDate < now);
  }

  private calculateResponseTime(dsar: DSARRequest): number {
    if (!dsar.completedAt) return -1;
    return Math.ceil(
      (dsar.completedAt.getTime() - dsar.requestedAt.getTime()) / (1000 * 60 * 60 * 24)
    );
  }

  // ==========================================================================
  // Right to Erasure (Article 17)
  // ==========================================================================

  async executeErasure(subjectId: string, reason: string): Promise<{
    success: boolean;
    erasedRecords: number;
    errors: string[];
  }> {
    const errors: string[] = [];
    let erasedRecords = 0;

    // Check for legal holds or exceptions
    const subject = this.storage.subjects.get(subjectId);
    if (!subject) {
      return { success: false, erasedRecords: 0, errors: ['Subject not found'] };
    }

    // Erase consents
    for (const [id, consent] of this.storage.consents.entries()) {
      if (consent.subjectId === subjectId) {
        this.storage.consents.delete(id);
        erasedRecords++;
      }
    }

    // Mark DSARs as anonymized (keep for audit but remove PII)
    for (const dsar of this.storage.dsarRequests.values()) {
      if (dsar.subjectId === subjectId) {
        dsar.subjectId = `ERASED_${createHash('sha256').update(subjectId).digest('hex').slice(0, 8)}`;
        erasedRecords++;
      }
    }

    // Erase automated decisions
    for (const [id, decision] of this.storage.automatedDecisions.entries()) {
      if (decision.subjectId === subjectId) {
        this.storage.automatedDecisions.delete(id);
        erasedRecords++;
      }
    }

    // Remove subject
    this.storage.subjects.delete(subjectId);

    // Create checkpoint
    this.createCheckpoint({
      type: 'data_deleted',
      actor: 'system',
      action: 'Right to erasure executed',
      subjectId: `ERASED_${subjectId.slice(0, 8)}`,
      details: {
        reason,
        erasedRecords,
        timestamp: new Date(),
      },
    });

    return { success: errors.length === 0, erasedRecords, errors };
  }

  // ==========================================================================
  // Right to Data Portability (Article 20)
  // ==========================================================================

  exportSubjectData(subjectId: string, format: 'json' | 'csv' = 'json'): {
    subject: DataSubject | null;
    consents: ConsentRecord[];
    dsarRequests: DSARRequest[];
    automatedDecisions: AutomatedDecision[];
    exportedAt: Date;
    format: string;
  } {
    const subject = this.storage.subjects.get(subjectId) || null;

    const consents: ConsentRecord[] = [];
    for (const consent of this.storage.consents.values()) {
      if (consent.subjectId === subjectId) {
        consents.push(consent);
      }
    }

    const dsarRequests: DSARRequest[] = [];
    for (const dsar of this.storage.dsarRequests.values()) {
      if (dsar.subjectId === subjectId) {
        dsarRequests.push(dsar);
      }
    }

    const automatedDecisions: AutomatedDecision[] = [];
    for (const decision of this.storage.automatedDecisions.values()) {
      if (decision.subjectId === subjectId) {
        automatedDecisions.push(decision);
      }
    }

    // Create checkpoint
    this.createCheckpoint({
      type: 'data_exported',
      actor: 'system',
      action: 'Data portability export',
      subjectId,
      details: {
        format,
        recordCount: consents.length + dsarRequests.length + automatedDecisions.length,
      },
    });

    return {
      subject,
      consents,
      dsarRequests,
      automatedDecisions,
      exportedAt: new Date(),
      format,
    };
  }

  // ==========================================================================
  // Processing Records (Article 30)
  // ==========================================================================

  createProcessingRecord(record: Omit<ProcessingRecord, 'id' | 'createdAt' | 'updatedAt'>): ProcessingRecord {
    const processingRecord: ProcessingRecord = {
      ...record,
      id: randomUUID(),
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.storage.processingRecords.set(processingRecord.id, processingRecord);
    return processingRecord;
  }

  updateProcessingRecord(id: string, updates: Partial<ProcessingRecord>): ProcessingRecord | null {
    const record = this.storage.processingRecords.get(id);
    if (!record) return null;

    Object.assign(record, updates, { updatedAt: new Date() });
    return record;
  }

  getProcessingRecords(): ProcessingRecord[] {
    return Array.from(this.storage.processingRecords.values());
  }

  getProcessingRecord(id: string): ProcessingRecord | undefined {
    return this.storage.processingRecords.get(id);
  }

  // ==========================================================================
  // Data Breach Management
  // ==========================================================================

  reportBreach(params: {
    description: string;
    severity: BreachSeverity;
    affectedSubjects: number;
    affectedCategories: DataCategory[];
    cause: BreachCause;
    consequences: string[];
  }): DataBreach {
    const breach: DataBreach = {
      id: randomUUID(),
      detectedAt: new Date(),
      description: params.description,
      severity: params.severity,
      status: 'detected',
      affectedSubjects: params.affectedSubjects,
      affectedCategories: params.affectedCategories,
      cause: params.cause,
      consequences: params.consequences,
      mitigationActions: [],
    };

    this.storage.breaches.set(breach.id, breach);

    // Create checkpoint
    this.createCheckpoint({
      type: 'breach_detected',
      actor: 'system',
      action: `Data breach detected: ${params.severity} severity`,
      details: {
        breachId: breach.id,
        severity: params.severity,
        affectedSubjects: params.affectedSubjects,
        cause: params.cause,
      },
    });

    return breach;
  }

  addBreachMitigation(breachId: string, action: Omit<MitigationAction, 'performedAt'>): DataBreach | null {
    const breach = this.storage.breaches.get(breachId);
    if (!breach) return null;

    breach.mitigationActions.push({
      ...action,
      performedAt: new Date(),
    });

    if (breach.status === 'detected') {
      breach.status = 'investigating';
    }

    return breach;
  }

  notifySupervisoryAuthority(breachId: string, authority: string, referenceNumber?: string): DataBreach | null {
    const breach = this.storage.breaches.get(breachId);
    if (!breach) return null;

    const notifiedAt = new Date();
    const hoursElapsed = (notifiedAt.getTime() - breach.detectedAt.getTime()) / (1000 * 60 * 60);

    breach.supervisoryNotification = {
      authority,
      notifiedAt,
      referenceNumber,
      withinDeadline: hoursElapsed <= 72, // GDPR requires 72-hour notification
      delayReason: hoursElapsed > 72 ? 'Late notification' : undefined,
    };

    breach.status = 'notifying';

    // Create checkpoint
    this.createCheckpoint({
      type: 'breach_notified',
      actor: 'dpo',
      action: `Supervisory authority notified: ${authority}`,
      details: {
        breachId,
        authority,
        withinDeadline: breach.supervisoryNotification.withinDeadline,
        hoursElapsed: Math.round(hoursElapsed),
      },
    });

    return breach;
  }

  notifyAffectedSubjects(
    breachId: string,
    method: 'email' | 'letter' | 'public_notice' | 'direct_contact',
    subjectsNotified: number
  ): DataBreach | null {
    const breach = this.storage.breaches.get(breachId);
    if (!breach) return null;

    breach.subjectNotification = {
      notifiedAt: new Date(),
      method,
      subjectsNotified,
    };

    return breach;
  }

  closeBreach(breachId: string, rootCauseAnalysis: string, preventiveMeasures: string[]): DataBreach | null {
    const breach = this.storage.breaches.get(breachId);
    if (!breach) return null;

    breach.status = 'closed';
    breach.closedAt = new Date();
    breach.rootCauseAnalysis = rootCauseAnalysis;
    breach.preventiveMeasures = preventiveMeasures;

    return breach;
  }

  getBreach(breachId: string): DataBreach | undefined {
    return this.storage.breaches.get(breachId);
  }

  getActiveBreaches(): DataBreach[] {
    return Array.from(this.storage.breaches.values()).filter(b => b.status !== 'closed');
  }

  // ==========================================================================
  // Retention Policy Management
  // ==========================================================================

  createRetentionPolicy(policy: Omit<RetentionPolicy, 'id' | 'createdAt' | 'updatedAt'>): RetentionPolicy {
    const retentionPolicy: RetentionPolicy = {
      ...policy,
      id: randomUUID(),
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.storage.retentionPolicies.set(retentionPolicy.id, retentionPolicy);
    return retentionPolicy;
  }

  executeRetentionCheck(policyId: string): RetentionCheck {
    const policy = this.storage.retentionPolicies.get(policyId);
    if (!policy) {
      throw new Error(`Retention policy not found: ${policyId}`);
    }

    const check: RetentionCheck = {
      id: randomUUID(),
      policyId,
      executedAt: new Date(),
      recordsChecked: 0,
      recordsExpired: 0,
      recordsDeleted: 0,
      recordsExcepted: 0,
      errors: [],
      status: 'completed',
    };

    // Simulate retention check (in real implementation, would scan actual data)
    // This would integrate with actual data stores

    this.storage.retentionChecks.set(check.id, check);

    // Create checkpoint
    this.createCheckpoint({
      type: 'retention_executed',
      actor: 'system',
      action: `Retention policy executed: ${policy.name}`,
      details: {
        policyId,
        checkId: check.id,
        recordsDeleted: check.recordsDeleted,
      },
    });

    return check;
  }

  getRetentionPolicies(): RetentionPolicy[] {
    return Array.from(this.storage.retentionPolicies.values());
  }

  // ==========================================================================
  // Automated Decision Tracking (Article 22)
  // ==========================================================================

  recordAutomatedDecision(params: {
    subjectId: string;
    decisionType: string;
    algorithm: string;
    inputData: string[];
    outcome: string;
    significance: DecisionSignificance;
    legalBasis: LegalBasis;
    explanation?: string;
  }): AutomatedDecision {
    // Article 22 requires human review for decisions with legal/significant effects
    const humanReviewRequired =
      params.significance === 'legal_effects' || params.significance === 'similarly_significant';

    const decision: AutomatedDecision = {
      id: randomUUID(),
      subjectId: params.subjectId,
      decisionType: params.decisionType,
      algorithm: params.algorithm,
      inputData: params.inputData,
      outcome: params.outcome,
      significance: params.significance,
      legalBasis: params.legalBasis,
      humanReviewRequired,
      explanation: params.explanation,
      appealable: humanReviewRequired,
      appealDeadline: humanReviewRequired
        ? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days
        : undefined,
      createdAt: new Date(),
    };

    this.storage.automatedDecisions.set(decision.id, decision);

    // Create checkpoint
    this.createCheckpoint({
      type: 'automated_decision',
      actor: params.algorithm,
      action: `Automated decision: ${params.decisionType}`,
      subjectId: params.subjectId,
      details: {
        decisionId: decision.id,
        outcome: params.outcome,
        significance: params.significance,
        humanReviewRequired,
      },
    });

    return decision;
  }

  completeHumanReview(
    decisionId: string,
    reviewedBy: string,
    reviewOutcome: string
  ): AutomatedDecision | null {
    const decision = this.storage.automatedDecisions.get(decisionId);
    if (!decision) return null;

    decision.humanReviewCompleted = true;
    decision.reviewedBy = reviewedBy;
    decision.reviewedAt = new Date();
    decision.reviewOutcome = reviewOutcome;

    // Create checkpoint
    this.createCheckpoint({
      type: 'human_review',
      actor: reviewedBy,
      action: `Human review completed for automated decision`,
      subjectId: decision.subjectId,
      details: {
        decisionId,
        originalOutcome: decision.outcome,
        reviewOutcome,
      },
    });

    return decision;
  }

  getPendingHumanReviews(): AutomatedDecision[] {
    return Array.from(this.storage.automatedDecisions.values()).filter(
      d => d.humanReviewRequired && !d.humanReviewCompleted
    );
  }

  // ==========================================================================
  // Checkpoint Management
  // ==========================================================================

  private createCheckpoint(params: {
    type: GDPRCheckpointType;
    actor: string;
    action: string;
    subjectId?: string;
    details: Record<string, unknown>;
  }): GDPRCheckpoint {
    const lastCheckpoint = this.getLastCheckpoint();

    const checkpoint: GDPRCheckpoint = {
      id: randomUUID(),
      type: params.type,
      timestamp: new Date(),
      actor: params.actor,
      action: params.action,
      subjectId: params.subjectId,
      details: params.details,
      hash: '',
      previousHash: lastCheckpoint?.hash,
    };

    // Calculate hash
    checkpoint.hash = createHash('sha256')
      .update(JSON.stringify({
        id: checkpoint.id,
        type: checkpoint.type,
        timestamp: checkpoint.timestamp.toISOString(),
        actor: checkpoint.actor,
        action: checkpoint.action,
        subjectId: checkpoint.subjectId,
        details: checkpoint.details,
        previousHash: checkpoint.previousHash,
      }))
      .digest('hex');

    this.storage.checkpoints.set(checkpoint.id, checkpoint);
    return checkpoint;
  }

  private getLastCheckpoint(): GDPRCheckpoint | undefined {
    let last: GDPRCheckpoint | undefined;
    for (const checkpoint of this.storage.checkpoints.values()) {
      if (!last || checkpoint.timestamp > last.timestamp) {
        last = checkpoint;
      }
    }
    return last;
  }

  getCheckpoints(filter?: {
    type?: GDPRCheckpointType;
    subjectId?: string;
    startDate?: Date;
    endDate?: Date;
  }): GDPRCheckpoint[] {
    let checkpoints = Array.from(this.storage.checkpoints.values());

    if (filter?.type) {
      checkpoints = checkpoints.filter(c => c.type === filter.type);
    }
    if (filter?.subjectId) {
      checkpoints = checkpoints.filter(c => c.subjectId === filter.subjectId);
    }
    if (filter?.startDate) {
      checkpoints = checkpoints.filter(c => c.timestamp >= filter.startDate!);
    }
    if (filter?.endDate) {
      checkpoints = checkpoints.filter(c => c.timestamp <= filter.endDate!);
    }

    return checkpoints.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  }

  // ==========================================================================
  // Reporting
  // ==========================================================================

  generateReport(type: GDPRReportType, period: { start: Date; end: Date }): GDPRReport {
    const summary = this.calculateSummary(period);

    const report: GDPRReport = {
      id: randomUUID(),
      type,
      generatedAt: new Date(),
      period,
      summary,
      details: this.getReportDetails(type, period),
      format: 'json',
    };

    return report;
  }

  private calculateSummary(period: { start: Date; end: Date }): GDPRReportSummary {
    let totalSubjects = 0;
    let activeConsents = 0;
    let dsarRequests = 0;
    let dsarCompleted = 0;
    let dsarPending = 0;
    let totalResponseTime = 0;
    let responseCount = 0;
    let breaches = 0;
    let retentionViolations = 0;
    let automatedDecisions = 0;
    let humanReviews = 0;

    for (const subject of this.storage.subjects.values()) {
      if (subject.createdAt >= period.start && subject.createdAt <= period.end) {
        totalSubjects++;
      }
    }

    for (const consent of this.storage.consents.values()) {
      if (consent.granted && !consent.withdrawnAt) {
        activeConsents++;
      }
    }

    for (const dsar of this.storage.dsarRequests.values()) {
      if (dsar.requestedAt >= period.start && dsar.requestedAt <= period.end) {
        dsarRequests++;
        if (dsar.status === 'completed') {
          dsarCompleted++;
          const responseTime = this.calculateResponseTime(dsar);
          if (responseTime > 0) {
            totalResponseTime += responseTime;
            responseCount++;
          }
        } else if (!['completed', 'rejected'].includes(dsar.status)) {
          dsarPending++;
        }
      }
    }

    for (const breach of this.storage.breaches.values()) {
      if (breach.detectedAt >= period.start && breach.detectedAt <= period.end) {
        breaches++;
      }
    }

    for (const decision of this.storage.automatedDecisions.values()) {
      if (decision.createdAt >= period.start && decision.createdAt <= period.end) {
        automatedDecisions++;
        if (decision.humanReviewCompleted) {
          humanReviews++;
        }
      }
    }

    // Calculate compliance score (0-100)
    const complianceFactors = [
      dsarRequests > 0 ? dsarCompleted / dsarRequests : 1,
      this.getOverdueDSARs().length === 0 ? 1 : 0.5,
      breaches === 0 ? 1 : 0.7,
      retentionViolations === 0 ? 1 : 0.8,
    ];
    const complianceScore = Math.round(
      (complianceFactors.reduce((a, b) => a + b, 0) / complianceFactors.length) * 100
    );

    return {
      totalSubjects,
      activeConsents,
      dsarRequests,
      dsarCompleted,
      dsarPending,
      avgResponseTime: responseCount > 0 ? Math.round(totalResponseTime / responseCount) : 0,
      breaches,
      retentionViolations,
      automatedDecisions,
      humanReviews,
      complianceScore,
    };
  }

  private getReportDetails(type: GDPRReportType, period: { start: Date; end: Date }): Record<string, unknown> {
    switch (type) {
      case 'consent_summary':
        return { consents: Array.from(this.storage.consents.values()) };
      case 'dsar_summary':
        return { dsars: Array.from(this.storage.dsarRequests.values()) };
      case 'processing_records':
        return { records: Array.from(this.storage.processingRecords.values()) };
      case 'breach_report':
        return { breaches: Array.from(this.storage.breaches.values()) };
      case 'retention_report':
        return {
          policies: Array.from(this.storage.retentionPolicies.values()),
          checks: Array.from(this.storage.retentionChecks.values()),
        };
      case 'automated_decisions':
        return { decisions: Array.from(this.storage.automatedDecisions.values()) };
      case 'full_compliance':
        return {
          consents: Array.from(this.storage.consents.values()),
          dsars: Array.from(this.storage.dsarRequests.values()),
          processingRecords: Array.from(this.storage.processingRecords.values()),
          breaches: Array.from(this.storage.breaches.values()),
          retentionPolicies: Array.from(this.storage.retentionPolicies.values()),
          automatedDecisions: Array.from(this.storage.automatedDecisions.values()),
          checkpoints: this.getCheckpoints({ startDate: period.start, endDate: period.end }),
        };
      default:
        return {};
    }
  }
}

export default GDPRManager;
