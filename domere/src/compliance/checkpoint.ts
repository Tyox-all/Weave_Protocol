/**
 * Dōmere - Compliance Checkpoints (SOC2/HIPAA)
 * 
 * Automated compliance tracking and reporting for AI systems.
 * Supports SOC2, HIPAA, GDPR, and custom frameworks.
 */

import * as crypto from 'crypto';

// =============================================================================
// Types
// =============================================================================

export type ComplianceFramework = 'SOC2' | 'HIPAA' | 'GDPR' | 'PCI-DSS' | 'ISO27001' | 'CUSTOM';

export type SOC2Control = 
  | 'CC1.1' | 'CC1.2' | 'CC1.3' | 'CC1.4' | 'CC1.5'  // Control Environment
  | 'CC2.1' | 'CC2.2' | 'CC2.3'                       // Communication
  | 'CC3.1' | 'CC3.2' | 'CC3.3' | 'CC3.4'            // Risk Assessment
  | 'CC4.1' | 'CC4.2'                                  // Monitoring
  | 'CC5.1' | 'CC5.2' | 'CC5.3'                       // Control Activities
  | 'CC6.1' | 'CC6.2' | 'CC6.3' | 'CC6.4' | 'CC6.5' | 'CC6.6' | 'CC6.7' | 'CC6.8'  // Logical Access
  | 'CC7.1' | 'CC7.2' | 'CC7.3' | 'CC7.4' | 'CC7.5'  // System Operations
  | 'CC8.1'                                            // Change Management
  | 'CC9.1' | 'CC9.2';                                // Risk Mitigation

export type HIPAAControl =
  | 'ACCESS_CONTROL'
  | 'AUDIT_CONTROLS'
  | 'INTEGRITY'
  | 'PERSON_AUTH'
  | 'TRANSMISSION_SECURITY'
  | 'PRIVACY_RULE'
  | 'BREACH_NOTIFICATION'
  | 'MINIMUM_NECESSARY';

export type PCIDSSControl = "REQ1" | "REQ2" | "REQ3" | "REQ4" | "REQ5" | "REQ6" | "REQ7" | "REQ8" | "REQ9" | "REQ10" | "REQ11" | "REQ12";

export type ISO27001Control = "A5" | "A6" | "A7" | "A8" | "A9" | "A10" | "A11" | "A12" | "A13" | "A14" | "A15" | "A16" | "A17" | "A18";

export type PCIDSSControl =
  | "REQ1" | "REQ2" | "REQ3" | "REQ4" | "REQ5" | "REQ6"
  | "REQ7" | "REQ8" | "REQ9" | "REQ10" | "REQ11" | "REQ12";

export type ISO27001Control =
  | "A5" | "A6" | "A7" | "A8" | "A9" | "A10"
  | "A11" | "A12" | "A13" | "A14" | "A15" | "A16" | "A17" | "A18";

export interface ComplianceCheckpointRecord {
  id: string;
  thread_id: string;
  timestamp: Date;
  
  // Framework & control
  framework: ComplianceFramework;
  control: string;
  control_description: string;
  
  // Event details
  event_type: 'access' | 'modification' | 'disclosure' | 'deletion' | 'transmission' | 'authentication' | 'authorization' | 'audit';
  event_description: string;
  
  // Data classification
  data_classification: 'public' | 'internal' | 'confidential' | 'restricted' | 'phi' | 'pii';
  data_categories: string[];
  
  // Actors
  agent_id: string;
  user_id?: string;
  data_subject_id?: string;
  
  // Legal basis (GDPR/HIPAA)
  legal_basis?: 'consent' | 'contract' | 'legal_obligation' | 'vital_interests' | 'public_task' | 'legitimate_interests' | 'treatment' | 'payment' | 'operations';
  
  // Retention
  retention_days?: number;
  retention_policy?: string;
  
  // Risk
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  mitigations_applied: string[];
  
  // Verification
  checkpoint_hash: string;
  signed: boolean;
  signature?: string;
}

export interface ComplianceViolationRecord {
  id: string;
  checkpoint_id: string;
  thread_id: string;
  timestamp: Date;
  
  framework: ComplianceFramework;
  control: string;
  
  violation_type: 'unauthorized_access' | 'data_breach' | 'policy_violation' | 'retention_violation' | 'consent_violation' | 'audit_gap' | 'encryption_failure';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  
  affected_records: number;
  affected_subjects: string[];
  
  remediation_required: boolean;
  remediation_deadline?: Date;
  remediation_status: 'pending' | 'in_progress' | 'completed' | 'waived';
  remediation_notes?: string;
}

export interface ComplianceReportOutput {
  id: string;
  generated_at: Date;
  period_start: Date;
  period_end: Date;
  
  framework: ComplianceFramework;
  
  // Summary
  total_checkpoints: number;
  checkpoints_by_control: Record<string, number>;
  checkpoints_by_event_type: Record<string, number>;
  checkpoints_by_risk_level: Record<string, number>;
  
  // Violations
  total_violations: number;
  violations_by_severity: Record<string, number>;
  open_violations: number;
  remediated_violations: number;
  
  // Data subjects
  unique_data_subjects: number;
  data_access_count: number;
  
  // Compliance score
  compliance_score: number;  // 0-100
  control_coverage: Record<string, { covered: boolean; checkpoint_count: number }>;
  
  // Attestation
  attestation?: {
    attester: string;
    attested_at: Date;
    statement: string;
    signature: string;
  };
}

export interface RetentionPolicy {
  name: string;
  data_categories: string[];
  retention_days: number;
  deletion_method: 'soft' | 'hard' | 'anonymize';
  legal_hold_exempt: boolean;
}

// =============================================================================
// SOC2 Control Descriptions
// =============================================================================

export const SOC2_CONTROLS: Record<SOC2Control, string> = {
  'CC1.1': 'Integrity and Ethical Values',
  'CC1.2': 'Board Independence and Oversight',
  'CC1.3': 'Organizational Structure',
  'CC1.4': 'Commitment to Competence',
  'CC1.5': 'Accountability',
  'CC2.1': 'Information Quality',
  'CC2.2': 'Internal Communication',
  'CC2.3': 'External Communication',
  'CC3.1': 'Risk Assessment Objectives',
  'CC3.2': 'Risk Identification',
  'CC3.3': 'Fraud Risk',
  'CC3.4': 'Change Impact Analysis',
  'CC4.1': 'Monitoring Activities',
  'CC4.2': 'Deficiency Evaluation',
  'CC5.1': 'Control Selection',
  'CC5.2': 'Technology Controls',
  'CC5.3': 'Policy Deployment',
  'CC6.1': 'Logical Access Security',
  'CC6.2': 'Access Provisioning',
  'CC6.3': 'Access Removal',
  'CC6.4': 'Access Review',
  'CC6.5': 'Authentication',
  'CC6.6': 'Access Restrictions',
  'CC6.7': 'Data Transmission Protection',
  'CC6.8': 'Malicious Software Prevention',
  'CC7.1': 'Infrastructure Monitoring',
  'CC7.2': 'Security Event Detection',
  'CC7.3': 'Incident Response',
  'CC7.4': 'Business Continuity',
  'CC7.5': 'Data Recovery',
  'CC8.1': 'Change Management',
  'CC9.1': 'Risk Mitigation',
  'CC9.2': 'Vendor Management',
};

export const HIPAA_CONTROLS: Record<HIPAAControl, string> = {
  'ACCESS_CONTROL': 'Access Control (§164.312(a)(1))',
  'AUDIT_CONTROLS': 'Audit Controls (§164.312(b))',
  'INTEGRITY': 'Integrity Controls (§164.312(c)(1))',
  'PERSON_AUTH': 'Person Authentication (§164.312(d))',
  'TRANSMISSION_SECURITY': 'Transmission Security (§164.312(e)(1))',
  'PRIVACY_RULE': 'Privacy Rule Compliance',
  'BREACH_NOTIFICATION': 'Breach Notification (§164.400-414)',
  'MINIMUM_NECESSARY': 'Minimum Necessary Standard',
};

// =============================================================================
// Compliance Manager
// =============================================================================

export class ComplianceManager {
  private checkpoints: Map<string, ComplianceCheckpointRecord> = new Map();
  private violations: Map<string, ComplianceViolationRecord> = new Map();
  private retentionPolicies: Map<string, RetentionPolicy> = new Map();
  private signingKey: Buffer;
  
  constructor(signingKey: string) {
    this.signingKey = crypto.scryptSync(signingKey, 'domere-compliance', 32);
    this.initDefaultPolicies();
  }
  
  /**
   * Record a compliance checkpoint
   */
  async checkpoint(params: {
    thread_id: string;
    framework: ComplianceFramework;
    control: string;
    event_type: ComplianceCheckpointRecord['event_type'];
    event_description: string;
    data_classification: ComplianceCheckpointRecord['data_classification'];
    data_categories?: string[];
    agent_id: string;
    user_id?: string;
    data_subject_id?: string;
    legal_basis?: ComplianceCheckpointRecord['legal_basis'];
    retention_days?: number;
    risk_level?: ComplianceCheckpointRecord['risk_level'];
    mitigations_applied?: string[];
    sign?: boolean;
  }): Promise<ComplianceCheckpointRecord> {
    const id = `chk_${crypto.randomUUID()}`;
    
    // Get control description
    let controlDescription = params.control;
    if (params.framework === 'SOC2' && SOC2_CONTROLS[params.control as SOC2Control]) {
      controlDescription = SOC2_CONTROLS[params.control as SOC2Control];
    } else if (params.framework === 'HIPAA' && HIPAA_CONTROLS[params.control as HIPAAControl]) {
      controlDescription = HIPAA_CONTROLS[params.control as HIPAAControl];
    }
    
    // Auto-assess risk if not provided
    const riskLevel = params.risk_level || this.assessRisk(params);
    
    // Get retention from policy
    const retention = params.retention_days || this.getRetentionDays(params.data_categories || []);
    
    const checkpoint: ComplianceCheckpointRecord = {
      id,
      thread_id: params.thread_id,
      timestamp: new Date(),
      
      framework: params.framework,
      control: params.control,
      control_description: controlDescription,
      
      event_type: params.event_type,
      event_description: params.event_description,
      
      data_classification: params.data_classification,
      data_categories: params.data_categories || [],
      
      agent_id: params.agent_id,
      user_id: params.user_id,
      data_subject_id: params.data_subject_id,
      
      legal_basis: params.legal_basis,
      retention_days: retention,
      
      risk_level: riskLevel,
      mitigations_applied: params.mitigations_applied || [],
      
      checkpoint_hash: '',
      signed: params.sign || false,
    };
    
    // Compute hash
    checkpoint.checkpoint_hash = this.computeCheckpointHash(checkpoint);
    
    // Sign if requested
    if (params.sign) {
      checkpoint.signature = this.sign(checkpoint.checkpoint_hash);
    }
    
    // Store
    this.checkpoints.set(id, checkpoint);
    
    // Check for violations
    await this.checkViolations(checkpoint);
    
    return checkpoint;
  }
  
  /**
   * Record a compliance violation
   */
  async recordViolation(params: {
    checkpoint_id?: string;
    thread_id: string;
    framework: ComplianceFramework;
    control: string;
    violation_type: ComplianceViolationRecord['violation_type'];
    severity: ComplianceViolationRecord['severity'];
    description: string;
    affected_records?: number;
    affected_subjects?: string[];
    remediation_deadline?: Date;
  }): Promise<ComplianceViolationRecord> {
    const id = `vio_${crypto.randomUUID()}`;
    
    const violation: ComplianceViolationRecord = {
      id,
      checkpoint_id: params.checkpoint_id || '',
      thread_id: params.thread_id,
      timestamp: new Date(),
      
      framework: params.framework,
      control: params.control,
      
      violation_type: params.violation_type,
      severity: params.severity,
      description: params.description,
      
      affected_records: params.affected_records || 0,
      affected_subjects: params.affected_subjects || [],
      
      remediation_required: params.severity !== 'low',
      remediation_deadline: params.remediation_deadline,
      remediation_status: 'pending',
    };
    
    this.violations.set(id, violation);
    
    return violation;
  }
  
  /**
   * Update remediation status
   */
  async updateRemediation(violationId: string, status: ComplianceViolationRecord['remediation_status'], notes?: string): Promise<ComplianceViolationRecord | null> {
    const violation = this.violations.get(violationId);
    if (!violation) return null;
    
    violation.remediation_status = status;
    if (notes) violation.remediation_notes = notes;
    
    return violation;
  }
  
  /**
   * Generate compliance report
   */
  async generateReport(params: {
    framework: ComplianceFramework;
    period_start: Date;
    period_end: Date;
    attester?: string;
  }): Promise<ComplianceReportOutput> {
    const id = `rpt_${crypto.randomUUID()}`;
    
    // Filter checkpoints
    const relevantCheckpoints = Array.from(this.checkpoints.values()).filter(c =>
      c.framework === params.framework &&
      c.timestamp >= params.period_start &&
      c.timestamp <= params.period_end
    );
    
    // Filter violations
    const relevantViolations = Array.from(this.violations.values()).filter(v =>
      v.framework === params.framework &&
      v.timestamp >= params.period_start &&
      v.timestamp <= params.period_end
    );
    
    // Compute stats
    const checkpointsByControl: Record<string, number> = {};
    const checkpointsByEventType: Record<string, number> = {};
    const checkpointsByRiskLevel: Record<string, number> = {};
    const dataSubjects = new Set<string>();
    let dataAccessCount = 0;
    
    for (const c of relevantCheckpoints) {
      checkpointsByControl[c.control] = (checkpointsByControl[c.control] || 0) + 1;
      checkpointsByEventType[c.event_type] = (checkpointsByEventType[c.event_type] || 0) + 1;
      checkpointsByRiskLevel[c.risk_level] = (checkpointsByRiskLevel[c.risk_level] || 0) + 1;
      
      if (c.data_subject_id) dataSubjects.add(c.data_subject_id);
      if (c.event_type === 'access') dataAccessCount++;
    }
    
    const violationsBySeverity: Record<string, number> = {};
    let openViolations = 0;
    let remediatedViolations = 0;
    
    for (const v of relevantViolations) {
      violationsBySeverity[v.severity] = (violationsBySeverity[v.severity] || 0) + 1;
      if (v.remediation_status === 'pending' || v.remediation_status === 'in_progress') {
        openViolations++;
      } else if (v.remediation_status === 'completed') {
        remediatedViolations++;
      }
    }
    
    // Calculate control coverage
    const controlCoverage: Record<string, { covered: boolean; checkpoint_count: number }> = {};
    const controlList = params.framework === 'SOC2' ? Object.keys(SOC2_CONTROLS) : 
                        params.framework === 'HIPAA' ? Object.keys(HIPAA_CONTROLS) : [];
    
    for (const control of controlList) {
      const count = checkpointsByControl[control] || 0;
      controlCoverage[control] = { covered: count > 0, checkpoint_count: count };
    }
    
    // Calculate compliance score
    const coveredControls = Object.values(controlCoverage).filter(c => c.covered).length;
    const totalControls = controlList.length;
    const controlScore = totalControls > 0 ? (coveredControls / totalControls) * 50 : 50;
    
    const violationPenalty = Math.min(50, relevantViolations.length * 5);
    const complianceScore = Math.max(0, Math.round(controlScore + 50 - violationPenalty));
    
    const report: ComplianceReportOutput = {
      id,
      generated_at: new Date(),
      period_start: params.period_start,
      period_end: params.period_end,
      
      framework: params.framework,
      
      total_checkpoints: relevantCheckpoints.length,
      checkpoints_by_control: checkpointsByControl,
      checkpoints_by_event_type: checkpointsByEventType,
      checkpoints_by_risk_level: checkpointsByRiskLevel,
      
      total_violations: relevantViolations.length,
      violations_by_severity: violationsBySeverity,
      open_violations: openViolations,
      remediated_violations: remediatedViolations,
      
      unique_data_subjects: dataSubjects.size,
      data_access_count: dataAccessCount,
      
      compliance_score: complianceScore,
      control_coverage: controlCoverage,
    };
    
    // Add attestation if requested
    if (params.attester) {
      const statement = `I, ${params.attester}, attest that this compliance report accurately reflects the state of the ${params.framework} controls for the period ${params.period_start.toISOString()} to ${params.period_end.toISOString()}.`;
      report.attestation = {
        attester: params.attester,
        attested_at: new Date(),
        statement,
        signature: this.sign(statement),
      };
    }
    
    return report;
  }
  
  /**
   * Get checkpoints for a thread
   */
  async getCheckpoints(threadId: string): Promise<ComplianceCheckpointRecord[]> {
    return Array.from(this.checkpoints.values())
      .filter(c => c.thread_id === threadId)
      .sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  }
  
  /**
   * Get violations for a thread
   */
  async getViolations(threadId: string): Promise<ComplianceViolationRecord[]> {
    return Array.from(this.violations.values())
      .filter(v => v.thread_id === threadId)
      .sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  }
  
  /**
   * Add retention policy
   */
  addRetentionPolicy(policy: RetentionPolicy): void {
    this.retentionPolicies.set(policy.name, policy);
  }
  
  /**
   * HIPAA-specific: Log PHI access
   */
  async logPHIAccess(params: {
    thread_id: string;
    agent_id: string;
    patient_id: string;
    access_reason: string;
    data_accessed: string[];
    legal_basis: 'treatment' | 'payment' | 'operations';
  }): Promise<ComplianceCheckpointRecord> {
    return this.checkpoint({
      thread_id: params.thread_id,
      framework: 'HIPAA',
      control: 'ACCESS_CONTROL',
      event_type: 'access',
      event_description: `PHI accessed for ${params.access_reason}`,
      data_classification: 'phi',
      data_categories: params.data_accessed,
      agent_id: params.agent_id,
      data_subject_id: params.patient_id,
      legal_basis: params.legal_basis,
      sign: true,
    });
  }
  
  /**
   * SOC2-specific: Log access control event
   */
  async logAccessControl(params: {
    thread_id: string;
    agent_id: string;
    user_id?: string;
    resource: string;
    action: 'grant' | 'revoke' | 'modify' | 'review';
    success: boolean;
  }): Promise<ComplianceCheckpointRecord> {
    return this.checkpoint({
      thread_id: params.thread_id,
      framework: 'SOC2',
      control: params.action === 'grant' ? 'CC6.2' : 
               params.action === 'revoke' ? 'CC6.3' :
               params.action === 'review' ? 'CC6.4' : 'CC6.1',
      event_type: 'authorization',
      event_description: `Access ${params.action} for ${params.resource}: ${params.success ? 'success' : 'failed'}`,
      data_classification: 'internal',
      agent_id: params.agent_id,
      user_id: params.user_id,
      risk_level: params.success ? 'low' : 'medium',
      sign: true,
    });
  }
  /**
   * PCI-DSS: Log cardholder data access
   */
  async logCardholderDataAccess(params: {
    thread_id: string;
    agent_id: string;
    data_type: 'pan' | 'cvv' | 'pin' | 'track_data' | 'cardholder_name' | 'expiry';
    action: 'access' | 'store' | 'transmit' | 'delete';
    masked: boolean;
    encrypted: boolean;
    business_justification: string;
  }): Promise<ComplianceCheckpointRecord> {
    const control = params.action === 'store' ? 'REQ3' :
                    params.action === 'transmit' ? 'REQ4' :
                    params.action === 'access' ? 'REQ7' : 'REQ3';
    const mitigations: string[] = [];
    if (params.masked) mitigations.push('data_masking');
    if (params.encrypted) mitigations.push('encryption');
    return this.checkpoint({
      thread_id: params.thread_id,
      framework: 'PCI-DSS',
      control,
      event_type: params.action === 'transmit' ? 'transmission' : params.action === 'delete' ? 'deletion' : 'access',
      event_description: `Cardholder data (${params.data_type}) ${params.action}: ${params.business_justification}`,
      data_classification: 'restricted',
      data_categories: ['cardholder_data', params.data_type],
      agent_id: params.agent_id,
      risk_level: params.data_type === 'cvv' || params.data_type === 'pin' ? 'critical' : 'high',
      mitigations_applied: mitigations,
      sign: true,
    });
  }

  /**
   * ISO27001: Log security incident
   */
  async logSecurityIncident(params: {
    thread_id: string;
    agent_id: string;
    incident_id: string;
    incident_type: 'breach' | 'malware' | 'unauthorized_access' | 'data_loss' | 'ddos' | 'phishing' | 'other';
    severity: 'low' | 'medium' | 'high' | 'critical';
    status: 'detected' | 'investigating' | 'contained' | 'eradicated' | 'recovered' | 'closed';
    affected_assets: string[];
    description: string;
  }): Promise<ComplianceCheckpointRecord> {
    return this.checkpoint({
      thread_id: params.thread_id,
      framework: 'ISO27001',
      control: 'A16',
      event_type: params.incident_type === 'breach' ? 'disclosure' : 'audit',
      event_description: `Security incident ${params.incident_id} (${params.incident_type}): ${params.status} - ${params.description}`,
      data_classification: 'confidential',
      data_categories: ['security_incident', params.incident_type],
      agent_id: params.agent_id,
      risk_level: params.severity,
      sign: true,
    });
  }

  /**
   * ISO27001: Log asset management event
   */
  async logAssetEvent(params: {
    thread_id: string;
    agent_id: string;
    asset_id: string;
    asset_type: 'data' | 'software' | 'hardware' | 'service';
    action: 'create' | 'modify' | 'transfer' | 'dispose' | 'classify';
    classification: 'public' | 'internal' | 'confidential' | 'restricted';
  }): Promise<ComplianceCheckpointRecord> {
    return this.checkpoint({
      thread_id: params.thread_id,
      framework: 'ISO27001',
      control: 'A8',
      event_type: params.action === 'transfer' ? 'transmission' : 'modification',
      event_description: `Asset ${params.asset_id} (${params.asset_type}): ${params.action} - classified as ${params.classification}`,
      data_classification: params.classification,
      data_categories: ['asset_management', params.asset_type],
      agent_id: params.agent_id,
      risk_level: params.classification === 'restricted' ? 'high' : params.classification === 'confidential' ? 'medium' : 'low',
      sign: true,
    });
  }
  
  // ===========================================================================
  // Private Methods
  // ===========================================================================
  
  private initDefaultPolicies(): void {
    this.addRetentionPolicy({
      name: 'phi_retention',
      data_categories: ['phi', 'medical_records', 'patient_data'],
      retention_days: 2190, // 6 years for HIPAA
      deletion_method: 'hard',
      legal_hold_exempt: false,
    });
    
    this.addRetentionPolicy({
      name: 'pii_retention',
      data_categories: ['pii', 'personal_data'],
      retention_days: 365,
      deletion_method: 'anonymize',
      legal_hold_exempt: false,
    });
    
    this.addRetentionPolicy({
      name: 'audit_log_retention',
      data_categories: ['audit_logs', 'access_logs'],
      retention_days: 365, // SOC2 requirement
      deletion_method: 'soft',
      legal_hold_exempt: true,
    });
  }
    });
    
    this.addRetentionPolicy({
      name: 'cardholder_retention',
      data_categories: ['cardholder_data', 'pan', 'track_data'],
      retention_days: 365,
      deletion_method: 'hard',
      legal_hold_exempt: false,
    });
    
    this.addRetentionPolicy({
      name: 'incident_retention',
      data_categories: ['security_incident', 'breach'],
      retention_days: 1095,
      deletion_method: 'soft',
      legal_hold_exempt: true,
    });
  }
  private assessRisk(params: { data_classification: string; event_type: string }): 'low' | 'medium' | 'high' | 'critical' {
    if (params.data_classification === 'phi' || params.data_classification === 'restricted') {
      if (params.event_type === 'disclosure' || params.event_type === 'transmission') {
        return 'critical';
      }
      return 'high';
    }
    
    if (params.data_classification === 'pii' || params.data_classification === 'confidential') {
      return 'medium';
    }
    
    return 'low';
  }
  
  private getRetentionDays(categories: string[]): number {
    let maxRetention = 90; // Default
    
    for (const policy of this.retentionPolicies.values()) {
      if (categories.some(c => policy.data_categories.includes(c))) {
        maxRetention = Math.max(maxRetention, policy.retention_days);
      }
    }
    
    return maxRetention;
  }
  
  private async checkViolations(checkpoint: ComplianceCheckpointRecord): Promise<void> {
    // Check for missing legal basis on PHI
    if (checkpoint.data_classification === 'phi' && !checkpoint.legal_basis) {
      await this.recordViolation({
        checkpoint_id: checkpoint.id,
        thread_id: checkpoint.thread_id,
        framework: 'HIPAA',
        control: 'MINIMUM_NECESSARY',
        violation_type: 'policy_violation',
        severity: 'high',
        description: 'PHI accessed without documented legal basis',
        affected_records: 1,
        affected_subjects: checkpoint.data_subject_id ? [checkpoint.data_subject_id] : [],
      });
    }
    
    // Check for high-risk access without mitigations
    if (checkpoint.risk_level === 'critical' && checkpoint.mitigations_applied.length === 0) {
      await this.recordViolation({
        checkpoint_id: checkpoint.id,
        thread_id: checkpoint.thread_id,
        framework: checkpoint.framework,
        control: checkpoint.control,
        violation_type: 'policy_violation',
        severity: 'medium',
        description: 'Critical risk event without documented mitigations',
      });
    }
  }
  
  private computeCheckpointHash(checkpoint: ComplianceCheckpointRecord): string {
    const data = [
      checkpoint.id,
      checkpoint.thread_id,
      checkpoint.timestamp.toISOString(),
      checkpoint.framework,
      checkpoint.control,
      checkpoint.event_type,
      checkpoint.event_description,
      checkpoint.data_classification,
      checkpoint.agent_id,
    ].join('|');
    
    return crypto.createHash('sha256').update(data).digest('hex');
  }
  
  private sign(data: string): string {
    const hmac = crypto.createHmac('sha256', this.signingKey);
    hmac.update(data);
    return hmac.digest('hex');
  }
}

export default ComplianceManager;
