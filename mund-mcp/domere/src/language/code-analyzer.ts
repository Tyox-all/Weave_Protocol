/**
 * Dōmere - The Judge Protocol
 * Code Analysis
 */

import type {
  CodeAnalysis,
  DangerousPattern,
  DataFlow,
  ExternalCall,
  LanguageType,
} from '../types.js';
import { DANGEROUS_CODE_PATTERNS } from '../constants.js';

// ============================================================================
// Code Analyzer
// ============================================================================

export class CodeAnalyzer {
  /**
   * Analyze code for security and structure
   */
  analyze(code: string, language: LanguageType): CodeAnalysis {
    const dangerousPatterns = this.detectDangerousPatterns(code, language);
    const dataFlows = this.analyzeDataFlows(code, language);
    const externalCalls = this.detectExternalCalls(code, language);
    
    const riskLevel = this.calculateRiskLevel(dangerousPatterns, dataFlows, externalCalls);
    
    return {
      language,
      functions: this.extractFunctions(code, language),
      classes: this.extractClasses(code, language),
      imports: this.extractImports(code, language),
      exports: this.extractExports(code, language),
      dangerous_patterns: dangerousPatterns,
      data_flows: dataFlows,
      external_calls: externalCalls,
      complexity_score: this.calculateComplexity(code),
      sandbox_required: riskLevel !== 'low',
      risk_level: riskLevel,
      recommendations: this.generateRecommendations(dangerousPatterns, externalCalls),
    };
  }
  
  /**
   * Detect dangerous code patterns
   */
  detectDangerousPatterns(code: string, language: LanguageType): DangerousPattern[] {
    const patterns: DangerousPattern[] = [];
    
    // Get language-specific patterns
    const langPatterns = DANGEROUS_CODE_PATTERNS[language as keyof typeof DANGEROUS_CODE_PATTERNS];
    
    if (langPatterns) {
      for (const { pattern, description, severity } of langPatterns) {
        const regex = new RegExp(pattern.source, pattern.flags);
        let match;
        
        while ((match = regex.exec(code)) !== null) {
          const line = this.getLineNumber(code, match.index);
          const column = this.getColumnNumber(code, match.index);
          
          patterns.push({
            pattern: match[0],
            description,
            severity,
            line,
            column,
            recommendation: this.getRecommendation(description, severity),
          });
        }
      }
    }
    
    // Common patterns across languages
    const commonPatterns = [
      { pattern: /password\s*=\s*['"][^'"]+['"]/gi, description: 'Hardcoded password', severity: 'critical' as const },
      { pattern: /api[_-]?key\s*=\s*['"][^'"]+['"]/gi, description: 'Hardcoded API key', severity: 'critical' as const },
      { pattern: /secret\s*=\s*['"][^'"]+['"]/gi, description: 'Hardcoded secret', severity: 'critical' as const },
      { pattern: /TODO|FIXME|HACK|XXX/g, description: 'Code annotation suggesting incomplete work', severity: 'low' as const },
    ];
    
    for (const { pattern, description, severity } of commonPatterns) {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        const line = this.getLineNumber(code, match.index);
        patterns.push({
          pattern: match[0].slice(0, 50),  // Truncate for security
          description,
          severity,
          line,
          recommendation: this.getRecommendation(description, severity),
        });
      }
    }
    
    return patterns;
  }
  
  /**
   * Analyze data flows in code
   */
  analyzeDataFlows(code: string, language: LanguageType): DataFlow[] {
    const flows: DataFlow[] = [];
    
    // Detect input -> output flows
    const inputPatterns: Record<string, RegExp[]> = {
      javascript: [
        /req\.(body|query|params|headers)/g,
        /process\.env/g,
        /fs\.readFile/g,
        /fetch\s*\(/g,
      ],
      python: [
        /request\.(form|args|json|data)/g,
        /os\.environ/g,
        /open\s*\(/g,
        /requests\.(get|post)/g,
        /input\s*\(/g,
      ],
      sql: [
        /SELECT\s+.*\s+FROM/gi,
      ],
    };
    
    const outputPatterns: Record<string, RegExp[]> = {
      javascript: [
        /res\.(send|json|write)/g,
        /console\.(log|error)/g,
        /fs\.writeFile/g,
        /fetch\s*\(/g,
      ],
      python: [
        /return\s+/g,
        /print\s*\(/g,
        /\.write\s*\(/g,
        /requests\.(get|post)/g,
      ],
      sql: [
        /INSERT\s+INTO/gi,
        /UPDATE\s+/gi,
      ],
    };
    
    const inputs = inputPatterns[language as keyof typeof inputPatterns] || [];
    const outputs = outputPatterns[language as keyof typeof outputPatterns] || [];
    
    const inputMatches: string[] = [];
    const outputMatches: string[] = [];
    
    for (const pattern of inputs) {
      const matches = code.match(pattern);
      if (matches) inputMatches.push(...matches);
    }
    
    for (const pattern of outputs) {
      const matches = code.match(pattern);
      if (matches) outputMatches.push(...matches);
    }
    
    // Create flow pairs
    for (const input of inputMatches) {
      for (const output of outputMatches) {
        flows.push({
          source: input,
          destination: output,
          sensitive: this.isSensitiveFlow(input, output),
        });
      }
    }
    
    // Detect sensitive data patterns
    const sensitivePatterns = [
      /password/i, /secret/i, /token/i, /key/i, /credential/i,
      /ssn/i, /social.*security/i, /credit.*card/i,
    ];
    
    for (const pattern of sensitivePatterns) {
      if (pattern.test(code)) {
        // Look for where this data goes
        const varPattern = new RegExp(`(\\w+)\\s*=.*${pattern.source}`, 'gi');
        const matches = code.match(varPattern);
        if (matches) {
          for (const match of matches) {
            flows.push({
              source: match,
              destination: 'unknown',
              data_type: pattern.source.replace(/[\\^$*+?.()|[\]{}]/g, ''),
              sensitive: true,
            });
          }
        }
      }
    }
    
    return flows;
  }
  
  /**
   * Detect external calls
   */
  detectExternalCalls(code: string, language: LanguageType): ExternalCall[] {
    const calls: ExternalCall[] = [];
    
    // HTTP calls
    const httpPatterns = [
      { pattern: /fetch\s*\(\s*['"`]([^'"`]+)['"`]/g, type: 'http' as const },
      { pattern: /axios\.(get|post|put|delete)\s*\(\s*['"`]([^'"`]+)['"`]/g, type: 'http' as const },
      { pattern: /requests\.(get|post|put|delete)\s*\(\s*['"`]([^'"`]+)['"`]/g, type: 'http' as const },
      { pattern: /http\.(get|post|put|delete)\s*\(\s*['"`]([^'"`]+)['"`]/g, type: 'http' as const },
      { pattern: /curl\s+['"`]?([^\s'"`]+)/g, type: 'http' as const },
      { pattern: /wget\s+['"`]?([^\s'"`]+)/g, type: 'http' as const },
    ];
    
    for (const { pattern, type } of httpPatterns) {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        const url = match[2] || match[1];
        calls.push({
          type,
          target: url,
          method: match[1]?.toUpperCase(),
          risk_level: this.assessUrlRisk(url),
        });
      }
    }
    
    // Database calls
    const dbPatterns = [
      { pattern: /\.query\s*\(\s*['"`]([^'"`]+)['"`]/g, type: 'database' as const },
      { pattern: /\.execute\s*\(\s*['"`]([^'"`]+)['"`]/g, type: 'database' as const },
      { pattern: /cursor\.execute\s*\(\s*['"`]([^'"`]+)['"`]/g, type: 'database' as const },
    ];
    
    for (const { pattern, type } of dbPatterns) {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        calls.push({
          type,
          target: match[1].slice(0, 100),  // Truncate long queries
          risk_level: this.assessQueryRisk(match[1]),
        });
      }
    }
    
    // File system calls
    const fsPatterns = [
      { pattern: /(?:fs\.|open\s*\()['"`]([^'"`]+)['"`]/g, type: 'file' as const },
      { pattern: /(?:readFile|writeFile|appendFile)\s*\(\s*['"`]([^'"`]+)['"`]/g, type: 'file' as const },
    ];
    
    for (const { pattern, type } of fsPatterns) {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        calls.push({
          type,
          target: match[1],
          risk_level: this.assessFileRisk(match[1]),
        });
      }
    }
    
    // Process/command execution
    const processPatterns = [
      { pattern: /(?:exec|spawn|system)\s*\(\s*['"`]([^'"`]+)['"`]/g, type: 'process' as const },
      { pattern: /subprocess\.(call|run|Popen)\s*\(\s*\[?['"`]([^'"`]+)['"`]/g, type: 'process' as const },
      { pattern: /os\.system\s*\(\s*['"`]([^'"`]+)['"`]/g, type: 'process' as const },
    ];
    
    for (const { pattern, type } of processPatterns) {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        calls.push({
          type,
          target: match[1] || match[2],
          risk_level: 'high',
        });
      }
    }
    
    return calls;
  }
  
  /**
   * Extract function definitions
   */
  extractFunctions(code: string, language: LanguageType): string[] {
    const functions: string[] = [];
    
    const patterns: Record<string, RegExp> = {
      javascript: /(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[^=])\s*=>|(\w+)\s*:\s*(?:async\s+)?function)/g,
      typescript: /(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[^=])\s*=>|(\w+)\s*:\s*(?:async\s+)?function)/g,
      python: /def\s+(\w+)\s*\(/g,
      java: /(?:public|private|protected)?\s*(?:static\s+)?(?:\w+\s+)+(\w+)\s*\([^)]*\)\s*(?:throws\s+\w+\s*)?{/g,
      go: /func\s+(?:\([^)]+\)\s+)?(\w+)\s*\(/g,
      rust: /fn\s+(\w+)\s*[<(]/g,
      ruby: /def\s+(\w+)/g,
      php: /function\s+(\w+)\s*\(/g,
    };
    
    const pattern = patterns[language as keyof typeof patterns];
    if (pattern) {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        const name = match[1] || match[2] || match[3];
        if (name && !functions.includes(name)) {
          functions.push(name);
        }
      }
    }
    
    return functions;
  }
  
  /**
   * Extract class definitions
   */
  extractClasses(code: string, language: LanguageType): string[] {
    const classes: string[] = [];
    
    const patterns: Record<string, RegExp> = {
      javascript: /class\s+(\w+)/g,
      typescript: /class\s+(\w+)/g,
      python: /class\s+(\w+)/g,
      java: /class\s+(\w+)/g,
      csharp: /class\s+(\w+)/g,
      ruby: /class\s+(\w+)/g,
      php: /class\s+(\w+)/g,
    };
    
    const pattern = patterns[language as keyof typeof patterns];
    if (pattern) {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        if (!classes.includes(match[1])) {
          classes.push(match[1]);
        }
      }
    }
    
    return classes;
  }
  
  /**
   * Extract imports
   */
  extractImports(code: string, language: LanguageType): string[] {
    const imports: string[] = [];
    
    const patterns: Record<string, RegExp> = {
      javascript: /(?:import\s+.*\s+from\s+['"]([^'"]+)['"]|require\s*\(\s*['"]([^'"]+)['"]\s*\))/g,
      typescript: /(?:import\s+.*\s+from\s+['"]([^'"]+)['"]|require\s*\(\s*['"]([^'"]+)['"]\s*\))/g,
      python: /(?:import\s+(\w+)|from\s+(\w+)\s+import)/g,
      java: /import\s+([\w.]+);/g,
      go: /import\s+(?:\(\s*)?["']([^"']+)["']/g,
      rust: /use\s+([\w:]+)/g,
    };
    
    const pattern = patterns[language as keyof typeof patterns];
    if (pattern) {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        const imp = match[1] || match[2];
        if (imp && !imports.includes(imp)) {
          imports.push(imp);
        }
      }
    }
    
    return imports;
  }
  
  /**
   * Extract exports
   */
  extractExports(code: string, language: LanguageType): string[] {
    const exports: string[] = [];
    
    const patterns: Record<string, RegExp> = {
      javascript: /export\s+(?:default\s+)?(?:class|function|const|let|var|interface|type)?\s*(\w+)/g,
      typescript: /export\s+(?:default\s+)?(?:class|function|const|let|var|interface|type)?\s*(\w+)/g,
    };
    
    const pattern = patterns[language as keyof typeof patterns];
    if (pattern) {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        if (match[1] && !exports.includes(match[1])) {
          exports.push(match[1]);
        }
      }
    }
    
    return exports;
  }
  
  /**
   * Calculate code complexity
   */
  calculateComplexity(code: string): number {
    let complexity = 1;  // Base complexity
    
    // Count decision points
    const decisionPatterns = [
      /\bif\b/g,
      /\belse\s+if\b/g,
      /\bwhile\b/g,
      /\bfor\b/g,
      /\bforeach\b/g,
      /\bswitch\b/g,
      /\bcase\b/g,
      /\bcatch\b/g,
      /\?\s*[^:]+\s*:/g,  // Ternary
      /&&/g,
      /\|\|/g,
    ];
    
    for (const pattern of decisionPatterns) {
      const matches = code.match(pattern);
      if (matches) {
        complexity += matches.length;
      }
    }
    
    // Normalize (0-100 scale)
    const lines = code.split('\n').length;
    const normalizedComplexity = Math.min(100, (complexity / Math.max(1, lines / 10)) * 10);
    
    return Math.round(normalizedComplexity);
  }
  
  /**
   * Calculate overall risk level
   */
  private calculateRiskLevel(
    patterns: DangerousPattern[],
    flows: DataFlow[],
    calls: ExternalCall[]
  ): 'low' | 'medium' | 'high' | 'critical' {
    const criticalPatterns = patterns.filter(p => p.severity === 'critical').length;
    const highPatterns = patterns.filter(p => p.severity === 'high').length;
    const sensitiveFlows = flows.filter(f => f.sensitive).length;
    const highRiskCalls = calls.filter(c => c.risk_level === 'high').length;
    
    if (criticalPatterns > 0) return 'critical';
    if (highPatterns > 2 || sensitiveFlows > 2 || highRiskCalls > 1) return 'high';
    if (highPatterns > 0 || sensitiveFlows > 0 || highRiskCalls > 0) return 'medium';
    
    return 'low';
  }
  
  /**
   * Generate recommendations
   */
  private generateRecommendations(patterns: DangerousPattern[], calls: ExternalCall[]): string[] {
    const recommendations: string[] = [];
    
    for (const pattern of patterns) {
      if (pattern.recommendation && !recommendations.includes(pattern.recommendation)) {
        recommendations.push(pattern.recommendation);
      }
    }
    
    if (calls.some(c => c.type === 'process')) {
      recommendations.push('Review process execution calls for potential command injection');
    }
    
    if (calls.some(c => c.type === 'database')) {
      recommendations.push('Ensure database queries use parameterized statements');
    }
    
    if (calls.some(c => c.type === 'file')) {
      recommendations.push('Validate file paths to prevent directory traversal');
    }
    
    return recommendations.slice(0, 5);
  }
  
  /**
   * Get line number from character position
   */
  private getLineNumber(code: string, position: number): number {
    return code.slice(0, position).split('\n').length;
  }
  
  /**
   * Get column number from character position
   */
  private getColumnNumber(code: string, position: number): number {
    const lines = code.slice(0, position).split('\n');
    return lines[lines.length - 1].length + 1;
  }
  
  /**
   * Get recommendation based on issue
   */
  private getRecommendation(description: string, severity: string): string {
    const recommendations: Record<string, string> = {
      'eval': 'Avoid eval() - use safer alternatives like JSON.parse() or specific parsers',
      'exec': 'Avoid direct command execution - use libraries with proper escaping',
      'sql injection': 'Use parameterized queries or an ORM',
      'password': 'Move credentials to environment variables or a secrets manager',
      'api key': 'Move API keys to environment variables or a secrets manager',
    };
    
    for (const [key, rec] of Object.entries(recommendations)) {
      if (description.toLowerCase().includes(key)) {
        return rec;
      }
    }
    
    return severity === 'critical' 
      ? 'Review this pattern carefully before deployment'
      : 'Consider reviewing this pattern';
  }
  
  /**
   * Check if a data flow is sensitive
   */
  private isSensitiveFlow(source: string, destination: string): boolean {
    const sensitiveTerms = ['password', 'secret', 'token', 'key', 'credential', 'auth'];
    const combined = (source + destination).toLowerCase();
    return sensitiveTerms.some(term => combined.includes(term));
  }
  
  /**
   * Assess URL risk
   */
  private assessUrlRisk(url: string): 'low' | 'medium' | 'high' {
    // External URLs are higher risk
    if (url.startsWith('http://')) return 'high';  // Insecure
    if (url.includes('localhost') || url.includes('127.0.0.1')) return 'low';
    if (url.startsWith('/')) return 'low';  // Relative
    return 'medium';
  }
  
  /**
   * Assess SQL query risk
   */
  private assessQueryRisk(query: string): 'low' | 'medium' | 'high' {
    const queryUpper = query.toUpperCase();
    if (queryUpper.includes('DROP') || queryUpper.includes('DELETE') || queryUpper.includes('TRUNCATE')) {
      return 'high';
    }
    if (queryUpper.includes('UPDATE') || queryUpper.includes('INSERT')) {
      return 'medium';
    }
    return 'low';
  }
  
  /**
   * Assess file path risk
   */
  private assessFileRisk(path: string): 'low' | 'medium' | 'high' {
    if (path.includes('..') || path.startsWith('/etc') || path.startsWith('/var')) {
      return 'high';
    }
    if (path.startsWith('/')) {
      return 'medium';
    }
    return 'low';
  }
}
