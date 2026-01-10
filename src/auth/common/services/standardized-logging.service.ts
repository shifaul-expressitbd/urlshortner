import { Injectable, Logger } from '@nestjs/common';

/**
 * Standardized logging service for the auth module
 * Enforces consistent logging levels and formats across the auth system
 */
@Injectable()
export class StandardizedLoggingService {
  private readonly logger = new Logger('AuthService');

  /**
   * Log successful authentication events
   */
  logAuthSuccess(operation: string, userId?: string, details?: Record<string, any>): void {
    this.logger.log({
      level: 'info',
      event: 'AUTH_SUCCESS',
      operation,
      userId,
      details,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Log authentication failures
   */
  logAuthFailure(operation: string, reason: string, userId?: string, details?: Record<string, any>): void {
    this.logger.warn({
      level: 'warn',
      event: 'AUTH_FAILURE',
      operation,
      reason,
      userId,
      details,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Log security-related events
   */
  logSecurityEvent(event: string, severity: 'low' | 'medium' | 'high' | 'critical', details: Record<string, any>): void {
    const logLevel = this.getLogLevelForSecurityEvent(severity);
    
    this.logger[logLevel]({
      level: logLevel,
      event: 'SECURITY_EVENT',
      securityEvent: event,
      severity,
      details,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Log system errors
   */
  logError(operation: string, error: Error, context?: Record<string, any>): void {
    this.logger.error({
      level: 'error',
      event: 'SYSTEM_ERROR',
      operation,
      error: {
        message: error.message,
        stack: error.stack,
        name: error.name,
      },
      context,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Log business logic events
   */
  logBusinessEvent(event: string, operation: string, details: Record<string, any>): void {
    this.logger.log({
      level: 'info',
      event: 'BUSINESS_EVENT',
      businessEvent: event,
      operation,
      details,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Log performance metrics
   */
  logPerformance(operation: string, duration: number, details?: Record<string, any>): void {
    this.logger.log({
      level: 'info',
      event: 'PERFORMANCE_METRIC',
      operation,
      durationMs: duration,
      details,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Log debug information (should be disabled in production)
   */
  logDebug(message: string, details?: Record<string, any>): void {
    this.logger.debug({
      level: 'debug',
      message,
      details,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Log token operations
   */
  logTokenOperation(operation: string, userId?: string, details?: Record<string, any>): void {
    this.logger.log({
      level: 'info',
      event: 'TOKEN_OPERATION',
      operation,
      userId,
      details,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Log session operations
   */
  logSessionOperation(operation: string, sessionId: string, userId?: string, details?: Record<string, any>): void {
    this.logger.log({
      level: 'info',
      event: 'SESSION_OPERATION',
      operation,
      sessionId,
      userId,
      details,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Log OAuth operations
   */
  logOAuthOperation(operation: string, provider: string, userId?: string, details?: Record<string, any>): void {
    this.logger.log({
      level: 'info',
      event: 'OAUTH_OPERATION',
      operation,
      provider,
      userId,
      details,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Log rate limiting events
   */
  logRateLimit(event: string, identifier: string, count: number, limit: number, resetTime?: Date): void {
    this.logger.warn({
      level: 'warn',
      event: 'RATE_LIMIT_EVENT',
      rateLimitEvent: event,
      identifier,
      count,
      limit,
      resetTime: resetTime?.toISOString(),
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Log configuration validation
   */
  logConfigValidation(component: string, status: 'success' | 'failure', details?: Record<string, any>): void {
    this.logger.log({
      level: status === 'success' ? 'info' : 'error',
      event: 'CONFIG_VALIDATION',
      component,
      status,
      details,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Determine appropriate log level for security events
   */
  private getLogLevelForSecurityEvent(severity: string): 'log' | 'warn' | 'error' {
    switch (severity.toLowerCase()) {
      case 'critical':
      case 'high':
        return 'error';
      case 'medium':
        return 'warn';
      case 'low':
      default:
        return 'log';
    }
  }
}