// Enhanced session service with proper database transactions
// Prevents race conditions in concurrent session operations

import { Injectable, Logger, NotFoundException, BadRequestException } from '@nestjs/common';
import { DatabaseService } from 'src/database/database.service';
import { MailService } from 'src/mail/mail.service';
import { UsersService } from 'src/users/users.service';
import { LoggerService } from 'src/utils/logger/logger.service';

export interface SessionInfo {
  id: string;
  sessionId: string;
  deviceInfo?: any;
  ipAddress?: string | null;
  userAgent?: string | null;
  location?: string | null;
  isActive: boolean;
  expiresAt: Date;
  lastActivity: Date;
  rememberMe: boolean;
  createdAt: Date;
  browserFingerprintHash?: string | null;
  deviceFingerprintConfidence?: number | null;
  latitude?: number | null;
  longitude?: number | null;
  timezone?: string | null;
  riskScore?: number;
  unusualActivityCount?: number;
  invalidatedAt?: Date | null;
  invalidationReason?: string | null;
}

export interface TransactionResult<T = void> {
  success: boolean;
  data?: T;
  error?: string;
  retryAfter?: number;
}

@Injectable()
export class TransactionalSessionService {
  private readonly logger = new Logger(TransactionalSessionService.name);

  constructor(
    private readonly prisma: DatabaseService,
    private readonly usersService: UsersService,
    private readonly loggerService: LoggerService,
    private readonly mailService: MailService,
  ) {}

  /**
   * Atomically invalidates a session and all associated refresh tokens
   * Uses database transactions to prevent race conditions
   */
  async invalidateSessionAtomic(
    userId: string, 
    sessionId: string,
    reason?: string
  ): Promise<TransactionResult<void>> {
    const maxRetries = 3;
    let lastError: any;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const result = await this.prisma.$transaction(async (tx) => {
          // Find session with optimistic approach
          const session = await tx.userSession.findFirst({
            where: {
              userId,
              sessionId,
              isActive: true,
            },
          });

          if (!session) {
            throw new NotFoundException('Session not found or already invalid');
          }

          // Refresh tokens are not stored in DB anymore, so detailed tracking 
          // happens only via JWT invalidation mechanisms (if implemented)
          // or implicit invalidation via session status

          // Update session status atomically
          await tx.userSession.update({
            where: { id: session.id },
            data: { 
              isActive: false,
              invalidatedAt: new Date(),
              invalidationReason: reason || 'User requested invalidation',
            },
          });

          this.logger.log(
            `✅ Atomic session invalidation: ${sessionId} (deleted 0 tokens)`
          );

          return {
            sessionId: session.sessionId,
            deletedTokens: 0,
          };
        });

        return { success: true, data: undefined };
      } catch (error) {
        lastError = error;
        
        // Check if it's a deadlock or transaction conflict
        if (this.isRetryableError(error) && attempt < maxRetries) {
          this.logger.warn(
            `Session invalidation attempt ${attempt} failed, retrying: ${error.message}`
          );
          
          // Exponential backoff for retries
          await this.delay(Math.pow(2, attempt) * 100);
          continue;
        }
        
        break; // Exit retry loop
      }
    }

    // All retries failed
    this.logger.error(
      `Failed to invalidate session ${sessionId} after ${maxRetries} attempts`,
      lastError
    );

    if (lastError instanceof NotFoundException) {
      return { success: false, error: 'Session not found' };
    }

    return { 
      success: false, 
      error: 'Failed to invalidate session due to database conflict' 
    };
  }

  /**
   * Atomically invalidates multiple sessions with proper error handling
   */
  async invalidateSessionsBatchAtomic(
    userId: string,
    sessionIds: string[],
    excludeCurrentSession?: string,
    reason?: string
  ): Promise<TransactionResult<{ invalidatedCount: number }>> {
    const maxRetries = 3;
    let lastError: any;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const result = await this.prisma.$transaction(async (tx) => {
          // Build query conditions
          const conditions: any = {
            userId,
            isActive: true,
            id: { in: sessionIds },
          };

          // Exclude current session if specified
          if (excludeCurrentSession) {
            conditions.sessionId = { not: excludeCurrentSession };
          }

          // Get sessions to invalidate
          const sessions = await tx.userSession.findMany({
            where: conditions,
          });

          if (sessions.length === 0) {
            return { invalidatedCount: 0, deletedTokens: 0 };
          }

          const sessionIds_list = sessions.map(s => s.id);

          // Refresh tokens are not stored in DB anymore

          // Update all sessions atomically
          await tx.userSession.updateMany({
            where: {
              id: { in: sessionIds_list },
            },
            data: {
              isActive: false,
              invalidatedAt: new Date(),
              invalidationReason: reason || 'Batch invalidation',
            },
          });

          this.logger.log(
            `✅ Atomic batch invalidation: ${sessions.length} sessions, 0 tokens`
          );

          return {
            invalidatedCount: sessions.length,
            deletedTokens: 0,
          };
        });

        return { success: true, data: result };
      } catch (error) {
        lastError = error;
        
        if (this.isRetryableError(error) && attempt < maxRetries) {
          this.logger.warn(
            `Batch session invalidation attempt ${attempt} failed, retrying: ${error.message}`
          );
          await this.delay(Math.pow(2, attempt) * 100);
          continue;
        }
        
        break;
      }
    }

    this.logger.error(
      `Failed to invalidate sessions batch after ${maxRetries} attempts`,
      lastError
    );

    return { success: false, error: 'Failed to invalidate sessions batch' };
  }

  /**
   * Atomically updates session activity with conflict detection
   */
  async updateSessionActivityAtomic(
    sessionId: string,
    lastActivity: Date = new Date()
  ): Promise<TransactionResult<void>> {
    try {
      await this.prisma.$transaction(async (tx) => {
        // Find session and update atomically
        const result = await tx.userSession.updateMany({
          where: {
            sessionId,
            isActive: true,
            expiresAt: { gt: new Date() },
          },
          data: {
            lastActivity,
          },
        });

        if (result.count === 0) {
          throw new NotFoundException('Session not found or expired');
        }
      });

      return { success: true };
    } catch (error) {
      this.logger.warn(
        `Failed to update session activity for ${sessionId}: ${error.message}`
      );
      
      if (error instanceof NotFoundException) {
        return { success: false, error: 'Session not found or expired' };
      }
      
      return { success: false, error: 'Failed to update session activity' };
    }
  }

  /**
   * Cleans up expired sessions atomically
   */
  async cleanupExpiredSessionsAtomic(): Promise<TransactionResult<{
    sessionsDeleted: number;
    tokensDeleted: number;
  }>> {
    try {
      const result = await this.prisma.$transaction(async (tx) => {
        const now = new Date();

        // Find expired sessions to clean up
        const expiredSessions = await tx.userSession.findMany({
          where: {
            OR: [
              { expiresAt: { lt: now } },
              { isActive: false }
            ],
          },
          select: { id: true, sessionId: true },
        });

        if (expiredSessions.length === 0) {
          return { sessionsDeleted: 0, tokensDeleted: 0 };
        }

        const sessionIds_list = expiredSessions.map(s => s.id);

        // Refresh tokens are not stored in DB anymore

        // Delete expired sessions
        const sessionsDeletedResult = await tx.userSession.deleteMany({
          where: {
            id: { in: sessionIds_list },
          },
        });

        this.logger.log(
          `🧹 Cleanup: ${sessionsDeletedResult.count} sessions, 0 tokens`
        );

        return {
          sessionsDeleted: sessionsDeletedResult.count,
          tokensDeleted: 0,
        };
      });

      return { success: true, data: result };
    } catch (error) {
      this.logger.error('Failed to cleanup expired sessions:', error);
      return { success: false, error: 'Failed to cleanup expired sessions' };
    }
  }

  /**
   * Gets active sessions with optimistic locking for concurrent access
   */
  async getActiveSessionsWithLock(userId: string): Promise<SessionInfo[]> {
    try {
      const sessions = await this.prisma.userSession.findMany({
        where: {
          userId,
          isActive: true,
          expiresAt: { gt: new Date() },
        },
        select: {
          id: true,
          sessionId: true,
          deviceInfo: true,
          ipAddress: true,
          userAgent: true,
          location: true,
          isActive: true,
          expiresAt: true,
          lastActivity: true,
          rememberMe: true,
          createdAt: true,
          browserFingerprintHash: true,
          deviceFingerprintConfidence: true,
          latitude: true,
          longitude: true,
          timezone: true,
          riskScore: true,
          unusualActivityCount: true,
          invalidatedAt: true,
          invalidationReason: true,
        },
        orderBy: {
          lastActivity: 'desc',
        },
      });

      return sessions.map(session => ({
        id: session.id,
        sessionId: session.sessionId,
        deviceInfo: session.deviceInfo,
        ipAddress: session.ipAddress,
        userAgent: session.userAgent,
        location: session.location,
        isActive: session.isActive,
        expiresAt: session.expiresAt,
        lastActivity: session.lastActivity,
        rememberMe: session.rememberMe,
        createdAt: session.createdAt,
        browserFingerprintHash: session.browserFingerprintHash,
        deviceFingerprintConfidence: session.deviceFingerprintConfidence,
        latitude: session.latitude,
        longitude: session.longitude,
        timezone: session.timezone,
        riskScore: session.riskScore,
        unusualActivityCount: session.unusualActivityCount,
        invalidatedAt: session.invalidatedAt,
        invalidationReason: session.invalidationReason,
      }));
    } catch (error) {
      this.logger.error(`Failed to get active sessions for user ${userId}:`, error);
      throw error;
    }
  }

  /**
   * Checks if an error is retryable (deadlock, transaction conflict, etc.)
   */
  private isRetryableError(error: any): boolean {
    // PostgreSQL deadlock detection
    if (error.code === '40P01') return true;
    
    // Serialization failure
    if (error.code === '40001') return true;
    
    // Transaction conflict
    if (error.message?.includes('could not serialize access')) return true;
    
    // Connection issues
    if (error.code === 'ECONNREFUSED' || error.code === 'ETIMEDOUT') return true;
    
    return false;
  }

  /**
   * Delay utility for exponential backoff
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}