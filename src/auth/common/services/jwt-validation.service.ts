// Centralized JWT secret validation service
// This resolves the scattered JWT validation logic across modules

import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtValidationService {
  private readonly logger = new Logger(JwtValidationService.name);

  constructor(private readonly configService: ConfigService) {}

  /**
   * Validates JWT secrets configuration at startup
   * This ensures all JWT-related operations have valid secrets
   */
  validateJWTSecrets(): void {
    const jwtSecret = this.configService.get<string>('JWT_SECRET');
    const jwtRefreshSecret = this.configService.get<string>('JWT_REFRESH_SECRET');

    this.logger.log(`🔐 [JwtValidation] Validating JWT secrets at ${new Date().toISOString()}`);
    this.logger.log(`🔐 [JwtValidation] JWT_SECRET length: ${jwtSecret?.length || 'undefined'}`);
    this.logger.log(`🔐 [JwtValidation] JWT_REFRESH_SECRET length: ${jwtRefreshSecret?.length || 'undefined'}`);

    if (!jwtSecret || jwtSecret.length < 32) {
      this.logger.error(
        `❌ [JwtValidation] JWT_SECRET validation failed: ${!jwtSecret ? 'NOT FOUND' : `too short (${jwtSecret.length} chars)`}`,
      );
      throw new Error(
        `JWT_SECRET is missing or too short (minimum 32 characters). Found length: ${jwtSecret?.length || 'undefined'}`,
      );
    }

    if (!jwtRefreshSecret || jwtRefreshSecret.length < 32) {
      this.logger.error(
        `❌ [JwtValidation] JWT_REFRESH_SECRET validation failed: ${!jwtRefreshSecret ? 'NOT FOUND' : `too short (${jwtRefreshSecret.length} chars)`}`,
      );
      throw new Error(
        `JWT_REFRESH_SECRET is missing or too short (minimum 32 characters). Found length: ${jwtRefreshSecret?.length || 'undefined'}`,
      );
    }

    this.logger.log('✅ [JwtValidation] JWT secrets validated successfully');
  }

  /**
   * Gets validated JWT secret for access tokens
   */
  getAccessTokenSecret(): string {
    const secret = this.configService.get<string>('JWT_SECRET');
    if (!secret || secret.length < 32) {
      throw new Error('JWT_SECRET is not properly configured');
    }
    return secret;
  }

  /**
   * Gets validated JWT secret for refresh tokens
   */
  getRefreshTokenSecret(): string {
    const secret = this.configService.get<string>('JWT_REFRESH_SECRET');
    if (!secret || secret.length < 32) {
      throw new Error('JWT_REFRESH_SECRET is not properly configured');
    }
    return secret;
  }

  /**
   * Gets JWT configuration from environment with validation
   */
  getJWTConfig(): {
    accessTokenExpiresInSeconds: number;
    refreshTokenExpiresInSeconds: number;
    refreshTokenRememberMeExpiresInSeconds: number;
  } {
    const accessTokenExpiresInSeconds = this.configService.get<number>('jwt.accessTokenExpiresInSeconds') || 900; // 15 minutes
    const refreshTokenExpiresInSeconds = this.configService.get<number>('jwt.refreshTokenExpiresInSeconds') || 604800; // 7 days
    const refreshTokenRememberMeExpiresInSeconds = this.configService.get<number>('jwt.refreshTokenRememberMeExpiresInSeconds') || 2592000; // 30 days

    return {
      accessTokenExpiresInSeconds,
      refreshTokenExpiresInSeconds,
      refreshTokenRememberMeExpiresInSeconds,
    };
  }

  /**
   * Validates if a token secret meets security requirements
   */
  validateTokenSecret(secret: string, secretName: string): boolean {
    if (!secret) {
      this.logger.error(`❌ [JwtValidation] ${secretName} is missing`);
      return false;
    }

    if (secret.length < 32) {
      this.logger.error(`❌ [JwtValidation] ${secretName} is too short (${secret.length} chars, minimum 32)`);
      return false;
    }

    // Check for weak secrets (simple patterns)
    if (/^[a-zA-Z0-9]{32,}$/.test(secret) === false) {
      this.logger.warn(`⚠️ [JwtValidation] ${secretName} might contain weak characters`);
    }

    this.logger.log(`✅ [JwtValidation] ${secretName} validation passed`);
    return true;
  }
}