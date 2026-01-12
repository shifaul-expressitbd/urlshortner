import {
  Injectable,
  InternalServerErrorException,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { DatabaseService } from '../../database/database.service';
import { UsersService } from '../../users/users.service';
import { IpGeolocationService } from '../common/services/ip-geolocation.service';

export interface JwtPayload {
  sub: string;
  email: string;
  role?: string;
  systemRole?: string;

  type?: string;
  permissions?: string[];
  iat?: number;
  exp?: number;
  impersonatedBy?: string;
  rememberMe?: boolean;
  impersonatorEmail?: string;
  isImpersonation?: boolean;
  sessionId?: string;
  tokenFamily?: string;
}

export interface RefreshTokenResponse {
  accessToken: string;
  refreshToken: string;
  session: any;
}

@Injectable()
export class TokenService {
  private readonly logger = new Logger(TokenService.name);
  private readonly appName = 'Platform';

  // GTM Permission Token Configuration
  private readonly GTM_PERMISSIONS = [
    'gtm.accounts.read',
    'gtm.containers.read',
    'gtm.tags.read',
  ] as const;

  private readonly GTM_TOKEN_TYPE = 'gtm-permission';
  private readonly GTM_TOKEN_EXPIRY = '15m';

  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly prisma: DatabaseService,
    private readonly usersService: UsersService,
    private readonly ipGeolocationService: IpGeolocationService,
  ) { }

  /**
   * Generate JWT tokens with session management
   */
  async generateTokens(
    userId: string,
    email: string,
    role: string,
    systemRole: string,
    rememberMe = false,
    ipAddress?: string,
    userAgent?: string,
    deviceInfo?: any,
    additionalHeaders?: Record<string, string>,
  ): Promise<RefreshTokenResponse> {
    try {
      const jwtSecret = this.configService.get<string>('JWT_SECRET');

      if (!jwtSecret) {
        throw new Error('JWT secrets missing');
      }

      // Generate session expiry and refresh token expiry
      const sessionExpiryHours = rememberMe ? 30 * 24 : 24; // 30 days or 24 hours
      const refreshTokenExpiryHours = rememberMe ? 30 * 24 : 7 * 24; // 30 days or 7 days

      // Create user session with enhanced security
      const session = await this.createUserSession(
        userId,
        rememberMe,
        ipAddress,
        userAgent,
        deviceInfo,
        additionalHeaders,
      );

      // Create base payload
      const crypto = require('crypto');
      const tokenFamily = crypto.randomBytes(16).toString('hex');
      const payload: JwtPayload = {
        sub: userId,
        email,
        role,
        systemRole,
        rememberMe,
        sessionId: session.sessionId,
        tokenFamily,
      };

      this.logger.log(`🔑 ========== TOKEN GENERATION ==========`);
      this.logger.log(`🔑 Session ID: ${session.sessionId}`);
      this.logger.log(`🔑 Token Family: ${tokenFamily}`);
      this.logger.log(`🔑 User ID: ${userId}`);

      const accessTokenExpiresInSeconds =
        this.configService.get<number>('jwt.accessTokenExpiresInSeconds') || 86400;
      const refreshTokenExpiresInSeconds = rememberMe
        ? this.configService.get<number>('jwt.refreshTokenRememberMeExpiresInSeconds') || 2592000
        : this.configService.get<number>('jwt.refreshTokenExpiresInSeconds') || 604800;

      // Generate access token
      const accessToken = await this.jwtService.signAsync(payload, {
        secret: jwtSecret,
        expiresIn: accessTokenExpiresInSeconds,
      });

      // Generate refresh token with session info
      const refreshPayload: JwtPayload = {
        sub: userId,
        email,
        role,
        systemRole,
        rememberMe,
        sessionId: session.sessionId,
        tokenFamily: payload.tokenFamily,
      };

      const refreshToken = await this.jwtService.signAsync(refreshPayload, {
        secret: jwtSecret,
        expiresIn: refreshTokenExpiresInSeconds,
      });

      // Note: We are not storing refresh token in DB, only relying on JWT
      // Wait for user instruction if we need to store in Redis later
      /*
      await this.storeRefreshToken(
        session.id,
        refreshToken,
        payload.tokenFamily || '',
        ipAddress,
        userAgent,
      );
      */

      this.logger.log(`✅ Generated tokens for session ${session.sessionId}`);
      return { accessToken, refreshToken, session };
    } catch (error) {
      this.logger.error(
        `Failed to generate tokens for user ${userId}:`,
        error.message,
      );
      throw error;
    }
  }

  /**
   * Refresh tokens using existing session (for refresh token endpoint)
   * This method reuses the existing session instead of creating a new one
   */
  async refreshTokensWithExistingSession(
    existingSession: any,
    userId: string,
    email: string,
    role: string,
    systemRole: string,
    rememberMe: boolean,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<RefreshTokenResponse> {
    try {
      const jwtSecret = this.configService.get<string>('JWT_SECRET');

      if (!jwtSecret) {
        throw new Error('JWT secrets missing');
      }

      // Generate a NEW token family for rotation (keep same session)
      const crypto = require('crypto');
      const newTokenFamily = crypto.randomBytes(16).toString('hex');

      // Create base payload using existing session info
      const payload: JwtPayload = {
        sub: userId,
        email,
        role,
        systemRole,
        rememberMe,
        sessionId: existingSession.sessionId, // Reuse existing sessionId
        tokenFamily: newTokenFamily, // New token family for rotation
      };

      this.logger.log(`🔄 ========== REFRESHING TOKENS ==========`);
      this.logger.log(`🔄 Existing Session ID: ${existingSession.sessionId}`);
      this.logger.log(`🔄 New Token Family: ${newTokenFamily}`);
      this.logger.log(`🔄 User ID: ${userId}`);

      const accessTokenExpiresInSeconds =
        this.configService.get<number>('jwt.accessTokenExpiresInSeconds') || 86400;
      const refreshTokenExpiresInSeconds = rememberMe
        ? this.configService.get<number>('jwt.refreshTokenRememberMeExpiresInSeconds') || 2592000
        : this.configService.get<number>('jwt.refreshTokenExpiresInSeconds') || 604800;

      // Generate access token with current timestamp to ensure uniqueness
      const accessToken = await this.jwtService.signAsync(
        {
          ...payload,
          iat: Math.floor(Date.now() / 1000), // Force new issued at time
        },
        {
          secret: jwtSecret,
          expiresIn: accessTokenExpiresInSeconds,
        },
      );

      // Generate refresh token with existing session info
      const refreshPayload: JwtPayload = {
        sub: userId,
        email,
        role,
        systemRole,
        rememberMe,
        sessionId: existingSession.sessionId, // Reuse existing sessionId
        tokenFamily: newTokenFamily, // New token family for rotation
      };

      const refreshToken = await this.jwtService.signAsync(
        {
          ...refreshPayload,
          iat: Math.floor(Date.now() / 1000), // Force new issued at time
        },
        {
          secret: jwtSecret,
          expiresIn: refreshTokenExpiresInSeconds,
        },
      );

      this.logger.log(
        `🔄 Generated new access token with iat: ${Math.floor(Date.now() / 1000)}`,
      );
      this.logger.log(
        `🔄 Generated new refresh token with iat: ${Math.floor(Date.now() / 1000)}`,
      );

      // Store refresh token in database (reusing existing session)
      /*
      await this.storeRefreshToken(
        existingSession.id, // Use existing session ID
        refreshToken,
        newTokenFamily,
        ipAddress,
        userAgent,
      );
      */

      // Update session activity
      await this.prisma.userSession.update({
        where: { id: existingSession.id },
        data: { lastActivity: new Date() },
      });

      this.logger.log(
        `✅ Refreshed tokens for existing session ${existingSession.sessionId}`,
      );
      return { accessToken, refreshToken, session: existingSession };
    } catch (error) {
      this.logger.error(
        `Failed to refresh tokens for user ${userId}:`,
        error.message,
      );
      throw error;
    }
  }

  /**
   * Validate and consume a refresh token
   */
  /**
   * Validate and consume a refresh token
   * We only verify JWT signature and session existence/validity
   */
  async validateAndConsumeRefreshToken(
    refreshToken: string,
    userId: string,
  ): Promise<{ session: any; tokenFamily: string | null }> {
    try {
      this.logger.log(
        `🔍 ========== REFRESH TOKEN VALIDATION START ==========`,
      );
      // ... log details

      const jwtSecret = this.configService.get<string>('JWT_SECRET');
      if (!jwtSecret) {
        throw new Error('JWT_SECRET missing');
      }

      // Verify the JWT and extract payload
      const payload = await this.jwtService.verifyAsync(refreshToken, {
        secret: jwtSecret,
      });

      if (!payload.sessionId) {
        throw new UnauthorizedException('Invalid refresh token payload');
      }

      // Find the specific session
      const session = await this.prisma.userSession.findUnique({
        where: {
          sessionId: payload.sessionId,
          userId,
          isActive: true,
          expiresAt: { gt: new Date() },
        },
      });

      if (!session) {
        throw new UnauthorizedException('Session not found or expired');
      }

      // Update session activity
      await this.prisma.userSession.update({
        where: { id: session.id },
        data: { lastActivity: new Date() },
      });

      this.logger.log(
        `✅ Consumed valid refresh token for session ${session.id}`,
      );
      return { session, tokenFamily: payload.tokenFamily || null };
    } catch (error) {
      this.logger.error(
        `Refresh token validation failed for user ${userId}:`,
        error.message,
      );
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }

  /**
   * Generate GTM permission token for accessing Google Tag Manager APIs
   */
  async generateGTMPermissionToken(
    userId: string,
    context?: any,
  ): Promise<{ permissionToken: string; expiresIn: number; issuedAt: number }> {
    try {
      const user = await this.usersService.findById(userId);
      if (!user) {
        throw new NotFoundException('User not found');
      }

      // Verify user has Google authentication configured
      const googleProvider = await this.prisma.authProvider.findFirst({
        where: {
          userId: userId,
          provider: 'GOOGLE',
        },
      });

      if (!googleProvider?.accessToken) {
        throw new UnauthorizedException(
          'Google authentication required for GTM access. Please authenticate with Google first.',
        );
      }

      // Generate permission token with GTM-specific permissions
      const payload: any = {
        sub: userId,
        email: user.email,
        type: this.GTM_TOKEN_TYPE,
        permissions: this.GTM_PERMISSIONS,
      };

      // Only include context if it has meaningful data
      if (context && Object.keys(context).length > 0) {
        payload.context = context;
      }

      // Use standard expiresIn approach instead of manual exp to avoid conflicts
      const permissionToken = await this.jwtService.signAsync(payload, {
        secret: this.configService.get<string>('JWT_SECRET'),
        expiresIn: this.GTM_TOKEN_EXPIRY,
        noTimestamp: false,
        audience: 'cutzy.app-gtm',
        issuer: 'cutzy.app-auth',
      });

      // Calculate expiresIn for 15 minute token
      const EXPIRES_IN_15_MINUTES = 15 * 60 * 1000; // 900,000 ms

      return {
        permissionToken,
        expiresIn: EXPIRES_IN_15_MINUTES,
        issuedAt: Date.now(),
      };
    } catch (error) {
      this.logger.error(
        `Failed to generate GTM permission token for user ${userId}:`,
        error.message,
      );
      throw error;
    }
  }

  /**
   * Generate email verification token
   */
  async generateEmailVerificationToken(email: string): Promise<string> {
    try {
      const payload: JwtPayload = {
        email,
        type: 'verification',
        sub: email,
      };

      const jwtSecret = this.configService.get<string>('JWT_SECRET');
      if (!jwtSecret) throw new Error('JWT_SECRET missing');

      const verificationToken = await this.jwtService.signAsync(payload, {
        secret: jwtSecret,
        expiresIn: '24h',
        noTimestamp: false,
      });

      return verificationToken;
    } catch (error) {
      this.logger.error(
        'Failed to generate email verification token:',
        error.message,
      );
      throw new InternalServerErrorException(
        'Failed to generate verification token',
      );
    }
  }

  /**
   * Validate JWT secrets
   */
  validateJWTSecrets(): void {
    const jwtSecret = this.configService.get<string>('JWT_SECRET');
    const jwtRefreshSecret =
      this.configService.get<string>('JWT_REFRESH_SECRET');

    this.logger.log(
      `🔐 [TokenService] Validating JWT secrets at ${new Date().toISOString()}`,
    );
    this.logger.log(
      `🔐 [TokenService] JWT_SECRET length: ${jwtSecret?.length || 'undefined'}`,
    );
    this.logger.log(
      `🔐 [TokenService] JWT_REFRESH_SECRET length: ${jwtRefreshSecret?.length || 'undefined'}`,
    );

    if (!jwtSecret || jwtSecret.length < 32) {
      this.logger.error(
        `❌ [TokenService] JWT_SECRET validation failed: ${!jwtSecret ? 'NOT FOUND' : `too short (${jwtSecret.length} chars)`}`,
      );
      throw new Error(
        `JWT_SECRET is missing or too short (minimum 32 characters). Found length: ${jwtSecret?.length || 'undefined'}`,
      );
    }

    if (!jwtRefreshSecret || jwtRefreshSecret.length < 32) {
      this.logger.error(
        `❌ [TokenService] JWT_REFRESH_SECRET validation failed: ${!jwtRefreshSecret ? 'NOT FOUND' : `too short (${jwtRefreshSecret.length} chars)`}`,
      );
      throw new Error(
        `JWT_REFRESH_SECRET is missing or too short (minimum 32 characters). Found length: ${jwtRefreshSecret?.length || 'undefined'}`,
      );
    }

    this.logger.log('✅ [TokenService] JWT secrets validated successfully');
  }

  /**
   * Decode and verify JWT token without throwing errors
   */
  async decodeToken(token: string): Promise<JwtPayload | null> {
    try {
      const jwtSecret = this.configService.get<string>('JWT_SECRET');
      if (!jwtSecret) return null;

      const payload = await this.jwtService.verifyAsync(token, {
        secret: jwtSecret,
      });

      return payload;
    } catch (error) {
      this.logger.warn('Failed to decode token:', error.message);
      return null;
    }
  }

  /**
   * Check if token is expired
   */
  async isTokenExpired(token: string): Promise<boolean> {
    try {
      const decoded = await this.decodeToken(token);
      if (!decoded) return true;

      const now = Math.floor(Date.now() / 1000);
      return (decoded.exp || 0) < now;
    } catch (error) {
      return true;
    }
  }

  /**
   * Extract token metadata without verification
   */
  extractTokenMetadata(token: string): any {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;

      const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
      return {
        sub: payload.sub,
        email: payload.email,
        type: payload.type,
        permissions: payload.permissions,
        iat: payload.iat,
        exp: payload.exp,
        sessionId: payload.sessionId,
        tokenFamily: payload.tokenFamily,
      };
    } catch (error) {
      this.logger.warn('Failed to extract token metadata:', error.message);
      return null;
    }
  }

  /**
   * Create user session (internal helper)
   */
  private async createUserSession(
    userId: string,
    rememberMe = false,
    ipAddress?: string,
    userAgent?: string,
    deviceInfo?: any,
    additionalHeaders?: Record<string, string>,
  ): Promise<any> {
    try {
      // Generate device fingerprint
      const browserFingerprintHash = this.generateBrowserFingerprintHash(
        userAgent || '',
        additionalHeaders,
      );

      // Detect geolocation
      const geolocation = ipAddress
        ? await this.detectGeolocation(ipAddress)
        : {};

      // Calculate session expiry
      const sessionExpiryHours = rememberMe ? 30 * 24 : 24;
      const expiresAt = new Date(
        Date.now() + sessionExpiryHours * 60 * 60 * 1000,
      );

      // Generate unique session ID
      const crypto = require('crypto');
      const sessionId = crypto.randomBytes(32).toString('hex');

      // Create enhanced session data
      const sessionData = {
        userId,
        sessionId,
        deviceInfo: {
          ...deviceInfo,
          fingerprintGeneratedAt: new Date().toISOString(),
        },
        ipAddress,
        userAgent,
        location: geolocation.location,
        browserFingerprintHash,
        deviceFingerprintConfidence: 0.8,
        latitude: geolocation.latitude,
        longitude: geolocation.longitude,
        timezone: geolocation.timezone,
        rememberMe,
        expiresAt,
      };

      const session = await this.prisma.userSession.create({
        data: sessionData,
      });

      this.logger.log(`✅ ========== SESSION CREATED ==========`);
      this.logger.log(`✅ Session ID: ${sessionId}`);
      this.logger.log(`✅ Database Session ID: ${session.id}`);
      this.logger.log(`✅ User ID: ${userId}`);
      this.logger.log(`✅ Expires At: ${expiresAt}`);

      return session;
    } catch (error) {
      this.logger.error(
        `Failed to create user session for user ${userId}:`,
        error.message,
      );
      throw error;
    }
  }

  /**
   * Store refresh token (internal helper)
   */
  /*
  private async storeRefreshToken(
    sessionId: string,
    refreshToken: string,
    tokenFamily: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<any> {
    // Stubbed out - logic moved to no-op as per requirement
    return null; 
  }
  */

  /**
   * Generate browser fingerprint hash (helper)
   */
  private generateBrowserFingerprintHash(
    userAgent: string,
    additionalHeaders?: Record<string, string>,
  ): string {
    try {
      const crypto = require('crypto');
      const fingerprintData = {
        userAgent: userAgent || '',
        acceptLanguage: additionalHeaders?.['accept-language'] || '',
        acceptEncoding: additionalHeaders?.['accept-encoding'] || '',
        accept: additionalHeaders?.['accept'] || '',
        dnt: additionalHeaders?.['dnt'] || '',
        secChUa: additionalHeaders?.['sec-ch-ua'] || '',
        secChUaMobile: additionalHeaders?.['sec-ch-ua-mobile'] || '',
        secChUaPlatform: additionalHeaders?.['sec-ch-ua-platform'] || '',
      };

      const fingerprintString = JSON.stringify(
        fingerprintData,
        Object.keys(fingerprintData).sort(),
      );
      return crypto
        .createHash('sha256')
        .update(fingerprintString)
        .digest('hex');
    } catch (error) {
      this.logger.warn(
        'Failed to generate browser fingerprint hash:',
        error.message,
      );
      return '';
    }
  }

  /**
   * Detect geolocation from IP (helper)
   */
  private async detectGeolocation(ipAddress: string): Promise<{
    latitude?: number;
    longitude?: number;
    timezone?: string;
    location?: string;
  }> {
    try {
      const geolocationResult = await this.ipGeolocationService.detectGeolocation(ipAddress);
      return {
        latitude: geolocationResult.latitude,
        longitude: geolocationResult.longitude,
        timezone: geolocationResult.timezone,
        location: geolocationResult.location,
      };
    } catch (error) {
      this.logger.warn(
        `Failed to detect geolocation for IP ${ipAddress}:`,
        error.message,
      );
      return {};
    }
  }
}
