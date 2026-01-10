// src/auth/strategies/jwt.strategy.ts
import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { DatabaseService } from 'src/database/database.service';
import { LoggerService } from 'src/utils/logger/logger.service';
import { JwtPayload } from '../../common/interfaces/jwt-payload.interface';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  private readonly logger = new Logger(JwtStrategy.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly prisma: DatabaseService,
    private readonly loggerService: LoggerService,
  ) {
    const secret =
      configService.get<string>('JWT_SECRET') ||
      configService.get<string>('jwt.secret');

    if (!secret) {
      throw new Error(
        'JWT_SECRET is not configured via ConfigService. Please set JWT_SECRET in your configuration.',
      );
    }

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: secret,
    });

    this.logger.log('JWT secret configured successfully via ConfigService.');
  }

  async validate(payload: JwtPayload) {
    // If this is a permission token (like GTM tokens), skip session validation
    if (payload.type === 'gtm-permission') {
      return {
        id: payload.sub,
        email: payload.email,
        role: payload.role,
        systemRole: payload.systemRole,
        type: payload.type,
        permissions: payload.permissions || [],
        impersonatedBy: payload.impersonatedBy,
        impersonatorEmail: payload.impersonatorEmail,
        isImpersonation: !!payload.isImpersonation,
        rememberMe: payload.rememberMe || false,
      };
    }

    // Validate session if sessionId is present in payload
    if (payload.sessionId) {
      try {
        const session = await this.prisma.userSession.findUnique({
          where: { sessionId: payload.sessionId },
        });

        if (!session) {
          this.loggerService.security(
            'SESSION_NOT_FOUND',
            {
              sessionId: payload.sessionId,
            },
            payload.sub,
          );
          throw new UnauthorizedException('Session not found');
        }

        if (!session.isActive) {
          this.loggerService.security(
            'SESSION_INACTIVE',
            {
              sessionId: payload.sessionId,
              invalidatedAt: session.invalidatedAt,
              invalidationReason: session.invalidationReason,
            },
            payload.sub,
          );
          throw new UnauthorizedException('Session is inactive');
        }

        if (session.expiresAt < new Date()) {
          this.loggerService.security(
            'SESSION_EXPIRED',
            {
              sessionId: payload.sessionId,
              expiresAt: session.expiresAt,
            },
            payload.sub,
          );
          throw new UnauthorizedException('Session has expired');
        }

        // Update session activity
        await this.prisma.userSession.update({
          where: { id: session.id },
          data: { lastActivity: new Date() },
        });

        // Log successful session validation
        this.loggerService.security(
          'SESSION_VALIDATED',
          {
            sessionId: payload.sessionId,
            riskScore: session.riskScore,
          },
          payload.sub,
        );
      } catch (error) {
        if (error instanceof UnauthorizedException) {
          throw error;
        }
        this.logger.error(
          `Session validation failed for user ${payload.sub}:`,
          error.message,
        );
        throw new UnauthorizedException('Session validation failed');
      }
    }

    // Return user object with systemRole and role from JWT payload
    // RolesGuard will use these for permission checks
    return {
      id: payload.sub,
      email: payload.email,
      role: payload.role,           // Tenant-level role (e.g., 'admin', 'user')
      systemRole: payload.systemRole, // System-level role (e.g., TENANT_OWNER, SYSTEM_ADMIN)
      type: payload.type,
      permissions: payload.permissions || [],
      impersonatedBy: payload.impersonatedBy,
      impersonatorEmail: payload.impersonatorEmail,
      isImpersonation: !!payload.isImpersonation,
      rememberMe: payload.rememberMe || false,
      sessionId: payload.sessionId,
    };
  }
}
