// src/auth/auth.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { LoggerService } from 'src/utils/logger/logger.service';
import { MailModule } from 'src/mail/mail.module';
import { UsersModule } from 'src/users/users.module';
import { UrlConfigService } from 'src/config/url.config';

// Controllers
import { AuthController } from './authentication/authentication.controller';
import { OAuthController } from './oauth/oauth.controller';
import { SessionController } from './session/session.controller';
import { TwoFactorController } from './two-factor/two-factor.controller';

// Services
import { AuthenticationService } from './authentication/authentication.service';
import { OAuthService } from './oauth/oauth.service';
import { SessionService } from './session/session.service';
import { TokenService } from './token/token.service';
import { TwoFactorService } from './two-factor/two-factor.service';
import { IpGeolocationService } from './common/services/ip-geolocation.service';

// Strategies
import { FacebookStrategy } from './oauth/strategies/facebook.strategy';
import { GithubStrategy } from './oauth/strategies/github.strategy';
import { GoogleStrategy } from './oauth/strategies/google.strategy';
import { JwtStrategy } from './token/strategies/jwt.strategy';
import { LocalStrategy } from './common/strategies/local.strategy';
import { RefreshTokenStrategy } from './token/strategies/refresh-token.strategy';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => {
        // Get JWT configuration from ConfigService
        const secret = configService.get<string>('jwt.secret');
        const accessTokenExpiresInSeconds = configService.get<number>('jwt.accessTokenExpiresInSeconds');

        if (!secret) {
          throw new Error(
            'JWT_SECRET is not configured. Please check your .env file and ensure JWT_SECRET is set.',
          );
        }

        if (secret.length < 32) {
          throw new Error('JWT_SECRET must be at least 32 characters long');
        }

        return {
          secret,
          signOptions: {
            expiresIn: accessTokenExpiresInSeconds,
            issuer: 'backend.shifaul.dev-api',
            audience: 'backend.shifaul.dev-client',
          },
          verifyOptions: {
            issuer: 'backend.shifaul.dev-api',
            audience: 'backend.shifaul.dev-client',
          },
        };
      },
      inject: [ConfigService],
    }),
    UsersModule,
    MailModule,
  ],
  controllers: [
    AuthController,
    OAuthController,
    TwoFactorController,
    SessionController,
  ],
  providers: [
    // Services
    AuthenticationService,
    OAuthService,
    TwoFactorService,
    SessionService,
    TokenService,
    IpGeolocationService,
    LoggerService,

    // Strategies
    LocalStrategy,
    JwtStrategy,
    RefreshTokenStrategy,
    GoogleStrategy,
    FacebookStrategy,
    GithubStrategy,
    UrlConfigService,
  ],
  exports: [
    AuthenticationService,
    OAuthService,
    TwoFactorService,
    SessionService,
    TokenService,
    JwtModule,
    PassportModule,
  ],
})
export class AuthModule {}
