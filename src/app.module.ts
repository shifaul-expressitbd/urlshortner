import { HttpModule } from '@nestjs/axios';
import { MiddlewareConsumer, Module, NestModule, RequestMethod } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { EventEmitterModule } from '@nestjs/event-emitter';
import { ScheduleModule } from '@nestjs/schedule';
import { ServeStaticModule } from '@nestjs/serve-static';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { join } from 'path';
import { AdminModule } from './admin/admin.module';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { AccessTokenGuard } from './common/guards/access-token.guard';
import { ImpersonationGuard } from './common/guards/impersonation.guard';
import { RolesGuard } from './common/guards/roles.guard';
import { ResponseInterceptor } from './common/interceptors/response.interceptor';
import { CsrfMiddleware } from './common/middleware/csrf.middleware';

import { ContextService } from './common/services/context.service';
import { UrlConfigService } from './config/url.config';
import { validationSchema } from './config/validation.schema';
import { DatabaseModule } from './database/database.module';
import { MailModule } from './mail/mail.module';
import { UsersModule } from './users/users.module';
import { LoggerService } from './utils/logger/logger.service';
import { AnalyticsModule } from './analytics/analytics.module';
import { UrlShortenerModule } from './url-shortener/url-shortener.module';
import { OrganizationModule } from './organization/organization.module';
import { DomainsModule } from './domains/domains.module';
import { ApiRewriteMiddleware } from './common/middleware/api-rewrite.middleware';
import { DomainRedirectMiddleware } from './common/middleware/domain-redirect.middleware';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [() => require('./config/app.config').appConfig()],
      validationSchema,
      envFilePath: ['.env.local', '.env'],
    }),
    ScheduleModule.forRoot(),
    {
      module: class { },
      providers: [UrlConfigService],
      exports: [UrlConfigService],
      global: true,
    },
    // FIX: Corrected ThrottlerModule configuration - must use 'throttlers' array
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        throttlers: [
          {
            ttl: config.get<number>('THROTTLE_TTL', 60000),
            limit: config.get<number>('THROTTLE_LIMIT', 100),
          },
        ],
      }),
    }),
    EventEmitterModule.forRoot({
      wildcard: false,
      delimiter: '.',
      newListener: false,
      removeListener: false,
      maxListeners: 10,
      verboseMemoryLeak: false,
      ignoreErrors: false,
    }),

    // Static file serving for uploads folder
    ServeStaticModule.forRoot({
      rootPath: join(process.cwd(), 'uploads'),
      serveRoot: '/files',
      serveStaticOptions: {
        index: false, // Don't serve index.html
        setHeaders: (res, path) => {
          // Set cache headers for static files
          res.setHeader('Cache-Control', 'public, max-age=3600');
        },
      },
    }),

    HttpModule,
    DatabaseModule,
    AuthModule,
    UsersModule,
    MailModule,
    AdminModule,
    EventEmitterModule.forRoot(),
    AnalyticsModule,
    UrlShortenerModule,
    OrganizationModule,
    DomainsModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    LoggerService,
    ContextService,
    {
      provide: APP_INTERCEPTOR,
      useClass: ResponseInterceptor,
    },
    {
      provide: APP_GUARD,
      useClass: AccessTokenGuard,
    },
    {
      provide: APP_GUARD,
      useClass: RolesGuard,
    },
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
    ImpersonationGuard,
    CsrfMiddleware,
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(ApiRewriteMiddleware)
      .forRoutes({ path: '*', method: RequestMethod.ALL });

    consumer
      .apply(DomainRedirectMiddleware)
      .forRoutes({ path: '*', method: RequestMethod.ALL });
  }
}
