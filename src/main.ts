// src/main.ts
import { Logger, RequestMethod, ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { SwaggerModule } from '@nestjs/swagger';
import cookieParser from 'cookie-parser';
import { AppModule } from './app.module';
import { HttpExceptionFilter } from './common/filters/http-exception.filter';
import { LoggingInterceptor } from './common/interceptors/logging.interceptor';
import { ResponseInterceptor } from './common/interceptors/response.interceptor';
import { CsrfMiddleware } from './common/middleware/csrf.middleware';
import { UrlConfigService } from './config/url.config';
import { createSwaggerConfig, SWAGGER_CONFIG } from './swagger/swagger.config';
import { LoggerService } from './utils/logger/logger.service';

async function bootstrap() {
  const logger = new Logger('Bootstrap'); // Use simple logger for bootstrap
  const app = await NestFactory.create(AppModule);

  // Enable cookie parser (required for csrf-csrf)
  app.use(cookieParser());

  // Apply CSRF middleware
  const csrfMiddleware = app.get(CsrfMiddleware);
  app.use((req, res, next) => csrfMiddleware.use(req, res, next));

  // Set global prefix
  app.setGlobalPrefix('api', {
    exclude: [
      { path: '', method: RequestMethod.ALL }, // Exclude root path
      { path: 'files/(.*)', method: RequestMethod.ALL },
      { path: 's/(.*)', method: RequestMethod.ALL },
    ],
  });

  // Get config service
  const configService = app.get(ConfigService);

  // Global pipes
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: {
        enableImplicitConversion: true,
      },
    }),
  );

  // Global filters
  app.useGlobalFilters(new HttpExceptionFilter());

  // Global interceptors
  app.useGlobalInterceptors(
    new LoggingInterceptor(configService),
    new ResponseInterceptor(),
  );

  // CORS
  const urlConfigService = new UrlConfigService(configService);
  const corsOrigins = urlConfigService.getCorsOrigins();

  app.enableCors({
    origin: corsOrigins,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Requested-With',
      'X-API-Key',
    ],
  });

  // Swagger Setup (Inline)
  const swaggerEnabled = configService.get<string>('SWAGGER_ENABLED', 'false');
  if (swaggerEnabled === 'true') {
    const baseUrl = urlConfigService.getBaseUrl();
    const configBuilder = createSwaggerConfig(baseUrl);

    // Add tags
    SWAGGER_CONFIG.tags.forEach((tag) => {
      configBuilder.addTag(tag.name, tag.description);
    });

    const document = SwaggerModule.createDocument(app, configBuilder.build());

    // Add tag groups
    if (SWAGGER_CONFIG['x-tagGroups']) {
      document['x-tagGroups'] = SWAGGER_CONFIG['x-tagGroups'];
    }

    const swaggerDocsUrl = urlConfigService.getSwaggerUrl();
    const googleClientId = configService.get('GOOGLE_CLIENT_ID');
    const githubClientId = configService.get('GITHUB_CLIENT_ID');

    // Define tag order
    const tagOrder = SWAGGER_CONFIG.tags.map((tag) => tag.name);

    SwaggerModule.setup('api/docs', app, document, {
      swaggerOptions: {
        persistAuthorization: true,
        tagsSorter: 'alpha',
        operationsSorter: 'alpha',
        security: [
          { 'access-token': [] },
          { 'refresh-token': [] },
        ],
        oauth: {
          clientId: googleClientId,
          redirectUrl: urlConfigService.getOAuthCallbackUrl('google'),
          usePkceWithAuthorizationCodeGrant: true,
          scopes: ['openid', 'email', 'profile'],
        },
        // valid redirect URL for OAuth2
        oauth2RedirectUrl: `${swaggerDocsUrl}/oauth2-redirect.html`,
        initOAuth: {
          clientId: githubClientId || googleClientId,
          usePkceWithAuthorizationCodeGrant: true,
        },
      },
      customSiteTitle: SWAGGER_CONFIG.title,
    });

    logger.log(`✅ Swagger is available at ${swaggerDocsUrl}`);
  }

  const port = configService.get('port', 4000);
  await app.listen(port);

  const appLogger = app.get(LoggerService);
  appLogger.info(
    `🚀 Application is running on: http://localhost:${port}`,
    'Application',
  );
  if (swaggerEnabled === 'true') {
    appLogger.info(
      `🚀 Swagger is running on: http://localhost:${port}/api/docs`,
      'Application',
    );
  }
}

bootstrap();