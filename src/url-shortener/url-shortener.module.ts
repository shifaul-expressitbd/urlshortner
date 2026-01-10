import { Module } from '@nestjs/common';
import { UrlShortenerService } from './url-shortener.service';
import { RedirectController, UrlApiController } from './url-shortener.controller';
import { DatabaseModule } from '../database/database.module';
import { AnalyticsModule } from '../analytics/analytics.module';

@Module({
  imports: [DatabaseModule, AnalyticsModule],
  controllers: [RedirectController, UrlApiController],
  providers: [UrlShortenerService],
  exports: [UrlShortenerService],
})
export class UrlShortenerModule {}
