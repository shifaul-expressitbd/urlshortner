import { Module } from '@nestjs/common';
import { AnalyticsService } from './analytics.service';
import { AnalyticsController } from './analytics.controller';
import { DatabaseModule } from '../database/database.module';
import { PublicAnalyticsController } from './public-analytics.controller';
import { UserAnalyticsController } from './user-analytics.controller';

@Module({
  imports: [DatabaseModule],
  controllers: [AnalyticsController, PublicAnalyticsController, UserAnalyticsController],
  providers: [AnalyticsService],
  exports: [AnalyticsService],
})
export class AnalyticsModule {}
