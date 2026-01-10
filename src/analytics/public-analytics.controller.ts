import {
  Controller,
  Get,
  Param,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiParam } from '@nestjs/swagger';
import { AnalyticsService } from './analytics.service';
import { DatabaseService } from '../database/database.service';
import { Public } from '../common/decorators/public.decorator';

@ApiTags('Analytics')
@Controller('analytics/public')
export class PublicAnalyticsController {
  constructor(
    private readonly analyticsService: AnalyticsService,
    private readonly prisma: DatabaseService,
  ) {}

  @Public()
  @Get(':code')
  @ApiOperation({ 
    summary: 'Get public analytics for a short code', 
    description: 'Get basic stats for a short link. Only available for anonymous links (links with no owner).' 
  })
  @ApiParam({ name: 'code', description: 'The short code of the URL' })
  @ApiResponse({
    status: 200,
    description: 'Analytics summary retrieved',
  })
  async getPublicSummary(@Param('code') code: string) {
    // 1. Find URL by code
    const url = await this.prisma.shortenedUrl.findUnique({
      where: { shortCode: code },
      select: { id: true, userId: true },
    });

    if (!url) {
      throw new NotFoundException('URL not found');
    }

    // 2. Security Check: Only allow if userId is NULL
    if (url.userId) {
      throw new ForbiddenException('Analytics for this URL are private');
    }

    // 3. Return Summary
    return this.analyticsService.getAnalyticsSummary(url.id, 30);
  }
}
