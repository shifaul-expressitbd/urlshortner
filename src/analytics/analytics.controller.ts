import {
  Controller,
  Get,
  Param,
  Query,
  UseGuards,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiQuery, ApiParam } from '@nestjs/swagger';
import { AnalyticsService } from './analytics.service';
import { JwtAuthGuard } from '../auth/common/guards/jwt-auth.guard';
import { User } from '../common/decorators/user.decorator';
import { DatabaseService } from '../database/database.service';

@ApiTags('Analytics')
@Controller('urls/:urlId/analytics')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth('access-token')
export class AnalyticsController {
  constructor(
    private readonly analyticsService: AnalyticsService,
    private readonly prisma: DatabaseService,
  ) {}

  /**
   * Verify URL ownership before analytics access
   */
  private async verifyOwnership(urlId: string, userId: string) {
    const url = await this.prisma.shortenedUrl.findUnique({
      where: { id: urlId },
      select: { userId: true },
    });

    if (!url) {
      throw new NotFoundException('URL not found');
    }

    if (url.userId && url.userId !== userId) {
      throw new ForbiddenException('You do not have access to this URL');
    }
  }

  /**
   * Get analytics summary
   */
  @Get()
  @ApiOperation({ summary: 'Get analytics summary', description: 'Get aggregated stats (total clicks, unique clicks, browsers, etc) for a URL.' })
  @ApiResponse({
    status: 200,
    description: 'Analytics summary retrieved',
    schema: {
      example: {
        totalClicks: 1500,
        uniqueClicks: 1200,
        topCountry: 'US',
        topDevice: 'Mobile',
        topBrowser: 'Chrome',
      },
    },
  })
  async getSummary(
    @Param('urlId') urlId: string,
    @Query('days') days: string = '30',
    @User() user: any,
  ) {
    await this.verifyOwnership(urlId, user.id);
    return this.analyticsService.getAnalyticsSummary(urlId, parseInt(days, 10));
  }

  /**
   * Get clicks timeseries
   */
  @Get('timeseries')
  @ApiOperation({ summary: 'Get clicks over time', description: 'Get daily click counts for charts.' })
  @ApiResponse({
    status: 200,
    description: 'Timeseries data retrieved',
    schema: {
      example: [
        { date: '2024-03-01', clicks: 120 },
        { date: '2024-03-02', clicks: 145 },
      ],
    },
  })
  async getTimeseries(
    @Param('urlId') urlId: string,
    @Query('days') days: string = '30',
    @User() user: any,
  ) {
    await this.verifyOwnership(urlId, user.id);
    return this.analyticsService.getClicksTimeseries(urlId, parseInt(days, 10));
  }

  /**
   * Get top referrers
   */
  @Get('referrers')
  async getReferrers(
    @Param('urlId') urlId: string,
    @Query('limit') limit: string = '10',
    @User() user: any,
  ) {
    await this.verifyOwnership(urlId, user.id);
    return this.analyticsService.getTopReferrers(urlId, parseInt(limit, 10));
  }

  /**
   * Get device breakdown
   */
  @Get('devices')
  async getDevices(
    @Param('urlId') urlId: string,
    @User() user: any,
  ) {
    await this.verifyOwnership(urlId, user.id);
    return this.analyticsService.getDeviceBreakdown(urlId);
  }

  /**
   * Get browser breakdown
   */
  @Get('browsers')
  async getBrowsers(
    @Param('urlId') urlId: string,
    @Query('limit') limit: string = '10',
    @User() user: any,
  ) {
    await this.verifyOwnership(urlId, user.id);
    return this.analyticsService.getBrowserBreakdown(urlId, parseInt(limit, 10));
  }

  /**
   * Get geographic breakdown
   */
  @Get('locations')
  async getLocations(
    @Param('urlId') urlId: string,
    @Query('limit') limit: string = '10',
    @User() user: any,
  ) {
    await this.verifyOwnership(urlId, user.id);
    return this.analyticsService.getLocationBreakdown(urlId, parseInt(limit, 10));
  }
}
