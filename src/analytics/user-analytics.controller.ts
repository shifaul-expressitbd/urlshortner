import {
  Controller,
  Get,
  Query,
  UseGuards,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { AnalyticsService } from './analytics.service';
import { JwtAuthGuard } from '../auth/common/guards/jwt-auth.guard';
import { User } from '../common/decorators/user.decorator';

@ApiTags('User Analytics')
@Controller('analytics')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth('access-token')
export class UserAnalyticsController {
  constructor(
    private readonly analyticsService: AnalyticsService,
  ) {}

  @Get('dashboard')
  @ApiOperation({ summary: 'Get user analytics dashboard summary' })
  async getDashboardSummary(
    @User() user: any,
    @Query('days') days: string = '30',
  ) {
    return this.analyticsService.getUserAnalyticsSummary(user.id, parseInt(days, 10));
  }

  @Get('timeseries')
  @ApiOperation({ summary: 'Get user aggregated clicks timeseries' })
  async getTimeseries(
    @User() user: any,
    @Query('days') days: string = '30',
  ) {
    return this.analyticsService.getUserClicksTimeseries(user.id, parseInt(days, 10));
  }

  @Get('devices')
  @ApiOperation({ summary: 'Get user aggregated device breakdown' })
  async getDevices(@User() user: any) {
    return this.analyticsService.getUserDeviceBreakdown(user.id);
  }

  @Get('locations')
  @ApiOperation({ summary: 'Get user aggregated location breakdown' })
  async getLocations(
    @User() user: any,
    @Query('limit') limit: string = '10',
  ) {
    return this.analyticsService.getUserLocationBreakdown(user.id, parseInt(limit, 10));
  }

  @Get('top-links')
  @ApiOperation({ summary: 'Get users top performing links' })
  async getTopLinks(
    @User() user: any,
    @Query('limit') limit: string = '5',
  ) {
    return this.analyticsService.getUserTopLinks(user.id, parseInt(limit, 10));
  }
}
