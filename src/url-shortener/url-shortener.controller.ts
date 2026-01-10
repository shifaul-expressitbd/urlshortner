import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Param,
  Body,
  Query,
  Res,
  Req,
  HttpStatus,
  HttpCode,
  UseGuards,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiParam, ApiBody } from '@nestjs/swagger';
import type { Response, Request } from 'express';
import { UrlShortenerService } from './url-shortener.service';
import { AnalyticsService } from '../analytics/analytics.service';
import { CreateUrlDto, UpdateUrlDto, UrlQueryDto } from './dto';
import { Public } from '../common/decorators/public.decorator';
import { User } from '../common/decorators/user.decorator';
import { JwtAuthGuard } from '../auth/common/guards/jwt-auth.guard';
import { OptionalAuthGuard } from '../common/guards/optional-auth.guard';

/**
 * Redirect Controller - handles /s/:code redirects
 */
@ApiTags('URL Shortener')
@Controller('s')
export class RedirectController {
  constructor(
    private readonly urlShortenerService: UrlShortenerService,
    private readonly analyticsService: AnalyticsService,
  ) {}

  /**
   * Check if URL requires password
   */
  @Public()
  @Get(':code/check')
  @ApiOperation({ summary: 'Check password protection', description: 'Check if a short code requires a password.' })
  @ApiResponse({
    status: 200,
    description: 'Returns password requirement status',
    schema: { example: { requiresPassword: true } },
  })
  async checkPassword(@Param('code') code: string) {
    return this.urlShortenerService.checkPasswordRequired(code);
  }

  /**
   * Redirect to original URL (GET - for non-password URLs)
   */
  @Public()
  @Get(':code')
  @ApiOperation({ summary: 'Redirect to URL', description: 'Redirects to the original URL. If password is required, redirects to password page.' })
  @ApiResponse({ status: 302, description: 'Redirects to original URL' })
  @ApiResponse({ status: 404, description: 'URL not found' })
  async redirect(
    @Param('code') code: string,
    @Res() res: Response,
    @Req() req: Request,
  ) {
    try {
      // First check if password is required
      // Optimization: We could combine this with the getUrlForRedirect but for now checking separately is fine 
      // OR better: try to get url, and catch Forbidden (password required) to redirect to UI
      // But adhering to current logic:
      const { requiresPassword } = await this.urlShortenerService.checkPasswordRequired(code);
      
      if (requiresPassword) {
        // Redirect to password entry page
        const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:4173';
        return res.redirect(`${frontendUrl}/p/${code}`);
      }

      const url = await this.urlShortenerService.getUrlForRedirect(code);
      
      // Track click asynchronously with detailed analytics
      if (url) {
        this.analyticsService.recordClick(
          {
            urlId: url.id,
            ipAddress: (req.headers['x-forwarded-for'] as string) || req.ip,
            userAgent: req.headers['user-agent'],
            referer: req.headers['referer'],
          },
        ).catch((err) => console.error('Failed to record click:', err));
      }
      
      return res.redirect(HttpStatus.FOUND, url.originalUrl);
    } catch (error) {
       // If standard error, let it propagate (global filter handles it?), 
       // but for redirect we usually want to show a custom 404 page
       const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:4173';
       return res.redirect(`${frontendUrl}/not-found`);
    }
  }

  /**
   * Verify password and redirect (POST - for password-protected URLs)
   */
  @Public()
  @Post(':code/verify')
  @ApiOperation({ summary: 'Verify password', description: 'Verify password for a protected URL and get the redirect URL.' })
  @ApiBody({ schema: { example: { password: 'Secret123!' } } })
  @ApiResponse({
    status: 200,
    description: 'Password verified',
    schema: { example: { success: true, redirectUrl: 'https://example.com' } },
  })
  @ApiResponse({ status: 403, description: 'Invalid password' })
  async verifyPassword(
    @Param('code') code: string,
    @Body('password') password: string,
    @Res() res: Response,
    @Req() req: Request,
  ) {
    try {
      const url = await this.urlShortenerService.getUrlForRedirect(code, password);
      
      // Track click asynchronously
      if (url) {
        this.analyticsService.recordClick({
            urlId: url.id,
            ipAddress: (req.headers['x-forwarded-for'] as string) || req.ip,
            userAgent: req.headers['user-agent'],
            referer: req.headers['referer'],
        }).catch((err) => console.error('Failed to record click:', err));
      }
      
      return res.json({ success: true, redirectUrl: url.originalUrl });
    } catch (error) {
      if (error.status === 403) {
        return res.status(HttpStatus.FORBIDDEN).json({
          success: false,
          message: 'Invalid password',
        });
      }
      return res.status(HttpStatus.NOT_FOUND).json({
        success: false,
        message: 'URL not found',
      });
    }
  }
}

/**
 * API Controller - handles /api/urls CRUD
 */
@ApiTags('URL Shortener')
@Controller('urls')
export class UrlApiController {
  constructor(private readonly urlShortenerService: UrlShortenerService) {}

  /**
   * Create a new shortened URL
   * Authenticated users get ownership, anonymous users get anonymous URLs
   */
  @Post()
  @Public()
  @UseGuards(OptionalAuthGuard)
  @ApiBearerAuth('access-token')
  @ApiOperation({
    summary: 'Create a short URL',
    description: 'Creates a new shortened URL. Anonymous users can create links, but authenticated users gain ownership and advanced features.',
  })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: 'The URL has been successfully shortened.',
    schema: {
      example: {
        id: 'clq1234567890abcdef',
        shortCode: 'summer24',
        shortUrl: 'https://shifaul.dev/s/summer24',
        originalUrl: 'https://www.example.com/very/long/url',
        userId: 'user_123',
        createdAt: '2024-03-20T10:00:00Z',
      },
    },
  })
  async create(
    @Body() createUrlDto: CreateUrlDto,
    @User() user?: any,
  ) {
    return this.urlShortenerService.create(createUrlDto, user?.id);
  }

  /**
   * List user's URLs with filtering and pagination
   */
  @Get()
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @ApiOperation({ summary: 'List URLs', description: 'Get a paginated list of URLs created by the authenticated user.' })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'List of URLs retrieved successfully',
    schema: {
      example: {
        data: [
          {
            id: '1',
            shortCode: 'test',
            originalUrl: 'https://google.com',
            clicks: 5,
            isActive: true,
          },
        ],
        meta: {
          total: 1,
          page: 1,
          limit: 10,
        },
      },
    },
  })
  async findAll(
    @Query() query: UrlQueryDto,
    @User() user: any,
  ) {
    return this.urlShortenerService.findAll(query, user.id);
  }

  /**
   * Get a specific URL by ID
   */
  @Get(':id')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @ApiOperation({ summary: 'Get URL details', description: 'Retrieve detailed information about a specific URL by its ID.' })
  @ApiResponse({
    status: 200,
    description: 'URL details retrieved',
    schema: {
      example: {
        id: 'clq123...',
        originalUrl: 'https://example.com',
        shortCode: 'xyz123',
        clicks: 42,
        createdAt: '2024-01-01T00:00:00Z',
      },
    },
  })
  async findOne(
    @Param('id') id: string,
    @User() user: any,
  ) {
    return this.urlShortenerService.findOne(id, user.id);
  }

  /**
   * Update a URL
   */
  @Patch(':id')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @ApiOperation({ summary: 'Update URL', description: 'Update details of an existing URL (alias, expiration, etc).' })
  @ApiResponse({
    status: 200,
    description: 'URL updated successfully',
  })
  async update(
    @Param('id') id: string,
    @Body() updateUrlDto: UpdateUrlDto,
    @User() user: any,
  ) {
    return this.urlShortenerService.update(id, updateUrlDto, user.id);
  }

  /**
   * Delete a URL (soft delete)
   */
  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @ApiOperation({ summary: 'Delete URL', description: 'Soft delete a URL. It will no longer redirect.' })
  @ApiResponse({ status: 200, description: 'URL deleted successfully' })
  async remove(
    @Param('id') id: string,
    @User() user: any,
  ) {
    return this.urlShortenerService.remove(id, user.id);
  }
}
