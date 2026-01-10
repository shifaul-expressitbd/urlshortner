import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Param,
  Body,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiBody } from '@nestjs/swagger';
import { DomainsService } from './domains.service';
import { CreateDomainDto, UpdateDomainDto, RedirectTypeDto } from './dto/domain.dto';
import { JwtAuthGuard } from '../auth/common/guards/jwt-auth.guard';
import { User } from '../common/decorators/user.decorator';
import { RedirectType } from 'prisma/generated/client';

@ApiTags('Custom Domains')
@Controller('domains')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth('access-token')
export class DomainsController {
  constructor(private readonly domainsService: DomainsService) {}

  /**
   * Add a new custom domain
   */
  @Post()
  @ApiOperation({ summary: 'Add domain', description: 'Register a new custom domain for shortening.' })
  @ApiResponse({
    status: 201,
    description: 'Domain created',
    schema: { example: { id: 'dom_123', domain: 'links.example.com', status: 'PENDING' } },
  })
  async create(
    @Body() dto: CreateDomainDto,
    @User() user: any,
  ) {
    const redirectType = dto.redirectType === RedirectTypeDto.PERMANENT
      ? RedirectType.PERMANENT
      : RedirectType.TEMPORARY;
    return this.domainsService.create(dto.domain, user.id, redirectType);
  }

  /**
   * List user's domains
   */
  @Get()
  @ApiOperation({ summary: 'List domains', description: 'Get all custom domains owned by the user.' })
  @ApiResponse({
    status: 200,
    description: 'List of domains',
    schema: { example: [{ id: 'dom_123', domain: 'links.example.com', verified: false }] },
  })
  async findAll(@User() user: any) {
    return this.domainsService.findAll(user.id);
  }

  /**
   * Get a specific domain
   */
  @Get(':id')
  async findOne(
    @Param('id') id: string,
    @User() user: any,
  ) {
    return this.domainsService.findOne(id, user.id);
  }

  /**
   * Get verification instructions
   */
  @Get(':id/verify')
  async getVerificationInstructions(
    @Param('id') id: string,
    @User() user: any,
  ) {
    return this.domainsService.getVerificationInstructions(id, user.id);
  }

  /**
   * Trigger domain verification
   */
  @Post(':id/verify')
  async verifyDomain(
    @Param('id') id: string,
    @User() user: any,
  ) {
    return this.domainsService.verifyDomain(id, user.id);
  }

  /**
   * Update domain settings
   */
  @Patch(':id')
  async update(
    @Param('id') id: string,
    @Body() dto: UpdateDomainDto,
    @User() user: any,
  ) {
    const updateData: any = {};
    if (dto.isActive !== undefined) updateData.isActive = dto.isActive;
    if (dto.redirectType) {
      updateData.redirectType = dto.redirectType === RedirectTypeDto.PERMANENT
        ? RedirectType.PERMANENT
        : RedirectType.TEMPORARY;
    }
    return this.domainsService.update(id, user.id, updateData);
  }

  /**
   * Delete a domain
   */
  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  async remove(
    @Param('id') id: string,
    @User() user: any,
  ) {
    return this.domainsService.remove(id, user.id);
  }
}
