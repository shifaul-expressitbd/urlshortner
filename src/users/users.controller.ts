// src/users/users.controller.ts
import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import type { Request } from 'express';
import { AccessTokenGuard } from '../common/guards/access-token.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { User } from '../common/decorators/user.decorator';
import { ImpersonationGuard } from '../common/guards/impersonation.guard';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { UserResponseDto } from './dto/user-response.dto';

interface ApiResponseType<T = any> {
  success: boolean;
  message: string;
  data?: T;
}

@ApiTags('Users')
@ApiBearerAuth('access-token')
@UseGuards(AccessTokenGuard, RolesGuard)
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  private createSuccessResponse<T>(message: string, data?: T): ApiResponseType<T> {
    return { success: true, message, data };
  }

  @Post()
  @Roles('SYSTEM_ADMIN')
  @ApiOperation({ summary: 'Create a new user (Admin only)' })
  @ApiResponse({ status: 201, description: 'User created', type: UserResponseDto })
  async create(
    @Body() createUserDto: CreateUserDto,
  ) {
    const user = await this.usersService.create(createUserDto);
    const { password, verificationToken, twoFactorSecret, ...userData } = user;
    return this.createSuccessResponse('User created successfully', userData);
  }

  @Get()
  @Roles('SYSTEM_ADMIN')
  @ApiOperation({ summary: 'List all users (Admin only)' })
  @ApiResponse({ status: 200, description: 'List of users', type: [UserResponseDto] })
  async findAll() {
    const users = await this.usersService.findAll();
    return this.createSuccessResponse('Users retrieved successfully', users);
  }

  @Get('profile')
  @UseGuards(ImpersonationGuard)
  @ApiOperation({ summary: 'Get current user profile' })
  @ApiResponse({ status: 200, description: 'Profile retrieved' })
  async getProfile(
    @User() user: any,
    @Req() request: Request,
  ): Promise<ApiResponseType> {
    let targetUserId: string | null = null;

    const impersonateHeader =
      request.headers['x-impersonate-user'] ||
      request.headers['X-Impersonate-User'];

    if (impersonateHeader) {
      targetUserId = Array.isArray(impersonateHeader)
        ? impersonateHeader[0]
        : impersonateHeader;
    }

    const userIdToQuery = targetUserId || user.id;
    const userData = await this.usersService.findById(userIdToQuery);

    if (!userData) {
      throw new BadRequestException('User not found');
    }

    const {
      password,
      verificationToken,
      twoFactorSecret,
      ...profile
    } = userData;

    const responseData: any = {
      ...profile,
      isImpersonation: !!targetUserId,
    };

    if (targetUserId) {
      responseData.impersonatedBy = {
        id: user.id,
        email: user.email,
      };
    }

    return this.createSuccessResponse('Profile retrieved successfully', responseData);
  }

  @Get(':id')
  @Roles('SYSTEM_ADMIN', 'TENANT_OWNER', 'TENANT_MEMBER')
  @ApiOperation({ summary: 'Get user by ID' })
  @ApiResponse({ status: 200, description: 'User details', type: UserResponseDto })
  async findOne(@Param('id') id: string) {
    const user = await this.usersService.findById(id);
    if (!user) {
      throw new BadRequestException('User not found');
    }
    const { password, verificationToken, twoFactorSecret, ...userData } = user;
    return this.createSuccessResponse('User retrieved successfully', userData);
  }

  @Patch(':id')
  @Roles('SYSTEM_ADMIN', 'TENANT_OWNER')
  @ApiOperation({ summary: 'Update user' })
  @ApiResponse({ status: 200, description: 'User updated', type: UserResponseDto })
  async update(
    @Param('id') id: string,
    @Body() updateUserDto: UpdateUserDto,
  ) {
    const user = await this.usersService.update(id, updateUserDto as any);
    return this.createSuccessResponse('User updated successfully', user);
  }

  @Delete(':id')
  @Roles('SYSTEM_ADMIN', 'TENANT_OWNER')
  @ApiOperation({ summary: 'Soft delete user' })
  @ApiResponse({ status: 200, description: 'User deleted' })
  async remove(@Param('id') id: string) {
    await this.usersService.softDelete(id);
    return this.createSuccessResponse('User deleted successfully');
  }
}
