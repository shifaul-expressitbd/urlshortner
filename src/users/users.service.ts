import { Injectable, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';

import { LoggerService } from 'src/utils/logger/logger.service';
import { DatabaseService } from 'src/database/database.service';
import { Prisma } from 'prisma/generated/client';

// Define JwtPayload interface locally to avoid circular dependencies
interface JwtPayload {
  sub: string;
  email: string;
  roles?: string[];
  type?: string;
  permissions?: string[];
  iat?: number;
  exp?: number;
  impersonatedBy?: string;
  rememberMe?: boolean;
  impersonatorEmail?: string;
  isImpersonation?: boolean;
}

@Injectable()
export class UsersService {
  constructor(
    private prisma: DatabaseService,
    private jwtService: JwtService,
    private configService: ConfigService,
    private logger: LoggerService,
  ) {}

  async findByEmail(email: string) {
    this.logger.info(`Finding user by email: ${email}`, 'UsersService');
    try {
        const result = await this.prisma.user.findUnique({
          where: { email },
        });
        return result;
    } catch (error) {
        this.logger.error(`Error in findByEmail: ${(error as Error).message}`, 'UsersService', { stack: (error as Error).stack });
        throw error;
    }
  }

  async findById(id: string) {
    return this.prisma.user.findUnique({
      where: { id },
    });
  }

  async findByVerificationToken(token: string) {
    return this.prisma.user.findFirst({
      where: {
        verificationToken: token,
      },
    });
  }

  async markEmailAsVerified(
    userId: string,
  ): Promise<{ user: any; wasAlreadyVerified: boolean }> {
    const user = await this.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const wasAlreadyVerified = user.isEmailVerified;

    if (wasAlreadyVerified) {
      return { user, wasAlreadyVerified: true };
    }

    const updatedUser = await this.prisma.user.update({
      where: { id: userId },
      data: {
        isEmailVerified: true,
        emailVerifiedAt: new Date(),
        verificationToken: null,
      },
    });

    return { user: updatedUser, wasAlreadyVerified: false };
  }

  async create(data: {
    email: string;
    firstName: string;
    lastName: string;
    password?: string;
    avatar?: string | null;
    provider?: string;
    isEmailVerified?: boolean;
    emailVerifiedAt?: Date | null;
    verificationToken?: string | null;
  }) {
    return this.prisma.user.create({
      data: {
        email: data.email,
        firstName: data.firstName,
        lastName: data.lastName,
        password: data.password || null,
        avatar: data.avatar || null,
        isEmailVerified: data.isEmailVerified ?? false,
        emailVerifiedAt: data.emailVerifiedAt || null,
        verificationToken: data.verificationToken || null,
      },
    });
  }

  async update(id: string, data: Prisma.UserUpdateInput) {
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user) throw new NotFoundException('User not found');
    return this.prisma.user.update({ where: { id }, data });
  }

  async delete(id: string) {
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user) throw new NotFoundException('User not found');
    return this.prisma.user.delete({ where: { id } });
  }

  async findAll() {
    return this.prisma.user.findMany({
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        avatar: true,
        isEmailVerified: true,
        emailVerifiedAt: true,
        systemRole: true,
        status: true,
        suspendedAt: true,
        createdAt: true,
        updatedAt: true,
      },
    });
  }

  async resetPassword(userId: string, password: string) {
    return this.prisma.user.update({
      where: { id: userId },
      data: {
        password,
      },
    });
  }

  async changePassword(userId: string, password: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new NotFoundException('User not found');

    return this.prisma.user.update({
      where: { id: userId },
      data: { password },
    });
  }

  async verifyEmailToken(
    token: string,
  ): Promise<{ email: string; user?: any; tokenValid: boolean }> {
    try {
      const jwtSecret = this.configService.get<string>('JWT_SECRET');
      if (!jwtSecret) {
        throw new Error('JWT_SECRET missing');
      }

      const decoded = (await this.jwtService.verifyAsync(token, {
        secret: jwtSecret,
      })) as JwtPayload;

      if (decoded.email && decoded.type === 'verification') {
        const user = await this.findByEmail(decoded.email);

        return {
          email: decoded.email,
          user,
          tokenValid: true,
        };
      }

      throw new Error('Invalid token format');
    } catch (jwtError) {
      this.logger.warn(
        'JWT verification failed, trying legacy token lookup',
        'UsersService',
        {
          error: (jwtError as Error).message,
        },
      );

      const user = await this.prisma.user.findFirst({
        where: {
          verificationToken: token,
        },
      });

      if (user) {
        return {
          email: user.email,
          user,
          tokenValid: true,
        };
      }

      return { email: '', tokenValid: false };
    }
  }

  /**
   * Soft delete a user
   */
  async softDelete(id: string) {
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user) throw new NotFoundException('User not found');

    return this.prisma.user.update({
      where: { id },
      data: { deletedAt: new Date() },
    });
  }
}
