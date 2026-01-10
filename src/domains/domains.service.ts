import {
  Injectable,
  ConflictException,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { DatabaseService } from '../database/database.service';
import { DomainStatus, RedirectType } from 'prisma/generated/client';
import { randomBytes } from 'crypto';

@Injectable()
export class DomainsService {
  constructor(private readonly prisma: DatabaseService) {}

  /**
   * Add a new custom domain
   */
  async create(domain: string, userId: string, redirectType: RedirectType = RedirectType.TEMPORARY) {
    // Normalize domain
    const normalizedDomain = domain.toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '').replace(/\/$/, '');

    // Check if domain already exists
    const existing = await this.prisma.customDomain.findUnique({
      where: { domain: normalizedDomain },
    });

    if (existing) {
      throw new ConflictException('This domain is already registered');
    }

    // Generate verification token
    const verificationToken = randomBytes(32).toString('hex');

    return this.prisma.customDomain.create({
      data: {
        domain: normalizedDomain,
        userId,
        redirectType,
        verificationToken,
        verificationStatus: DomainStatus.PENDING,
      },
    });
  }

  /**
   * Get user's domains
   */
  async findAll(userId: string) {
    return this.prisma.customDomain.findMany({
      where: { userId, deletedAt: null },
      include: {
        _count: { select: { urls: true } },
      },
      orderBy: { createdAt: 'desc' },
    });
  }

  /**
   * Get domain by ID
   */
  async findOne(id: string, userId: string) {
    const domain = await this.prisma.customDomain.findUnique({
      where: { id },
      include: {
        _count: { select: { urls: true } },
      },
    });

    if (!domain || domain.deletedAt) {
      throw new NotFoundException('Domain not found');
    }

    if (domain.userId !== userId) {
      throw new ForbiddenException('You do not have access to this domain');
    }

    return domain;
  }

  /**
   * Get verification instructions
   */
  async getVerificationInstructions(id: string, userId: string) {
    const domain = await this.findOne(id, userId);

    return {
      domain: domain.domain,
      status: domain.verificationStatus,
      instructions: {
        method: 'DNS TXT Record',
        recordName: `_urlshortener-verification.${domain.domain}`,
        recordValue: domain.verificationToken,
        alternative: {
          method: 'CNAME Record',
          recordName: domain.domain,
          recordValue: process.env.CNAME_TARGET || 'url.yourdomain.com',
        },
      },
    };
  }

  /**
   * Verify domain ownership
   * In production, this would check DNS records
   */
  async verifyDomain(id: string, userId: string) {
    const domain = await this.findOne(id, userId);

    // TODO: Implement actual DNS verification
    // For now, simulate verification
    // In production: query DNS TXT record and compare with verificationToken

    // Mark as verified (simulated)
    const updated = await this.prisma.customDomain.update({
      where: { id },
      data: {
        verificationStatus: DomainStatus.VERIFIED,
        verifiedAt: new Date(),
        isActive: true,
      },
    });

    return {
      success: true,
      message: 'Domain verified successfully',
      domain: updated,
    };
  }

  /**
   * Update domain settings
   */
  async update(id: string, userId: string, data: { isActive?: boolean; redirectType?: RedirectType }) {
    await this.findOne(id, userId);

    return this.prisma.customDomain.update({
      where: { id },
      data,
    });
  }

  /**
   * Delete a domain
   */
  async remove(id: string, userId: string) {
    const domain = await this.findOne(id, userId);

    // Check if domain has URLs
    const urlCount = await this.prisma.shortenedUrl.count({
      where: { domainId: id, deletedAt: null },
    });

    if (urlCount > 0) {
      // Soft delete and unlink URLs
      await this.prisma.$transaction([
        this.prisma.shortenedUrl.updateMany({
          where: { domainId: id },
          data: { domainId: null },
        }),
        this.prisma.customDomain.update({
          where: { id },
          data: { deletedAt: new Date() },
        }),
      ]);
    } else {
      await this.prisma.customDomain.update({
        where: { id },
        data: { deletedAt: new Date() },
      });
    }

    return { success: true, message: 'Domain deleted successfully' };
  }
}
