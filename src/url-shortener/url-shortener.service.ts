import {
  Injectable,
  NotFoundException,
  ConflictException,
  ForbiddenException,
  BadRequestException,
} from '@nestjs/common';
import { DatabaseService } from '../database/database.service';
import { customAlphabet } from 'nanoid';
import * as bcrypt from 'bcrypt';
import * as QRCode from 'qrcode';
import { ConfigService } from '@nestjs/config';
import { CreateUrlDto, UpdateUrlDto, UrlQueryDto } from './dto';
import { Prisma } from 'prisma/generated/client';

@Injectable()
export class UrlShortenerService {
  private readonly generateShortCode = customAlphabet(
    '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
    8,
  );

  constructor(
    private readonly prisma: DatabaseService,
    private readonly configService: ConfigService,
  ) { }

  /**
   * Create a new shortened URL
   */
  async create(dto: CreateUrlDto, userId?: string) {
    // Check if custom alias is already taken
    if (dto.customAlias) {
      const existing = await this.prisma.shortenedUrl.findFirst({
        where: {
          OR: [
            { customAlias: dto.customAlias },
            { shortCode: dto.customAlias },
          ],
        },
      });
      if (existing) {
        throw new ConflictException('This alias is already taken');
      }
    }

    // Generate unique short code
    let shortCode = this.generateShortCode();
    let attempts = 0;
    while (await this.prisma.shortenedUrl.findUnique({ where: { shortCode } })) {
      shortCode = this.generateShortCode();
      attempts++;
      if (attempts > 10) {
        throw new BadRequestException('Failed to generate unique short code');
      }
    }

    // Hash password if provided
    let hashedPassword: string | undefined;
    if (dto.password) {
      hashedPassword = await bcrypt.hash(dto.password, 10);
    }

    // Create the shortened URL
    const shortenedUrl = await this.prisma.shortenedUrl.create({
      data: {
        shortCode,
        customAlias: dto.customAlias,
        originalUrl: dto.originalUrl,
        title: dto.title,
        description: dto.description,
        expiresAt: dto.expiresAt ? new Date(dto.expiresAt) : undefined,
        maxClicks: dto.maxClicks,
        password: hashedPassword,
        userId,
        folderId: dto.folderId,
        domainId: dto.domainId,
        tags: dto.tagIds
          ? { connect: dto.tagIds.map((id) => ({ id })) }
          : undefined,
      },
      include: {
        folder: true,
        tags: true,
        domain: true,
      },
    });

    // Generate QR code
    const fullUrl = this.getFullUrl(shortenedUrl.customAlias || shortenedUrl.shortCode);
    const qrCodeDataUrl = await this.generateQRCode(fullUrl);

    // Update with QR code URL
    await this.prisma.shortenedUrl.update({
      where: { id: shortenedUrl.id },
      data: { qrCodeUrl: qrCodeDataUrl },
    });

    return {
      ...shortenedUrl,
      qrCodeUrl: qrCodeDataUrl,
      shortUrl: fullUrl,
    };
  }

  /**
   * Get URL for redirect (public access)
   * Returns validation status and strict url record for analytics
   */
  async getUrlForRedirect(code: string, passwordAttempt?: string) {
    const urlRecord = await this.prisma.shortenedUrl.findFirst({
      where: {
        OR: [{ shortCode: code }, { customAlias: code }],
        deletedAt: null,
      },
      select: {
        id: true,
        originalUrl: true,
        isActive: true,
        expiresAt: true,
        maxClicks: true,
        totalClicks: true,
        password: true,
        shortCode: true,
        customAlias: true,
        userId: true,
        // Select fields needed for analytics/logging but avoid description/title if large (optional optimization)
      }
    });

    if (!urlRecord) {
      throw new NotFoundException('URL not found');
    }

    // Check if URL is active
    if (!urlRecord.isActive) {
      throw new NotFoundException('URL is inactive');
    }

    // Check expiration
    if (urlRecord.expiresAt && new Date() > urlRecord.expiresAt) {
      throw new NotFoundException('URL has expired');
    }

    // Check max clicks
    if (urlRecord.maxClicks && urlRecord.totalClicks >= urlRecord.maxClicks) {
      throw new NotFoundException('URL has reached maximum clicks');
    }

    // Check password
    if (urlRecord.password) {
      if (!passwordAttempt) {
        throw new ForbiddenException('This URL is password protected');
      }
      const isValidPassword = await bcrypt.compare(passwordAttempt, urlRecord.password);
      if (!isValidPassword) {
        throw new ForbiddenException('Invalid password');
      }
    }

    return urlRecord;
  }

  /**
   * Increment click count (called after successful redirect)
   */
  async incrementClickCount(code: string): Promise<void> {
    await this.prisma.shortenedUrl.updateMany({
      where: {
        OR: [{ shortCode: code }, { customAlias: code }],
      },
      data: {
        totalClicks: { increment: 1 },
        lastClickAt: new Date(),
      },
    });
  }

  /**
   * Get URL by ID (owner access)
   */
  async findOne(id: string, userId?: string) {
    const url = await this.prisma.shortenedUrl.findUnique({
      where: { id },
      include: {
        folder: true,
        tags: true,
        domain: true,
        _count: { select: { clicks: true } },
      },
    });

    if (!url || url.deletedAt) {
      throw new NotFoundException('URL not found');
    }

    // Check ownership if userId provided
    if (userId && url.userId && url.userId !== userId) {
      throw new ForbiddenException('You do not have access to this URL');
    }

    return {
      ...url,
      shortUrl: this.getFullUrl(url.customAlias || url.shortCode, url.domain?.domain),
      hasPassword: !!url.password,
      password: undefined, // Never expose password hash
    };
  }

  /**
   * List URLs with filtering and pagination
   */
  async findAll(query: UrlQueryDto, userId?: string) {
    const where: Prisma.ShortenedUrlWhereInput = {
      deletedAt: null,
      ...(userId && { userId }),
      ...(query.folderId && { folderId: query.folderId }),
      ...(query.domainId && { domainId: query.domainId }),
      ...(query.isActive !== undefined && { isActive: query.isActive }),
      ...(query.hasPassword !== undefined && {
        password: query.hasPassword ? { not: null } : null,
      }),
      ...(query.createdAfter && { createdAt: { gte: new Date(query.createdAfter) } }),
      ...(query.createdBefore && { createdAt: { lte: new Date(query.createdBefore) } }),
      ...(query.tagIds?.length && {
        tags: { some: { id: { in: query.tagIds } } },
      }),
      ...(query.search && {
        OR: [
          { title: { contains: query.search, mode: 'insensitive' } },
          { originalUrl: { contains: query.search, mode: 'insensitive' } },
          { shortCode: { contains: query.search, mode: 'insensitive' } },
          { customAlias: { contains: query.search, mode: 'insensitive' } },
        ],
      }),
    };

    const [items, total] = await Promise.all([
      this.prisma.shortenedUrl.findMany({
        where,
        include: {
          folder: true,
          tags: true,
          domain: true,
        },
        orderBy: { [query.sortBy || 'createdAt']: query.sortOrder || 'desc' },
        skip: ((query.page || 1) - 1) * (query.limit || 20),
        take: query.limit || 20,
      }),
      this.prisma.shortenedUrl.count({ where }),
    ]);

    const page = query.page || 1;
    const limit = query.limit || 20;

    return {
      items: items.map((url) => ({
        ...url,
        shortUrl: this.getFullUrl(url.customAlias || url.shortCode, url.domain?.domain),
        hasPassword: !!url.password,
        password: undefined,
      })),
      meta: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
        hasNextPage: page * limit < total,
        hasPrevPage: page > 1,
      },
    };
  }

  /**
   * Update a URL
   */
  async update(id: string, dto: UpdateUrlDto, userId?: string) {
    const existing = await this.findOne(id, userId);

    // Check if new custom alias conflicts
    if (dto.customAlias && dto.customAlias !== existing.customAlias) {
      const conflict = await this.prisma.shortenedUrl.findFirst({
        where: {
          OR: [
            { customAlias: dto.customAlias },
            { shortCode: dto.customAlias },
          ],
          id: { not: id },
        },
      });
      if (conflict) {
        throw new ConflictException('This alias is already taken');
      }
    }

    // Hash new password if provided
    let hashedPassword: string | undefined;
    if (dto.password) {
      hashedPassword = await bcrypt.hash(dto.password, 10);
    }

    const updated = await this.prisma.shortenedUrl.update({
      where: { id },
      data: {
        ...(dto.originalUrl && { originalUrl: dto.originalUrl }),
        ...(dto.customAlias !== undefined && { customAlias: dto.customAlias || null }),
        ...(dto.title !== undefined && { title: dto.title }),
        ...(dto.description !== undefined && { description: dto.description }),
        ...(dto.expiresAt !== undefined && {
          expiresAt: dto.expiresAt ? new Date(dto.expiresAt) : null,
        }),
        ...(dto.maxClicks !== undefined && { maxClicks: dto.maxClicks }),
        ...(dto.isActive !== undefined && { isActive: dto.isActive }),
        ...(hashedPassword && { password: hashedPassword }),
        ...(dto.folderId !== undefined && { folderId: dto.folderId || null }),
        ...(dto.domainId !== undefined && { domainId: dto.domainId || null }),
        ...(dto.tagIds && {
          tags: { set: dto.tagIds.map((tagId) => ({ id: tagId })) },
        }),
      },
      include: {
        folder: true,
        tags: true,
        domain: true,
      },
    });

    // Regenerate QR code if alias changed
    if (dto.customAlias !== undefined && dto.customAlias !== existing.customAlias) {
      const fullUrl = this.getFullUrl(updated.customAlias || updated.shortCode, updated.domain?.domain);
      const qrCodeDataUrl = await this.generateQRCode(fullUrl);
      await this.prisma.shortenedUrl.update({
        where: { id },
        data: { qrCodeUrl: qrCodeDataUrl },
      });
      updated.qrCodeUrl = qrCodeDataUrl;
    }

    return {
      ...updated,
      shortUrl: this.getFullUrl(updated.customAlias || updated.shortCode, updated.domain?.domain),
      hasPassword: !!updated.password,
      password: undefined,
    };
  }

  /**
   * Soft delete a URL
   */
  async remove(id: string, userId?: string) {
    await this.findOne(id, userId); // Verify access

    await this.prisma.shortenedUrl.update({
      where: { id },
      data: { deletedAt: new Date() },
    });

    return { success: true, message: 'URL deleted successfully' };
  }

  /**
   * Check if a URL requires password
   */
  async checkPasswordRequired(code: string): Promise<{ requiresPassword: boolean }> {
    const url = await this.prisma.shortenedUrl.findFirst({
      where: {
        OR: [{ shortCode: code }, { customAlias: code }],
        deletedAt: null,
      },
      select: { password: true },
    });

    if (!url) {
      throw new NotFoundException('URL not found');
    }

    return { requiresPassword: !!url.password };
  }

  /**
   * Get URL details by code (internal use)
   */
  async getUrlDetailsByCode(code: string) {
    return this.prisma.shortenedUrl.findFirst({
      where: {
        OR: [{ shortCode: code }, { customAlias: code }],
        deletedAt: null,
      },
    });
  }

  /**
   * Get full short URL
   */
  private getFullUrl(code: string, customDomain?: string): string {
    const baseUrl = customDomain
      ? `https://${customDomain}`
      : this.configService.get<string>('backend.url') || 'http://localhost:4000';
    return `${baseUrl}/s/${code}`;
  }

  /**
   * Generate QR code for URL
   */
  private async generateQRCode(url: string): Promise<string> {
    return QRCode.toDataURL(url, {
      width: 300,
      margin: 2,
      color: {
        dark: '#000000',
        light: '#ffffff',
      },
    });
  }
}
