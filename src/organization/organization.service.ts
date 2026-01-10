import {
  Injectable,
  ConflictException,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { DatabaseService } from '../database/database.service';
import { CreateFolderDto, UpdateFolderDto, CreateTagDto, UpdateTagDto } from './dto/organization.dto';

@Injectable()
export class OrganizationService {
  constructor(private readonly prisma: DatabaseService) {}

  // ============================================
  // FOLDERS
  // ============================================

  async createFolder(dto: CreateFolderDto, userId: string) {
    // Check for duplicate name in same parent
    const existing = await this.prisma.urlFolder.findFirst({
      where: {
        userId,
        name: dto.name,
        parentId: dto.parentId || null,
      },
    });

    if (existing) {
      throw new ConflictException('A folder with this name already exists');
    }

    return this.prisma.urlFolder.create({
      data: {
        name: dto.name,
        description: dto.description,
        color: dto.color,
        parentId: dto.parentId,
        userId,
      },
      include: {
        _count: { select: { urls: true, children: true } },
      },
    });
  }

  async getFolders(userId: string, parentId?: string) {
    return this.prisma.urlFolder.findMany({
      where: {
        userId,
        parentId: parentId || null,
      },
      include: {
        _count: { select: { urls: true, children: true } },
      },
      orderBy: { name: 'asc' },
    });
  }

  async getFolderTree(userId: string) {
    const folders = await this.prisma.urlFolder.findMany({
      where: { userId },
      include: {
        _count: { select: { urls: true } },
      },
      orderBy: { name: 'asc' },
    });

    // Build tree structure
    const folderMap = new Map();
    const roots: any[] = [];

    folders.forEach((folder) => {
      folderMap.set(folder.id, { ...folder, children: [] });
    });

    folders.forEach((folder) => {
      const node = folderMap.get(folder.id);
      if (folder.parentId && folderMap.has(folder.parentId)) {
        folderMap.get(folder.parentId).children.push(node);
      } else {
        roots.push(node);
      }
    });

    return roots;
  }

  async getFolder(id: string, userId: string) {
    const folder = await this.prisma.urlFolder.findUnique({
      where: { id },
      include: {
        children: true,
        _count: { select: { urls: true, children: true } },
      },
    });

    if (!folder) {
      throw new NotFoundException('Folder not found');
    }

    if (folder.userId !== userId) {
      throw new ForbiddenException('You do not have access to this folder');
    }

    return folder;
  }

  async updateFolder(id: string, dto: UpdateFolderDto, userId: string) {
    await this.getFolder(id, userId);

    // Check for duplicate name if name is being changed
    if (dto.name) {
      const existing = await this.prisma.urlFolder.findFirst({
        where: {
          userId,
          name: dto.name,
          parentId: dto.parentId,
          id: { not: id },
        },
      });

      if (existing) {
        throw new ConflictException('A folder with this name already exists');
      }
    }

    return this.prisma.urlFolder.update({
      where: { id },
      data: dto,
      include: {
        _count: { select: { urls: true, children: true } },
      },
    });
  }

  async deleteFolder(id: string, userId: string) {
    const folder = await this.getFolder(id, userId);

    // Move URLs to no folder
    await this.prisma.shortenedUrl.updateMany({
      where: { folderId: id },
      data: { folderId: null },
    });

    // Move children to parent
    await this.prisma.urlFolder.updateMany({
      where: { parentId: id },
      data: { parentId: folder.parentId },
    });

    await this.prisma.urlFolder.delete({
      where: { id },
    });

    return { success: true, message: 'Folder deleted successfully' };
  }

  // ============================================
  // TAGS
  // ============================================

  async createTag(dto: CreateTagDto, userId: string) {
    const existing = await this.prisma.urlTag.findFirst({
      where: { userId, name: dto.name },
    });

    if (existing) {
      throw new ConflictException('A tag with this name already exists');
    }

    return this.prisma.urlTag.create({
      data: {
        name: dto.name,
        color: dto.color,
        userId,
      },
      include: {
        _count: { select: { urls: true } },
      },
    });
  }

  async getTags(userId: string) {
    return this.prisma.urlTag.findMany({
      where: { userId },
      include: {
        _count: { select: { urls: true } },
      },
      orderBy: { name: 'asc' },
    });
  }

  async getTag(id: string, userId: string) {
    const tag = await this.prisma.urlTag.findUnique({
      where: { id },
      include: {
        _count: { select: { urls: true } },
      },
    });

    if (!tag) {
      throw new NotFoundException('Tag not found');
    }

    if (tag.userId !== userId) {
      throw new ForbiddenException('You do not have access to this tag');
    }

    return tag;
  }

  async updateTag(id: string, dto: UpdateTagDto, userId: string) {
    await this.getTag(id, userId);

    if (dto.name) {
      const existing = await this.prisma.urlTag.findFirst({
        where: {
          userId,
          name: dto.name,
          id: { not: id },
        },
      });

      if (existing) {
        throw new ConflictException('A tag with this name already exists');
      }
    }

    return this.prisma.urlTag.update({
      where: { id },
      data: dto,
      include: {
        _count: { select: { urls: true } },
      },
    });
  }

  async deleteTag(id: string, userId: string) {
    await this.getTag(id, userId);

    // Disconnect tag from all URLs
    await this.prisma.urlTag.update({
      where: { id },
      data: { urls: { set: [] } },
    });

    await this.prisma.urlTag.delete({
      where: { id },
    });

    return { success: true, message: 'Tag deleted successfully' };
  }
}
