import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Param,
  Body,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { OrganizationService } from './organization.service';
import {
  CreateFolderDto,
  UpdateFolderDto,
  CreateTagDto,
  UpdateTagDto,
} from './dto/organization.dto';
import { JwtAuthGuard } from '../auth/common/guards/jwt-auth.guard';
import { User } from '../common/decorators/user.decorator';

@ApiTags('Folders')
@Controller('folders')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth('access-token')
export class FoldersController {
  constructor(private readonly organizationService: OrganizationService) {}

  @Post()
  @ApiOperation({ summary: 'Create folder', description: 'Create a new folder to organize URLs.' })
  @ApiResponse({
    status: 201,
    description: 'Folder created',
    schema: { example: { id: 'folder_1', name: 'Marketing', color: '#ff0000' } },
  })
  async create(@Body() dto: CreateFolderDto, @User() user: any) {
    return this.organizationService.createFolder(dto, user.id);
  }

  @Get()
  @ApiOperation({ summary: 'List folders', description: 'Get all folders for the user.' })
  @ApiResponse({
    status: 200,
    description: 'List of folders',
    schema: { example: [{ id: 'folder_1', name: 'Marketing', _count: { urls: 5 } }] },
  })
  async findAll(@Query('parentId') parentId: string, @User() user: any) {
    return this.organizationService.getFolders(user.id, parentId);
  }

  @Get('tree')
  @ApiOperation({ summary: 'Get folder tree', description: 'Get folders in a hierarchical tree structure.' })
  @ApiResponse({
    status: 200,
    description: 'Folder tree',
    schema: { example: [{ id: 'f1', name: 'Root', children: [] }] },
  })
  async getTree(@User() user: any) {
    return this.organizationService.getFolderTree(user.id);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get folder details', description: 'Get a specific folder by ID.' })
  @ApiResponse({ status: 200, description: 'Folder details' })
  async findOne(@Param('id') id: string, @User() user: any) {
    return this.organizationService.getFolder(id, user.id);
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Update folder', description: 'Update folder name or color.' })
  @ApiResponse({ status: 200, description: 'Folder updated' })
  async update(
    @Param('id') id: string,
    @Body() dto: UpdateFolderDto,
    @User() user: any,
  ) {
    return this.organizationService.updateFolder(id, dto, user.id);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Delete folder', description: 'Delete a folder.' })
  @ApiResponse({ status: 200, description: 'Folder deleted' })
  async remove(@Param('id') id: string, @User() user: any) {
    return this.organizationService.deleteFolder(id, user.id);
  }
}

@ApiTags('Tags')
@Controller('tags')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth('access-token')
export class TagsController {
  constructor(private readonly organizationService: OrganizationService) {}

  @Post()
  @ApiOperation({ summary: 'Create tag', description: 'Create a new tag.' })
  @ApiResponse({
    status: 201,
    description: 'Tag created',
    schema: { example: { id: 'tag_1', name: 'sale', color: '#00ff00' } },
  })
  async create(@Body() dto: CreateTagDto, @User() user: any) {
    return this.organizationService.createTag(dto, user.id);
  }

  @Get()
  @ApiOperation({ summary: 'List tags', description: 'Get all tags for the user.' })
  @ApiResponse({
    status: 200,
    description: 'List of tags',
    schema: { example: [{ id: 'tag_1', name: 'sale' }] },
  })
  async findAll(@User() user: any) {
    return this.organizationService.getTags(user.id);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get tag', description: 'Get tag details.' })
  @ApiResponse({ status: 200, description: 'Tag details' })
  async findOne(@Param('id') id: string, @User() user: any) {
    return this.organizationService.getTag(id, user.id);
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Update tag', description: 'Update tag name or color.' })
  @ApiResponse({ status: 200, description: 'Tag updated' })
  async update(
    @Param('id') id: string,
    @Body() dto: UpdateTagDto,
    @User() user: any,
  ) {
    return this.organizationService.updateTag(id, dto, user.id);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Delete tag', description: 'Delete a tag.' })
  @ApiResponse({ status: 200, description: 'Tag deleted' })
  async remove(@Param('id') id: string, @User() user: any) {
    return this.organizationService.deleteTag(id, user.id);
  }
}
