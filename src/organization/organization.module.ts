import { Module } from '@nestjs/common';
import { OrganizationService } from './organization.service';
import { FoldersController, TagsController } from './organization.controller';
import { DatabaseModule } from '../database/database.module';

@Module({
  imports: [DatabaseModule],
  controllers: [FoldersController, TagsController],
  providers: [OrganizationService],
  exports: [OrganizationService],
})
export class OrganizationModule {}
