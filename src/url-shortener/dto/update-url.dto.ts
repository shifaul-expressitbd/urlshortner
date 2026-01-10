import { PartialType } from '@nestjs/swagger';
import { CreateUrlDto } from './create-url.dto';
import { IsBoolean, IsOptional } from 'class-validator';

export class UpdateUrlDto extends PartialType(CreateUrlDto) {
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;
}
