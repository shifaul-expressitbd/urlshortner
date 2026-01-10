import { IsString, IsOptional, MaxLength, Matches, IsHexColor } from 'class-validator';

export class CreateFolderDto {
  @IsString()
  @MaxLength(100)
  name: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsHexColor()
  color?: string;

  @IsOptional()
  @IsString()
  parentId?: string;
}

export class UpdateFolderDto {
  @IsOptional()
  @IsString()
  @MaxLength(100)
  name?: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsHexColor()
  color?: string;

  @IsOptional()
  @IsString()
  parentId?: string;
}

export class CreateTagDto {
  @IsString()
  @MaxLength(50)
  @Matches(/^[a-zA-Z0-9_-]+$/, {
    message: 'Tag name can only contain letters, numbers, hyphens, and underscores',
  })
  name: string;

  @IsOptional()
  @IsHexColor()
  color?: string;
}

export class UpdateTagDto {
  @IsOptional()
  @IsString()
  @MaxLength(50)
  @Matches(/^[a-zA-Z0-9_-]+$/, {
    message: 'Tag name can only contain letters, numbers, hyphens, and underscores',
  })
  name?: string;

  @IsOptional()
  @IsHexColor()
  color?: string;
}
