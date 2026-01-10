import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsString,
  IsUrl,
  IsOptional,
  IsInt,
  IsDateString,
  MaxLength,
  MinLength,
  Matches,
  Min,
} from 'class-validator';

export class CreateUrlDto {
  @ApiProperty({
    description: 'The original long URL to shorten',
    example: 'https://www.example.com/blog/2024/comprehensive-guide-to-url-shortening',
  })
  @IsUrl({}, { message: 'Please provide a valid URL' })
  @IsString()
  originalUrl: string;

  @ApiPropertyOptional({
    description: 'Custom alias for the short URL (optional)',
    example: 'summer-sale-2024',
    minLength: 3,
    maxLength: 50,
  })
  @IsOptional()
  @IsString()
  @MinLength(3, { message: 'Custom alias must be at least 3 characters' })
  @MaxLength(50, { message: 'Custom alias must not exceed 50 characters' })
  @Matches(/^[a-zA-Z0-9_-]+$/, {
    message: 'Custom alias can only contain letters, numbers, hyphens, and underscores',
  })
  customAlias?: string;

  @ApiPropertyOptional({
    description: 'A descriptive title for the URL',
    example: 'Summer Sale Landing Page',
  })
  @IsOptional()
  @IsString()
  @MaxLength(255)
  title?: string;

  @ApiPropertyOptional({
    description: 'A brief description associated with the URL',
    example: 'Link to the main landing page for the Q3 summer sale campaign.',
  })
  @IsOptional()
  @IsString()
  description?: string;

  @ApiPropertyOptional({
    description: 'Expiration date/time (ISO 8601)',
    example: '2024-12-31T23:59:59Z',
  })
  @IsOptional()
  @IsDateString()
  expiresAt?: string;

  @ApiPropertyOptional({
    description: 'Maximum number of clicks allowed before the link expires',
    example: 1000,
    minimum: 1,
  })
  @IsOptional()
  @IsInt()
  @Min(1, { message: 'Max clicks must be at least 1' })
  maxClicks?: number;

  @ApiPropertyOptional({
    description: 'Password protection for the link',
    example: 'Secret123!',
    minLength: 4,
  })
  @IsOptional()
  @IsString()
  @MinLength(4, { message: 'Password must be at least 4 characters' })
  password?: string;

  @ApiPropertyOptional({
    description: 'ID of the folder to organize this URL',
    example: 'cuid_folder_123456789',
  })
  @IsOptional()
  @IsString()
  folderId?: string;

  @ApiPropertyOptional({
    description: 'Array of tag IDs to associate with the URL',
    example: ['cuid_tag_1', 'cuid_tag_2'],
  })
  @IsOptional()
  @IsString({ each: true })
  tagIds?: string[];

  @ApiPropertyOptional({
    description: 'ID of the custom domain to use (optional)',
    example: 'cuid_domain_987654321',
  })
  @IsOptional()
  @IsString()
  domainId?: string;
}
