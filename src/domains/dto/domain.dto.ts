import {
  IsString,
  IsOptional,
  IsBoolean,
  IsEnum,
  MaxLength,
  Matches,
} from 'class-validator';

export enum RedirectTypeDto {
  PERMANENT = 'PERMANENT',
  TEMPORARY = 'TEMPORARY',
}

export class CreateDomainDto {
  @IsString()
  @MaxLength(255)
  @Matches(/^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]\.[a-zA-Z]{2,}$/, {
    message: 'Please provide a valid domain name',
  })
  domain: string;

  @IsOptional()
  @IsEnum(RedirectTypeDto)
  redirectType?: RedirectTypeDto;
}

export class UpdateDomainDto {
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;

  @IsOptional()
  @IsEnum(RedirectTypeDto)
  redirectType?: RedirectTypeDto;
}
