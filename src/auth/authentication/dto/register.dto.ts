import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsString,
  MinLength,
} from 'class-validator';

export class RegisterDto {
  @ApiProperty({
    /* example: 'user@example.com' */
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    /* example: 'John' */
  })
  @IsString()
  @IsNotEmpty()
  firstName: string;

  @ApiProperty({
    /* example: 'Doe' */
  })
  @IsString()
  @IsNotEmpty()
  lastName: string;

  @ApiProperty({ /* example: 'password123', */ minLength: 8 })
  @IsString()
  @MinLength(8)
  password: string;

  @ApiProperty({
    /* example: 'https://example.com/avatar.jpg', */ required: false,
  })
  @IsString()
  @IsOptional()
  avatar?: string;
}
