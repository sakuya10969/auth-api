import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class AuthCredentialsDto {
  @ApiProperty({ example: 'user@example.com' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'password123', minLength: 8 })
  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters' })
  password: string;
}

export class RefreshTokenDto {
  @ApiProperty({ description: 'Refresh token from login or register' })
  @IsString()
  @IsNotEmpty()
  refreshToken: string;
}

export class ChangePasswordDto {
  @ApiProperty({ description: 'Current password' })
  @IsString()
  @MinLength(8)
  currentPassword: string;

  @ApiProperty({ description: 'New password', minLength: 8 })
  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters' })
  newPassword: string;
}

export class ChangeEmailDto {
  @ApiProperty({ example: 'newemail@example.com' })
  @IsEmail()
  newEmail: string;

  @ApiProperty({ description: 'Current password for verification' })
  @IsString()
  @MinLength(8)
  password: string;
}
