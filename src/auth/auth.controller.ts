import { Body, Controller, Post, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';

import { AuthService } from '@/auth/auth.service';
import { AuthCredentialsDto, ChangeEmailDto, ChangePasswordDto, RefreshTokenDto } from '@/auth/dto/auth.dto';
import { JwtGuard } from '@/auth/jwt.guard';
import { CurrentUser } from '@/auth/decorators/current-user.decorator';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @ApiOperation({ summary: 'Register a new user' })
  @ApiResponse({ status: 201, description: 'User registered successfully' })
  @ApiResponse({ status: 409, description: 'Email already exists' })
  register(@Body() dto: AuthCredentialsDto) {
    return this.authService.register(dto.email, dto.password);
  }

  @Post('login')
  @ApiOperation({ summary: 'Login with email and password' })
  @ApiResponse({ status: 201, description: 'Login successful' })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  login(@Body() dto: AuthCredentialsDto) {
    return this.authService.login(dto.email, dto.password);
  }

  @Post('refresh')
  @ApiOperation({ summary: 'Refresh access token' })
  @ApiResponse({ status: 201, description: 'New tokens issued' })
  @ApiResponse({ status: 401, description: 'Invalid or expired refresh token' })
  refresh(@Body() dto: RefreshTokenDto) {
    return this.authService.refresh(dto.refreshToken);
  }

  @Post('logout')
  @ApiOperation({ summary: 'Logout (revoke single refresh token)' })
  @ApiResponse({ status: 201, description: 'Logged out successfully' })
  logout(@Body() dto: RefreshTokenDto) {
    return this.authService.logout(dto.refreshToken);
  }

  @Post('logout-all')
  @UseGuards(JwtGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Logout from all devices' })
  @ApiResponse({ status: 201, description: 'All sessions revoked' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  logoutAll(@CurrentUser('userId') userId: string) {
    return this.authService.logoutAll(userId);
  }

  @Post('change-password')
  @UseGuards(JwtGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Change password' })
  @ApiResponse({ status: 200, description: 'Password changed successfully' })
  @ApiResponse({ status: 401, description: 'Invalid current password' })
  changePassword(@CurrentUser('userId') userId: string, @Body() dto: ChangePasswordDto) {
    return this.authService.changePassword(userId, dto.currentPassword, dto.newPassword);
  }

  @Post('change-email')
  @UseGuards(JwtGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Change email address' })
  @ApiResponse({ status: 200, description: 'Email changed successfully' })
  @ApiResponse({ status: 401, description: 'Invalid password' })
  @ApiResponse({ status: 409, description: 'Email already in use' })
  changeEmail(@CurrentUser('userId') userId: string, @Body() dto: ChangeEmailDto) {
    return this.authService.changeEmail(userId, dto.newEmail, dto.password);
  }
}
