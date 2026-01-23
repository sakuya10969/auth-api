import { Body, Controller, Post, Req, UseGuards } from '@nestjs/common';
import type { Request } from 'express';

import { AuthService } from 'src/auth/auth.service';
import { AuthCredentialsDto } from 'src/auth/dto/auth.dto';
import { JwtGuard } from 'src/auth/jwt.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Post('register')
  register(@Body() dto: AuthCredentialsDto) {
    return this.auth.register(dto.email, dto.password);
  }

  @Post('login')
  login(@Body() dto: AuthCredentialsDto) {
    return this.auth.login(dto.email, dto.password);
  }

  // CLI側が refreshToken を body に入れて送る想定
  @Post('refresh')
  refresh(@Body() body: { userId: string; refreshToken: string }) {
    return this.auth.refresh(body.userId, body.refreshToken);
  }

  @UseGuards(JwtGuard)
  @Post('logout')
  logout(@Req() req: Request & { user: { userId: string } }) {
    return this.auth.logout(req.user.userId);
  }
}
