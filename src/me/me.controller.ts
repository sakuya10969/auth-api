import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import type { Request } from 'express';

import { JwtGuard } from '@/auth/jwt.guard';

@Controller()
export class MeController {
  @UseGuards(JwtGuard)
  @Get('me')
  me(@Req() req: Request & { user: { userId: string } }) {
    return req.user;
  }
}
