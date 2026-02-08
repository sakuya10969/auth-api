import { Controller, Get, UnauthorizedException, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOkResponse, ApiTags } from '@nestjs/swagger';

import { JwtGuard } from '@/auth/jwt.guard';
import { CurrentUser } from '@/auth/decorators/current-user.decorator';
import { UsersService } from '@/users/users.service';

@ApiTags('me')
@Controller()
export class MeController {
  constructor(private readonly usersService: UsersService) {}

  @UseGuards(JwtGuard)
  @Get('me')
  @ApiBearerAuth()
  @ApiOkResponse({ description: 'Returns current user profile' })
  async me(@CurrentUser('userId') userId: string) {
    const user = await this.usersService.findActiveUserById(userId);
    if (!user) {
      throw new UnauthorizedException('User not found or inactive');
    }
    return user;
  }
}
