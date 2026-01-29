import { Injectable, ConflictException, NotFoundException } from '@nestjs/common';

import { PrismaService } from '@/prisma/prisma.service';
import { hashPassword } from '@/auth/crypto';

@Injectable()
export class UsersService {
  constructor(private readonly prismaService: PrismaService) {}

  async createUser(email: string, password: string) {
    // 重複チェック
    const exists = await this.prismaService.user.findUnique({ where: { email } });
    if (exists) throw new ConflictException('Email already exists');

    const passwordHash = await hashPassword(password);

    return this.prismaService.user.create({
      data: { email, passwordHash },
      select: { id: true, email: true, isActive: true, createdAt: true },
    });
  }

  async findActiveUserByEmail(email: string) {
    return this.prismaService.user.findFirst({
      where: { email, isActive: true },
    });
  }

  async findActiveUserById(id: string) {
    return this.prismaService.user.findFirst({
      where: { id, isActive: true },
    });
  }

  async deactivateUser(userId: string) {
    const user = await this.prismaService.user.findUnique({ where: { id: userId } });
    if (!user) throw new NotFoundException('User not found');

    // 無効化 + 全refresh token revoke
    await this.prismaService.$transaction([
      this.prismaService.user.update({
        where: { id: userId },
        data: { isActive: false },
      }),
      this.prismaService.refreshToken.updateMany({
        where: { userId, revokedAt: null },
        data: { revokedAt: new Date() },
      }),
    ]);
  }
}
