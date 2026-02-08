import { Injectable, UnauthorizedException, ForbiddenException, ConflictException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

import { PrismaService } from '@/prisma/prisma.service';
import { AUTH_CONFIG } from '@/auth/auth.config';
import { generateRefreshToken, hashPassword, hashToken, verifyPassword } from '@/auth/crypto';

@Injectable()
export class AuthService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  private createAccessToken(userId: string) {
    return this.jwtService.sign(
      { sub: userId },
      { expiresIn: AUTH_CONFIG.accessTokenExpiresIn },
    );
  }

  private createRefreshExpiresAt() {
    const d = new Date();
    d.setDate(d.getDate() + AUTH_CONFIG.refreshTokenExpiresDays);
    return d;
  }

  async register(email: string, password: string) {
    // すでに存在したら弾く
    const exists = await this.prismaService.user.findUnique({ where: { email } });
    if (exists) throw new ConflictException('Email already exists');
  
    const passwordHash = await hashPassword(password);
  
    const user = await this.prismaService.user.create({
      data: {
        email,
        passwordHash,
      },
      select: { id: true, email: true, isActive: true },
    });
  
    const accessToken = this.createAccessToken(user.id);
  
    const refreshPlain = generateRefreshToken();
    const refreshHash = hashToken(refreshPlain);
  
    await this.prismaService.refreshToken.create({
      data: {
        userId: user.id,
        tokenHash: refreshHash,
        expiresAt: this.createRefreshExpiresAt(),
      },
    });
  
    return { user, accessToken, refreshToken: refreshPlain };
  }

  async login(email: string, password: string) {
    const user = await this.prismaService.user.findUnique({ where: { email } });
    if (!user || !user.isActive) throw new UnauthorizedException('Invalid credentials');

    const ok = await verifyPassword(user.passwordHash, password);
    if (!ok) throw new UnauthorizedException('Invalid credentials');

    const accessToken = this.createAccessToken(user.id);

    const refreshPlain = generateRefreshToken();
    const refreshHash = hashToken(refreshPlain);

    await this.prismaService.refreshToken.create({
      data: {
        userId: user.id,
        tokenHash: refreshHash,
        expiresAt: this.createRefreshExpiresAt(),
      },
    });

    return { accessToken, refreshToken: refreshPlain };
  }

  // refresh tokenローテーション：古いのをrevokeして新しいのを発行
  async refresh(refreshTokenPlain: string) {
    const now = new Date();
    const tokenHash = hashToken(refreshTokenPlain);

    const stored = await this.prismaService.refreshToken.findUnique({
      where: { tokenHash },
      include: { user: true },
    });

    if (!stored) throw new UnauthorizedException('Invalid refresh token');
    if (stored.revokedAt) throw new UnauthorizedException('Refresh token revoked');
    if (stored.expiresAt <= now) throw new UnauthorizedException('Refresh token expired');
    if (!stored.user.isActive) throw new ForbiddenException('User is inactive');

    const newAccess = this.createAccessToken(stored.userId);

    const newRefreshPlain = generateRefreshToken();
    const newRefreshHash = hashToken(newRefreshPlain);

    await this.prismaService.$transaction([
      this.prismaService.refreshToken.update({
        where: { id: stored.id },
        data: { revokedAt: now },
      }),
      this.prismaService.refreshToken.create({
        data: {
          userId: stored.userId,
          tokenHash: newRefreshHash,
          expiresAt: this.createRefreshExpiresAt(),
        },
      }),
    ]);

    return { accessToken: newAccess, refreshToken: newRefreshPlain };
  }

  // refresh token一本ログアウト
  async logout(refreshTokenPlain: string) {
    const tokenHash = hashToken(refreshTokenPlain);
    await this.prismaService.refreshToken.updateMany({
      where: { tokenHash, revokedAt: null },
      data: { revokedAt: new Date() },
    });
  }

  async logoutAll(userId: string) {
    await this.prismaService.refreshToken.updateMany({
      where: { userId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
  }

  async changePassword(userId: string, currentPassword: string, newPassword: string) {
    const user = await this.prismaService.user.findUnique({ where: { id: userId } });
    if (!user || !user.isActive) throw new UnauthorizedException('Invalid credentials');

    const ok = await verifyPassword(user.passwordHash, currentPassword);
    if (!ok) throw new UnauthorizedException('Invalid current password');

    const passwordHash = await hashPassword(newPassword);
    await this.prismaService.user.update({
      where: { id: userId },
      data: { passwordHash },
    });
  }

  async changeEmail(userId: string, newEmail: string, password: string) {
    const user = await this.prismaService.user.findUnique({ where: { id: userId } });
    if (!user || !user.isActive) throw new UnauthorizedException('Invalid credentials');

    const ok = await verifyPassword(user.passwordHash, password);
    if (!ok) throw new UnauthorizedException('Invalid password');

    const exists = await this.prismaService.user.findUnique({ where: { email: newEmail } });
    if (exists) throw new ConflictException('Email already in use');

    await this.prismaService.user.update({
      where: { id: userId },
      data: { email: newEmail },
    });
  }
}
