import {
  Injectable,
  UnauthorizedException,
  ConflictException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

import { UsersService } from 'src/users/users.service';

type Tokens = { accessToken: string; refreshToken: string };

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
  ) {}

  private signTokens(userId: string, email: string): Tokens {
    const accessToken = this.jwtService.sign(
      { sub: userId, email },
      { expiresIn: '15m' },
    );
    const refreshToken = this.jwtService.sign(
      { sub: userId, email },
      { expiresIn: '14d' },
    );
    return { accessToken, refreshToken };
  }

  private async hash(text: string) {
    const saltRounds = 12;
    return bcrypt.hash(text, saltRounds);
  }

  async register(email: string, password: string): Promise<Tokens> {
    const exists = await this.usersService.findByEmail(email);
    if (exists) throw new ConflictException('Email already used');

    const passwordHash = await this.hash(password);
    const user = await this.usersService.createUser(email, passwordHash);

    const tokens = this.signTokens(user.id, user.email);
    const refreshTokenHash = await this.hash(tokens.refreshToken);
    await this.usersService.setRefreshTokenHash(user.id, refreshTokenHash);

    return tokens;
  }

  async login(email: string, password: string): Promise<Tokens> {
    const user = await this.usersService.findByEmail(email);
    if (!user) throw new UnauthorizedException('Invalid credentials');

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) throw new UnauthorizedException('Invalid credentials');

    const tokens = this.signTokens(user.id, user.email);
    const refreshTokenHash = await this.hash(tokens.refreshToken);
    await this.usersService.setRefreshTokenHash(user.id, refreshTokenHash);

    return tokens;
  }

  async refresh(userId: string, refreshToken: string): Promise<Tokens> {
    const user = await this.usersService.findById(userId);
    if (!user?.refreshTokenHash) throw new UnauthorizedException('No refresh token');

    const ok = await bcrypt.compare(refreshToken, user.refreshTokenHash);
    if (!ok) throw new UnauthorizedException('Invalid refresh token');

    const tokens = this.signTokens(user.id, user.email);
    // ローテーション
    const refreshTokenHash = await this.hash(tokens.refreshToken);
    await this.usersService.setRefreshTokenHash(user.id, refreshTokenHash);

    return tokens;
  }

  async logout(userId: string) {
    await this.usersService.setRefreshTokenHash(userId, null);
    return { ok: true };
  }
}
