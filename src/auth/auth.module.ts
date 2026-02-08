import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';

import { PrismaModule } from '@/prisma/prisma.module';
import { UsersModule } from '@/users/users.module';
import { AUTH_CONFIG } from '@/auth/auth.config';
import { JwtGuard } from '@/auth/jwt.guard';
import { AuthService } from '@/auth/auth.service';
import { AuthController } from '@/auth/auth.controller';
import { JwtStrategy } from '@/auth/jwt.strategy';

@Module({
  imports: [
    PrismaModule,
    UsersModule,
    JwtModule.register({
      secret: process.env.JWT_SECRET!,
      signOptions: { expiresIn: AUTH_CONFIG.accessTokenExpiresIn },
    }),
  ],
  providers: [AuthService, JwtStrategy, JwtGuard],
  controllers: [AuthController],
  exports: [AuthService, JwtGuard],
})
export class AuthModule {}
