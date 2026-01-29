import * as argon2 from 'argon2';
import { createHash, randomBytes } from 'crypto';

export const hashPassword = (plain: string) => argon2.hash(plain);
export const verifyPassword = (hash: string, plain: string) => argon2.verify(hash, plain);

// refresh tokenのhash
export const hashToken = (token: string) =>
  createHash('sha256').update(token).digest('hex');

export const generateRefreshToken = () => randomBytes(48).toString('base64url');
