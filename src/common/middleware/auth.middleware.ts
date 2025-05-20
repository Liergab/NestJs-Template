import {
  Injectable,
  NestMiddleware,
  UnauthorizedException,
} from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../prisma/prisma.service';
import { JwtPayload } from '../interfaces/jwt-payload.interface';

interface RequestWithCookies extends Request {
  cookies: {
    jwt?: string;
  };
}

@Injectable()
export class AuthMiddleware implements NestMiddleware {
  constructor(
    private jwtService: JwtService,
    private prisma: PrismaService,
  ) {}

  async use(req: RequestWithCookies, res: Response, next: NextFunction) {
    try {
      const token = this.extractToken(req);
      if (!token) {
        throw new UnauthorizedException('No token provided');
      }

      const payload = await this.jwtService.verifyAsync<JwtPayload>(token, {
        secret: process.env.JWT_SECRET || 'secret',
      });

      const user = await this.prisma.user.findUnique({
        where: { id: payload.sub },
      });

      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      // Attach user to request object
      req['user'] = user;
      next();
    } catch {
      throw new UnauthorizedException('Invalid token');
    }
  }

  private extractToken(request: RequestWithCookies): string | undefined {
    // First try to get token from Authorization header
    const authHeader = request.headers.authorization;
    if (authHeader) {
      const [type, token] = authHeader.split(' ');
      if (type === 'Bearer') return token;
    }

    // Then try to get token from cookies
    return request.cookies?.jwt;
  }
}
