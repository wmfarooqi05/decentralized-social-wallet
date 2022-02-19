import { NestMiddleware, Injectable, UnauthorizedException } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { JwtService } from '@nestjs/jwt';
import { IUserJwt } from 'src/common/modules/jwt/jwt-payload.interface';
import { validateUserJwt } from 'src/common/modules/jwt/jwt.validate';

@Injectable()
export class AuthMiddleware implements NestMiddleware {
  constructor(private readonly jwtService: JwtService) {}

  async use(req: Request, res: Response, next: NextFunction) {
    try {
      const authHeaders = req.headers.authorization;
      if (authHeaders && (authHeaders as string).split(' ')[1]) {
        const token = (authHeaders as string).split(' ')[1];
        const user: IUserJwt = this.jwtService.verify(token);
        validateUserJwt(user);
        req.currentUser = user;
        next();
      } else {
        next();
      }
    } catch (error) {
      throw new UnauthorizedException('Invalid access-token.');
    }
  }
}
