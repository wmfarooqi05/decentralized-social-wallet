import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Socket } from 'socket.io';
import { JwtService } from '@nestjs/jwt';
import { WsException } from '@nestjs/websockets';
import { IUserJwt } from './jwt-payload.interface';

@Injectable()
export class WsGuard implements CanActivate {
  constructor(private readonly jwtService: JwtService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    try {
      const client: Socket = context.switchToWs().getClient<Socket>();
      const authHeader: string = client.handshake.headers.authorization;
      const authToken = authHeader.substring(7, authHeader.length);
      const jwtPayload: IUserJwt = await this.jwtService.verify(authToken);
      const user: any = this.validateUser(jwtPayload);

      context.switchToWs().getData().user = user;
      return Boolean(user);
    } catch (err) {
      throw new WsException(err.message);
    }
  }

  validateUser(payload: IUserJwt): any {
    return payload;
  }
}
