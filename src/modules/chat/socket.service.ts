import { Injectable, UnauthorizedException } from '@nestjs/common';
import { IUserJwt } from 'src/common/modules/jwt/jwt-payload.interface';
import { Socket } from 'socket.io';
import { JwtService } from '@nestjs/jwt';
import { validateUserJwt } from 'src/common/modules/jwt/jwt.validate';

@Injectable()
export class SocketService {
  constructor(private readonly jwtService: JwtService) {}

  async verifyIfUserExistsInChatroom(
    chatroomId: string,
    userId: string,
  ): Promise<void> {
    // @TODO: store chatroom map in redis and confirm from there
    // const chatroom = await this.chatroomService.findChatroomById(chatroomId, user);
    // return chatroom.participants.find(x => x.username === user.username);
  }

  /** Verify Handle Connection JWT */
  getUserFromSocket(client: Socket): IUserJwt {
    try {
      const authHeader: string = client.handshake.headers.authorization;
      const authToken = authHeader.substring(7, authHeader.length);
      const user: IUserJwt = this.jwtService.verify(authToken);
      validateUserJwt(user);
      return user;
    } catch (error) {
      throw new UnauthorizedException('Invalid access-token.');
    }
  }
}
