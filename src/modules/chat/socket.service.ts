import {
    Injectable,
  } from '@nestjs/common';
  import { IUserJwt } from 'src/common/modules/jwt/jwt-payload.interface';
  import { User } from 'src/modules/user/user.entity';
  import { Socket } from 'socket.io';
  import { UserService } from 'src/modules/user/user.service';
import { ChatroomService } from './chatroom/chatroom.service';
import { JwtService } from '@nestjs/jwt';
import { validateUserJwt } from 'src/common/modules/jwt/jwt.validate';
import { WsException } from '@nestjs/websockets';
  
  @Injectable()
  export class SocketService {
    constructor(
      private readonly chatroomService: ChatroomService,
      private readonly jwtService: JwtService,
      private readonly userService: UserService,
    ) {}

    async verifyIfUserExistsInChatroom(chatroomId: string, user: IUserJwt) {
      return this.chatroomService.findChatroomById(chatroomId, user);
    }


  /** Verify Handle Connection JWT */
  getUserFromSocket(client: Socket): Promise<User> {
    try {
      const authHeader: string = client.handshake.headers.authorization;
      const authToken = authHeader.substring(7, authHeader.length);
      const user: IUserJwt = this.jwtService.verify(authToken);
      validateUserJwt(user);
      return this.userService.findByUsername(user.username);
    } catch (error) {
      throw new WsException('Invalid access-token.');
    }
  }
  }
  