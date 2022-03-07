import { Logger, UseGuards } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import {
  SubscribeMessage,
  WebSocketGateway,
  OnGatewayInit,
  WebSocketServer,
  OnGatewayConnection,
  OnGatewayDisconnect,
  MessageBody,
  ConnectedSocket,
  WsException,
} from '@nestjs/websockets';
import { Socket, Server } from 'socket.io';
import { JwtAuthGuard } from 'src/common/modules/jwt/jwt-auth.guard';
import { IUserJwt } from 'src/common/modules/jwt/jwt-payload.interface';
import { validateUserJwt } from 'src/common/modules/jwt/jwt.validate';
import { WsGuard } from 'src/common/modules/jwt/websocket.guard';
import { User } from '../user/user.entity';
import { UserService } from '../user/user.service';
import { SocketService } from './socket.service';

type SOCKET_CUSTOM_EVENT_TYPE =
  | 'NEW_MESSAGE'
  | 'TYPING'
  | 'UPDATE_MESSAGE_STATUS'
  | 'JOIN_ROOM'
  | 'MESSAGE_RECEIVED'
  | 'CHECK_UPDATES'
  | 'DISCONNECT'
  | 'LEAVE_ROOM'
  | 'CLIENT_JOINED_ROOM';

const SocketCustomEventTypes: Record<SOCKET_CUSTOM_EVENT_TYPE, string> = {
  CHECK_UPDATES: 'CHECK_UPDATES',
  DISCONNECT: 'DISCONNECT',
  JOIN_ROOM: 'JOIN_ROOM',
  MESSAGE_RECEIVED: 'MESSAGE_RECEIVED',
  NEW_MESSAGE: 'NEW_MESSAGE',
  TYPING: 'TYPING',
  UPDATE_MESSAGE_STATUS: 'UPDATE_MESSAGE_STATUS',
  LEAVE_ROOM: 'LEAVE_ROOM',
  // Client Events
  CLIENT_JOINED_ROOM: 'CLIENT_JOINED_ROOM',
};

type SocketUser = {
  id: string;
  name: string;
  avatar: string;
};

type STATUS_TYPE = {
  SENT: 'SENT';
  NOT_SENT: 'NOT_SENT'; // FAILED
  SENDING: 'SENDING'; // will set to not_sent after 30 second

  /** OTHER PARTICIPANTS */
  NOT_DELIEVERED: 'NOT_DELIVERED'; // Default state
  DELIVERED: 'DELIVERED';
  SEEN: 'SEEN';
  READ: 'READ';
};

type READ_STATUS = {
  status: STATUS_TYPE;
  userId: string;
  updatedAt: Date;
};

type MESSAGE_TYPE = 'TEXT' | 'IMAGE';

type SOCKET_CUSTOM_EVENT_DTO = {
  eventName: SOCKET_CUSTOM_EVENT_TYPE;
  name: string;
  currentRoomId: string;
  user: SocketUser;
  message: string;
  type: MESSAGE_TYPE;
  messageRandomId: string;
  image: string;
  date: string;
  seenStatuses: READ_STATUS[];
  extraData: { typing: boolean };
};

type SOCKET_UPDATE_STATUS_DTO = {
  currentRoomId: string;
  user: SocketUser;
  status: STATUS_TYPE;
};

type MESSAGE_PAYLOAD = {};

type SOCKET_USER_STATUS = 'ONLINE' | 'OFFLINE';

type USER_MAP_TYPE = {
  clientId: string;
  status: SOCKET_USER_STATUS;
  roomName?: string | null;
};

@WebSocketGateway({
  namespace: '/chat',
  cors: {
    origin: '*',
  },

  // transports: ['websocket'],
})
export class ChatGateway
  implements OnGatewayInit, OnGatewayConnection, OnGatewayDisconnect
{
  constructor(private readonly socketService: SocketService) {}

  @WebSocketServer() server: Server;
  onlineUsersMap = new Map<string, USER_MAP_TYPE>();
  private logger: Logger = new Logger('ChatGateway');

  @SubscribeMessage('msgToServer')
  handleMessage(client: Socket, payload: any): void {
    console.log('handleDisconnect', payload);
    this.server.to(payload?.room).emit('msgToCleint', payload);
    // this.server.emit('msgToClient', payload);
  }

  afterInit(server: Server) {
    this.logger.log('Init');
  }

  handleDisconnect(client: Socket) {
    console.log('handleDisconnect', client?.id);
    const { userId } = client.handshake.query;
    this.onlineUsersMap.delete(userId?.toString());
    this.logger.log(`Client disconnected: ${client?.id}`);
  }

  async handleConnection(client: Socket, ...args: any) {
    try {
      console.log('handleConnection', client?.id);
      const user = await this.socketService.getUserFromSocket(client);
      this.onlineUsersMap.set(user.username?.toString(), {
        clientId: client.id,
        roomName: null,
        status: 'ONLINE',
      });
      this.logger.log(`Client connected: ${client?.id}, User: ${user.id}`);
    } catch (e) {
      client.disconnect();
    }
  }

  /** Listeners */

  @UseGuards(WsGuard)
  @SubscribeMessage('JOIN_ROOM')
  public async joinRoom(client: Socket, payload: any): Promise<void> {
    try {
      const { currentRoomId, user }: { currentRoomId: string; user: IUserJwt } =
        payload;
      await this.socketService.verifyIfUserExistsInChatroom(
        currentRoomId,
        user,
      );
      client.join(payload.currentRoomId);
      client.emit(
        SocketCustomEventTypes.CLIENT_JOINED_ROOM,
        payload.currentRoomId,
      ); // @TODO: Implement Side Effect
    } catch (err) {
      throw new WsException(err.message);
    }
  }

  @UseGuards(WsGuard)
  @SubscribeMessage('LEAVE_ROOM')
  public leaveRoom(client: Socket, room: string): void {
    client.leave(room);
    client.emit('leftRoom', room);
  }

  @UseGuards(WsGuard)
  @SubscribeMessage('NEW_MESSAGE')
  public onNewMessage(
    @ConnectedSocket() client: Socket,
    @MessageBody() payload: SOCKET_CUSTOM_EVENT_DTO,
  ) {
    console.log('NEW_MESSAGE', payload);
    const {
      currentRoomId,
      date,
      eventName,
      image,
      message,
      messageRandomId,
      name,
      seenStatuses, //@TODO: fix status payload
      type,
      user,
    } = payload;

    this.addUserToMap(user.id, {
      clientId: client.id,
      status: 'ONLINE',
      roomName: currentRoomId,
    });
    client.broadcast.to(currentRoomId).emit('CLIENT_ON_NEW_MESSAGE', payload);
    this.saveToDB(payload);
    this.server.to(client.id).emit('SELF_ON_MESSAGE_SENT', payload);
  }

  @UseGuards(WsGuard)
  @SubscribeMessage('TYPING')
  handleEvent(
    @ConnectedSocket() client: Socket,
    @MessageBody() payload: SOCKET_CUSTOM_EVENT_DTO,
  ): void {
    const {
      user,
      currentRoomId,
      extraData: { typing },
    } = payload;
    console.log('TYPING');
    this.addUserToMap(user.id, {
      clientId: client.id,
      status: 'ONLINE',
      roomName: currentRoomId,
    });
    // outOfRoomParticipents(chatroomId, io, message)
    client.broadcast.to(currentRoomId).emit('CLIENT_ON_TYPING', payload);
  }

  @UseGuards(WsGuard)
  @SubscribeMessage('UPDATE_MESSAGE_STATUS')
  public onUpdateMessageStatus(
    @ConnectedSocket() client: Socket,
    @MessageBody() payload: SOCKET_UPDATE_STATUS_DTO,
  ) {
    client.broadcast
      .to(payload.currentRoomId)
      .emit('CLIENT_ON_UPDATE_MESSAGE_STATUS', payload); // @TODO place validations like userId, payload extra vars
  }

  @UseGuards(WsGuard)
  @SubscribeMessage('MESSAGE_DELIVERED')
  public onMessageReceived(
    @ConnectedSocket() client: Socket,
    @MessageBody() payload: SOCKET_CUSTOM_EVENT_DTO,
  ) {
    client.broadcast
      .to(payload.currentRoomId)
      .emit('CLIENT_ON_MESSAGE_DELIVERED');
  }

  @UseGuards(WsGuard)
  @SubscribeMessage('MESSAGE_SEEN')
  public onMessageSeen(
    @ConnectedSocket() client: Socket,
    @MessageBody() payload: SOCKET_CUSTOM_EVENT_DTO,
  ) {
    client.broadcast.to(payload.currentRoomId).emit('CLIENT_ON_MESSAGE_SEEN');
  }

  @UseGuards(WsGuard)
  @SubscribeMessage('CHECK_UPDATES')
  public onCheckUpdates(client: Socket, ...args: any) {
    console.log('CHECK_UPDATES');
  }

  @UseGuards(WsGuard)
  @SubscribeMessage('PRINT_MAP')
  public printMap(client: Socket, ...args: any) {
    console.log(this.onlineUsersMap.values());
  }

  @UseGuards(WsGuard)
  @SubscribeMessage('DISCONNECT')
  public onDisconnect() {
    console.log('DISCONNECT');
  }

  @UseGuards(WsGuard)
  addUserToMap(userId: string, payload: USER_MAP_TYPE) {
    // @TODO: add conditions here
    this.onlineUsersMap.set(userId?.toString(), { ...payload });
  }

  saveToDB(payload: SOCKET_CUSTOM_EVENT_DTO) {
    // @TODO: save the payload to DB
    // @TODO: use redis to save to db
  }
}
