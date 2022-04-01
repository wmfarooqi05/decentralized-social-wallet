import { Logger, UseGuards } from '@nestjs/common';
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
import { IUserJwt } from 'src/common/modules/jwt/jwt-payload.interface';
import { WsGuard } from 'src/common/modules/jwt/websocket.guard';
import { SocketService } from '../socket.service';
import { SeenStatus, SeenStatuses } from '../chat.types';
import * as _ from 'lodash';
import {
  IMESSAGE,
  INCOMING_MESSAGE_PAYLOAD,
  OutgoingChannelEventTypes,
  OutgoingSingleClientEventType,
  OUTGOING_CHANNEL_EVENT_TYPE,
  OUTGOING_SINGLE_CLIENT_EVENT_TYPE,
  SocketCustomIncomingEventTypes,
  SOCKET_CUSTOM_INCOMING_EVENT_TYPE,
  SOCKET_INCOMING_PAYLOAD,
  SOCKET_OUTGOING_PAYLOAD,
  USER_MAP_TYPE,
} from './chat-socket.types';
import { ChatQueueService } from '../redis/chat-queue.service';

@WebSocketGateway({
  namespace: '/chat',
  cors: {
    origin: '*',
  },
  // @TODO: uncomment this
  // transports: ['websocket'],
})
export class ChatGateway
  implements OnGatewayInit, OnGatewayConnection, OnGatewayDisconnect
{
  constructor(
    private readonly socketService: SocketService,
    private readonly chatQueueService: ChatQueueService,
  ) {}

  @WebSocketServer() server: Server;
  onlineUsersMap = new Map<string, USER_MAP_TYPE>();
  private logger: Logger = new Logger('ChatGateway');

  afterInit(server: Server) {
    this.logger.log('Init');
  }

  handleDisconnect(client: Socket) {
    // const { userId } = client.handshake.query;
    // this.onlineUsersMap.delete(userId?.toString());
    this.logger.log(`Client disconnected, ${client?.id}`);
    // this.removeUserFromMap() @MOST_IMPORTANT @TODO: fix this
  }

  handleConnection(client: Socket, ...args: any) {
    try {
      const user = this.socketService.getUserFromSocket(client);
      this.storeUserToMap(client, user);
      console.log(`Client connected: ${client?.id}, User: ${user.username}`);
    } catch (e) {
      // this.removeUserFromMap()
      client.disconnect(true);
    }
  }

  /** Listeners */

  @UseGuards(WsGuard)
  @SubscribeMessage<SOCKET_CUSTOM_INCOMING_EVENT_TYPE>(
    SocketCustomIncomingEventTypes.JOIN_ROOM,
  )
  public async joinRoom(
    client: Socket,
    payload: SOCKET_INCOMING_PAYLOAD,
  ): Promise<void> {
    try {
      const { currentRoomId, user } = payload;
      await this.onJoinRoom(client.id, currentRoomId, user);
      client.join(payload.currentRoomId);
      console.log('room joined', payload.currentRoomId, user.username);
      // this.emitEventToCurrentRoom(
      //   ,
      // ); // @TODO: Implement Side Effect
    } catch (err) {
      throw new WsException(err.message);
    }
  }

  @UseGuards(WsGuard)
  @SubscribeMessage<SOCKET_CUSTOM_INCOMING_EVENT_TYPE>(
    SocketCustomIncomingEventTypes.LEAVE_ROOM,
  )
  public leaveRoom(@MessageBody() payload: SOCKET_INCOMING_PAYLOAD): void {}

  @UseGuards(WsGuard)
  @SubscribeMessage<SOCKET_CUSTOM_INCOMING_EVENT_TYPE>(
    SocketCustomIncomingEventTypes.NEW_MESSAGE,
  )
  public onNewMessage(
    @ConnectedSocket() client: Socket,
    @MessageBody() payload: SOCKET_INCOMING_PAYLOAD,
  ) {
    const newMessage: SOCKET_OUTGOING_PAYLOAD =
      this.constructNewMessage(payload);

    this.broadcaseEventToCurrentRoom(
      client,
      newMessage.currentRoomId,
      OutgoingChannelEventTypes.CLIENT_ON_NEW_MESSAGE,
      newMessage,
    );

    this.saveToDB(newMessage.messages, payload.currentRoomId, payload.user);
    this.emitEventOnlyToClient(
      client.id,
      OutgoingSingleClientEventType.SINGLE_CLIENT_ON_MESSAGE_SENT,
      newMessage,
    );
  }

  @UseGuards(WsGuard)
  @SubscribeMessage<SOCKET_CUSTOM_INCOMING_EVENT_TYPE>('TYPING')
  handleEvent(
    @ConnectedSocket() client: Socket,
    @MessageBody() payload: SOCKET_INCOMING_PAYLOAD,
  ): void {
    const {
      user,
      currentRoomId,
      extraData: { typing },
    } = payload;
    // outOfRoomParticipents(chatroomId, io, message)
    this.broadcaseEventToCurrentRoom(
      client,
      currentRoomId,
      OutgoingChannelEventTypes.CLIENT_ON_TYPING,
      {
        currentRoomId,
        user,
        extraData: {
          typing,
        },
      },
    );
  }

  @UseGuards(WsGuard)
  @SubscribeMessage<SOCKET_CUSTOM_INCOMING_EVENT_TYPE>('UPDATE_MESSAGE_STATUS')
  public onUpdateMessageStatus(
    @MessageBody() payload: SOCKET_INCOMING_PAYLOAD,
  ) {
    // Here two users are in scope
    // 1- sender
    // 2- who has updated the message status i.e. seen by user2
    // @NOTES: make sure only sender will recieve this

    const {
      extraData: { seenStatus },
      messages,
      currentRoomId,
      user: acknowledingUser,
    } = payload;
    this.updateMessageStatusInDB(
      messages,
      seenStatus,
      currentRoomId,
      acknowledingUser,
    );
    const messagesGroupedByUsers: any = _.groupBy(messages, 'userId');
    for (const senderId in messagesGroupedByUsers) {
      const { clientId: senderClientId } = this.getUserFromMap(senderId);
      this.emitEventOnlyToClient(
        senderClientId,
        OutgoingSingleClientEventType.SINGLE_CLIENT_UPDATE_MESSAGE_STATUS,
        {
          currentRoomId,
          user: acknowledingUser,
          extraData: {
            seenStatus,
          },
          messages: messagesGroupedByUsers[senderId],
        },
      );
    }
  }

  @UseGuards(WsGuard)
  @SubscribeMessage<SOCKET_CUSTOM_INCOMING_EVENT_TYPE>('MESSAGE_DELIVERED')
  public onMessageReceived(
    @ConnectedSocket() client: Socket,
    @MessageBody() payload: SOCKET_INCOMING_PAYLOAD,
  ) {
    client.broadcast
      .to(payload.currentRoomId)
      .emit('CLIENT_ON_MESSAGE_DELIVERED');
  }

  @UseGuards(WsGuard)
  @SubscribeMessage<SOCKET_CUSTOM_INCOMING_EVENT_TYPE>('MESSAGE_SEEN')
  public onMessageSeen(
    @ConnectedSocket() client: Socket,
    @MessageBody() payload: SOCKET_INCOMING_PAYLOAD,
  ) {
    client.broadcast.to(payload.currentRoomId).emit('CLIENT_ON_MESSAGE_SEEN');
  }

  @UseGuards(WsGuard)
  @SubscribeMessage<SOCKET_CUSTOM_INCOMING_EVENT_TYPE>('CHECK_UPDATES')
  public onCheckUpdates() {
    console.log('CHECK_UPDATES');
  }

  @UseGuards(WsGuard)
  @SubscribeMessage<SOCKET_CUSTOM_INCOMING_EVENT_TYPE>('PRINT_MAP')
  public printMap() {
    console.log(this.onlineUsersMap.values());
  }

  @UseGuards(WsGuard)
  @SubscribeMessage<SOCKET_CUSTOM_INCOMING_EVENT_TYPE>('DISCONNECT')
  public onDisconnect() {
    console.log('DISCONNECT');
  }

  @UseGuards(WsGuard)
  addUserToMap(username: string, payload: USER_MAP_TYPE) {
    // @TODO: add conditions here
    this.onlineUsersMap.set(username, { ...payload });
  }

  constructNewMessage(
    payload: SOCKET_INCOMING_PAYLOAD,
  ): SOCKET_OUTGOING_PAYLOAD {
    const { user } = payload;
    const { currentRoomId }: USER_MAP_TYPE = this.getUserFromMap(user.id);
    let chatroomValid = true;
    const date = new Date();
    const { messages } = payload;

    messages.forEach((x) => {
      if (x.chatroomId !== currentRoomId) {
        chatroomValid = false;
      }
    });
    if (!chatroomValid) {
      console.log('user currently not present in this chatroom');
    }

    const seenStatuses: SeenStatuses[] = [
      {
        status: 'SENT',
        updatedAt: new Date(),
        userId: user.id,
      },
    ];

    return {
      currentRoomId,
      extraData: {
        seenStatus: 'SENT',
      },
      messages: messages.map((message) => {
        const { messageContent, messageRandomId, messageType, chatroomId } =
          message;
        return {
          chatroomId,
          userId: user.id,
          sendingTime: date,
          messageContent,
          messageRandomId,
          messageType,
          reactions: [],
          seenStatuses,
          seenTicksCount: 1,
        };
      }),
      user,
    };
  }

  broadcaseEventToCurrentRoom(
    client: Socket,
    currentRoomId: string,
    event: OUTGOING_CHANNEL_EVENT_TYPE,
    payload: SOCKET_OUTGOING_PAYLOAD,
  ) {
    client.broadcast.to(currentRoomId).emit(event, payload);
  }

  // DO we need this?
  emitEventToCurrentRoom() {}

  emitEventOnlyToClient(
    clientId: string,
    event: OUTGOING_SINGLE_CLIENT_EVENT_TYPE,
    payload: SOCKET_OUTGOING_PAYLOAD,
  ) {
    this.server.to(clientId).emit(event, payload);
  }

  getUserFromMap(username: string): USER_MAP_TYPE {
    return this.onlineUsersMap.get(username);
  }

  storeUserToMap(client: Socket, user: IUserJwt, currentRoomId?: string) {
    this.onlineUsersMap.set(user.id, {
      username: user.username,
      clientId: client.id,
      currentRoomId,
      status: 'ONLINE',
    });
  }

  async onJoinRoom(
    clientId: string,
    currentRoomId: string,
    user: IUserJwt,
  ): Promise<void> {
    await this.socketService.verifyIfUserExistsInChatroom(
      currentRoomId,
      user.id,
    );
    this.onlineUsersMap.set(user.id, {
      clientId,
      status: 'ONLINE',
      username: user.username,
      currentRoomId,
    });
  }

  // Move these functions to service file

  saveToDB(messages: IMESSAGE[], currentRoomId: string, user: IUserJwt): void {
    this.chatQueueService.saveToDB(messages, currentRoomId, user);
  }

  updateMessageStatusInDB(
    messages: INCOMING_MESSAGE_PAYLOAD[],
    seenStatus: SeenStatus,
    currentRoomId: string,
    acknowledingUser: IUserJwt,
  ): void {
    this.chatQueueService.updateMessageStatusInDB(
      messages,
      seenStatus,
      currentRoomId,
      acknowledingUser,
    );
  }
}
