import {
  BadRequestException,
  forwardRef,
  Inject,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { paginationHelper } from 'src/common/helpers/pagination';
import { IUserJwt } from 'src/common/modules/jwt/jwt-payload.interface';
import { GoogleCloudService } from 'src/common/services/google-cloud/google-cloud.service';
import { User } from 'src/modules/user/user.entity';
import { UserService } from 'src/modules/user/user.service';
import { Repository } from 'typeorm';
import { v4 as uuidv4 } from 'uuid';
import { MESSAGE_TYPE_ENUM, SeenStatus, SeenStatuses } from '../chat.types';
import { Chatroom } from '../chatroom/chatroom.entity';
import { ChatroomService } from '../chatroom/chatroom.service';
import {
  IMESSAGE,
  INCOMING_MESSAGE_PAYLOAD,
} from '../socket/chat-socket.types';
import { ChatMessage } from './chat-message.entity';

@Injectable()
export class ChatMessageService {
  constructor(
    @InjectRepository(ChatMessage)
    private chatMessageRepository: Repository<ChatMessage>,
    private userService: UserService,
    @Inject(forwardRef(() => ChatroomService))
    private chatroomService: ChatroomService,
    private googleCloudService: GoogleCloudService,
  ) {}

  createMessage(
    user: User,
    chatroom: Chatroom,
    messageContent: string,
    messageType: MESSAGE_TYPE_ENUM,
    messageRandomId?: string,
  ) {
    const message = this.chatMessageRepository.create({
      user,
      messageContent,
      messageType: (<any>MESSAGE_TYPE_ENUM)[messageType],
      messageRandomId,
      chatroom,
      seenStatuses: this.createParticipantsMap(chatroom, user),
    });

    return this.chatMessageRepository.save(message);
  }
  findMessageById(id: string, relations?: string[]): Promise<ChatMessage> {
    return this.chatMessageRepository.findOne({
      where: {
        id,
      },
      relations,
    });
  }

  findMessageByIds(ids: string[]): Promise<ChatMessage[]> {
    return this.chatMessageRepository.findByIds(ids);
  }

  findMessagesByChatroomId(chatroomId: string, page: string, pageSize: string) {
    const { skip, take } = paginationHelper(page, pageSize);
    return this.chatMessageRepository.find({
      where: {
        chatroom: { id: chatroomId },
      },
      relations: ['user'],
      skip,
      take,
      order: {
        updatedAt: 'DESC',
      },
    });
  }

  async update(messageId: string, message: ChatMessage) {
    return this.chatMessageRepository.update(messageId, message);
  }
  async deleteMessage(chatroomId: string, user: User, messageId: string, messageRandomId: string) {
    const message = await this.chatMessageRepository.findOne({
      where: [{
        id: messageId,
      }, {
        messageRandomId,
        user: { id: user.id },
      }],
      relations: ['user', 'chatroom'],
    });
    if (!message) {
      throw new NotFoundException('Message not found');
    }
    if (message.user.id !== user.id) {
      throw new UnauthorizedException(
        'A user can only delete his own messages',
      );
    }
    if (message.chatroom.id !== chatroomId) {
      throw new BadRequestException(
        "The message doesn't belongs to this chatroom",
      );
    }
    return this.chatMessageRepository.update(messageId, {
      isDeleted: true,
    });
  }
  /** HELPER METHODS */

  private createParticipantsMap = (
    chatroom: Chatroom,
    user: User,
  ): SeenStatuses[] => {
    const updatedAt = new Date();
    return chatroom.participants.map((x: User): SeenStatuses => {
      return {
        userId: x.id,
        updatedAt,
        status: x.id === user.id ? 'SENDING' : 'NOT_DELIVERED',
      };
    });
  };

  /***  QUEUE OPERATIONS  */

  async createMessageBulk(
    messages: IMESSAGE[],
    currentRoomId: string,
    acknowledingUser: IUserJwt,
  ) {
    if (!acknowledingUser.id) {
      console.error('User JWT doesn\'t has id param');
    }
    const user = await this.userService.findOneById(acknowledingUser.id);
    if (!user) {
      console.error('The user doesn\'t exists');
    }
    const chatroom = await this.chatroomService._findChatroomById(
      currentRoomId,
    );

    if (!chatroom.participants.find((x) => x.id === user.id)) {
      console.error('This user cannot create this message');
    }

    const seenStatuses: SeenStatuses[] = [];
    const timeNow = new Date();
    chatroom.participants.map((participant: User) => {
      seenStatuses.push({
        status: 'NOT_DELIVERED',
        userId: participant.id,
        updatedAt: timeNow,
      });
    });

    let latestMessage = null;

    const newMessagesPayload = messages.map((message) => {
      const newMessage = {
        chatroom: { id: message.chatroomId },
        messageContent: message.messageContent,
        messageRandomId: message.messageRandomId,
        messageType: MESSAGE_TYPE_ENUM[`${message.messageType}`],
        reactions: [],
        seenStatuses,
        seenTicksCount: 0,
        user: { id: message.userId },
        sendingTime: message.sendingTime,
      };

      if (!latestMessage) {
        latestMessage = newMessage;
      } else {
        if (latestMessage.sendingTime < newMessage.sendingTime) {
          latestMessage = newMessage;
          0;
        }
      }
      return newMessage;
    });

    if (newMessagesPayload.length) {
      await this.chatMessageRepository.save(newMessagesPayload);
      await this.chatroomService.updateChatroomOnNewMessage(latestMessage);
    }
  }

  /**
   * Flow
   * UserA sent a message to UserB
   * Now we have to store the seen_status of UserB (userId) as `SEEN`
   *
   * @param messages
   * @param seenStatus
   * @param currentRoomId
   * @param acknowledingUser
   */
  async updateMessageStatusesBulk(
    messages: INCOMING_MESSAGE_PAYLOAD[],
    seenStatus: SeenStatus,
    currentRoomId: string,
    acknowledingUser: IUserJwt,
  ) {
    try {
      // It will verify if acknowledging user is part of this chatroom
      await this.chatroomService.findChatroomById(
        currentRoomId,
        acknowledingUser,
      );

      const messageIds = messages.map((x) => x.id);
      const messagesRecord = await this.chatMessageRepository.findByIds(
        messageIds,
      );

      for (let i = 0; i < messagesRecord.length; i++) {
        messagesRecord[i].seenStatuses.forEach((_seenStatus: SeenStatuses) => {
          if (_seenStatus.userId === acknowledingUser.id) {
            _seenStatus.status = seenStatus;
          }
        });

        await this.chatMessageRepository.update(messagesRecord[i].id, {
          seenStatuses: messagesRecord[i].seenStatuses,
        });
      }
    } catch(e) {
      console.error(e);
    }
  }

  async uploadChatImage(
    userJwt: IUserJwt,
    currentRoomId: string,
    buffer: Buffer,
    mimetype: string,
  ) {
    try {
      const id = uuidv4();

      await this.chatroomService.findChatroomById(currentRoomId, userJwt);

      const url = await this.googleCloudService.save(
        `media/chatrooms/${currentRoomId}/${id}.${mimetype.split('/')[1]}`,
        buffer,
      );

      /*** Message Storage */

      const user = await this.userService.findOneById(userJwt.id);
      const chatroom = await this.chatroomService._findChatroomById(
        currentRoomId,
      );

      if (!chatroom.participants.find((x) => x.id === user.id)) {
        throw new UnauthorizedException('This user cannot create this message');
      }

      const seenStatuses: SeenStatuses[] = [];
      const timeNow = new Date();
      chatroom.participants.map((participant: User) => {
        seenStatuses.push({
          status: 'NOT_DELIVERED',
          userId: participant.id,
          updatedAt: timeNow,
        });
      });

      const newMessage = {
        chatroom: { id: currentRoomId },
        messageContent: url,
        messageRandomId: id,
        messageType: MESSAGE_TYPE_ENUM.IMAGE,
        reactions: [],
        seenStatuses,
        seenTicksCount: 0,
        user: { id: userJwt.id },
        sendingTime: new Date(),
      };

      const message = await this.chatMessageRepository.save(newMessage);
      await this.chatroomService.updateChatroomOnNewMessage(message);

      return message;
    } catch(e) {
      console.error(e);
    };
  }
}
