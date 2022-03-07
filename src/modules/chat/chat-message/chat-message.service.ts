import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { paginationHelper } from 'src/common/helpers/pagination';
import { User } from 'src/modules/user/user.entity';
import { Repository } from 'typeorm';
import { MESSAGE_TYPE, SeenStatuses } from '../chat.types';
import { Chatroom } from '../chatroom/chatroom.entity';
import { ChatMessage } from './chat-message.entity';

@Injectable()
export class ChatMessageService {
  constructor(
    @InjectRepository(ChatMessage)
    private chatMessageRepository: Repository<ChatMessage>, // private userService: UserService,
  ) {}

  createMessage(
    user: User,
    chatroom: Chatroom,
    messageContent: string,
    messageType: MESSAGE_TYPE,
    messageRandomId?: string,
  ) {
    const message = this.chatMessageRepository.create({
      user,
      messageContent,
      messageType: (<any>MESSAGE_TYPE)[messageType],
      messageRandomId,
      chatroom,
      seenStatuses: this.createParticipantsMap(chatroom, user),
    });

    return this.chatMessageRepository.save(message);
  }

  findMessageById(id: string, relations?: string[]): Promise<ChatMessage> {
    return this.chatMessageRepository.findOne(id, {
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
  async deleteMessage(chatroomId: string, user: User, messageId: string) {
    const message = await this.chatMessageRepository.findOne(messageId, {
      relations: ['user', 'chatroom'],
    });
    if (message.user.id !== user.id) {
      throw new UnauthorizedException(
        'A user can only delete his own messages',
      );
    }
    if (message.chatroom.id !== chatroomId) {
      throw new BadRequestException(
        'The message doesn\'t belongs to this chatroom' 
      )
    }
    return this.chatMessageRepository.delete(message.id);
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
}
