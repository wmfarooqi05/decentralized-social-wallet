import {
  BadRequestException,
  ConflictException,
  forwardRef,
  Inject,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { IUserJwt } from 'src/common/modules/jwt/jwt-payload.interface';
import { User, UserRole } from 'src/modules/user/user.entity';
import { UserService } from 'src/modules/user/user.service';
import { Repository } from 'typeorm';
import { ChatMessage } from '../chat-message/chat-message.entity';
import { ChatMessageService } from '../chat-message/chat-message.service';
import { Chatroom } from './chatroom.entity';
import { GET_EXISTING_PRIVATE_CHATROOM } from './query/get-existing-private-chatroom';
import { MESSAGE_TYPE_ENUM } from '../chat.types';
import {
  paginationHelper,
  paginationHelperOffsetLimit,
} from 'src/common/helpers/pagination';
import { GET_CHATROOMS_BY_USER_ID } from './query/get-chatrooms-by-user-id';

@Injectable()
export class ChatroomService {
  constructor(
    @InjectRepository(Chatroom)
    private chatroomRepository: Repository<Chatroom>,
    private userService: UserService,
    @Inject(forwardRef(() => ChatMessageService))
    private chatMessageService: ChatMessageService,
  ) {}

  async findAllChatrooms(page: string, pageSize: string) {
    const { skip, take } = paginationHelper(page, pageSize);
    const chatrooms = await this.chatroomRepository.find({
      skip,
      take,
    });

    return this.addLastMessagesToChatrooms(chatrooms);
  }

  async findAllChatroomsByUser(id: string, page?: string, pageSize?: string) {
    const { limit, offset } = paginationHelperOffsetLimit(page, pageSize);
    return this.chatroomRepository.query(GET_CHATROOMS_BY_USER_ID, [
      [id],
      limit,
      offset,
    ]);
  }

  async _findChatroomById(id: string) {
    return await this.chatroomRepository.findOne(id, {
      relations: ['participants'],
    });
  }

  async findChatroomById(id: string, user: IUserJwt) {
    const chatroom = await this.chatroomRepository.findOne(id, {
      relations: ['participants'],
    });
    await this.checkIfUserPermitted(user, chatroom.participants);
    return chatroom;
  }

  async findMessagesByChatroomId(
    chatroomId: string,
    page: string,
    pageSize: string,
  ) {
    return this.chatMessageService.findMessagesByChatroomId(
      chatroomId,
      page,
      pageSize,
    );
  }

  async findOrCreateChatroom(
    username: string,
    participants: string[],
    name?: string,
    icon?: string,
  ) {
    const existingChatroom = await this.checkIfChatroomExists(participants);

    if (existingChatroom.length) {
      return this.chatroomRepository.findOne(existingChatroom[0]?.id, {
        relations: ['participants'],
      });
    }

    return this.createChatroom(username, participants, name, icon);
  }

  private async createChatroom(
    username: string,
    participants: string[],
    name?: string,
    icon?: string,
  ) {
    const user = await this.userService.findByUsername(username);
    if (!user) {
      throw new NotFoundException("User doesn't exist");
    }
    if (!participants.includes(user.id) && user.role !== UserRole.ADMIN) {
      // Only admin can create someone else's chatroom
      throw new BadRequestException(
        'User cannot create another person chatroom',
      );
    }

    const participantUsers = await this.userService.findByIds(participants);
    if (participantUsers.length !== participants.length) {
      const nonExistingUser = participants.filter(
        (x) => !participantUsers.find((p) => p.id === x),
      );
      throw new BadRequestException(
        `User(s) doesn't exist with Id(s): ${nonExistingUser}`,
      );
    }

    const chatroom = this.chatroomRepository.create({
      participants: participantUsers,
      name,
      icon,
    });
    return this.chatroomRepository.save(chatroom);
  }

  async addParticipantToChatroom(
    userJwtPayload: IUserJwt,
    participantId: string,
    chatroomId: string,
  ): Promise<Chatroom> {
    const chatroom = await this.chatroomRepository.findOne(chatroomId, {
      relations: ['participants'],
    });
    await this.checkIfUserPermitted(userJwtPayload, chatroom.participants);
    const participant = await this.userService.findOneById(participantId);
    if (chatroom.participants.find((x) => x.id === participant.id)) {
      throw new ConflictException(`Participant already exists in the chatroom`);
    }
    chatroom.participants.push(participant);
    return this.chatroomRepository.save(chatroom);
  }

  // @DEPRECATED: deprecated methods
  async addNewMessage(
    username: string,
    chatroomId: string,
    messageContent: string,
    messageType: MESSAGE_TYPE_ENUM,
    messageRandomId?: string,
  ) {
    const user = await this.userService.findByUsername(username);
    const chatroom = await this.chatroomRepository.findOne(chatroomId, {
      relations: ['participants'],
    });

    if (!chatroom.participants.find((x) => x.id === user.id)) {
      throw new UnauthorizedException('This user cannot create this message');
    }

    const newMessage = await this.chatMessageService.createMessage(
      user,
      chatroom,
      messageContent,
      messageType,
      messageRandomId,
    );

    if (newMessage) {
      await this.updateChatroomOnNewMessage(newMessage);
    }

    return newMessage;
  }

  // async addNewMessageViaQueue() {
  //   this.chatQueueService.saveToDB([
  //     {
  //       chatroomId: '1',
  //       messageContent: 'asads',
  //       messageRandomId: '123123123',
  //       messageType: 'IMAGE',
  //       userId:'1',
  //     }
  //   ],
  //   '1',
  //   '1',
  //   )
  // }

  // async updateMessageViaQueue() {
  //   this.chatQueueService.updateMessageStatusInDB([
  //     {
  //      id:'1',
  //       chatroomId: '1',
  //       messageContent: 'asads',
  //       messageRandomId: '123123123',
  //       messageType: 'IMAGE',
  //       userId:'1',
  //       reactions:[],
  //       seenStatuses:[],
  //       seenTicksCount:0,
  //     },
  //   ], 'DELIVERED', '1', '1');
  // }

  async updateChatroomOnNewMessage(message: ChatMessage) {
    const chatroom = await this.chatroomRepository.findOne(message.chatroom.id);
    chatroom.lastMessageId = message.id;
    chatroom.lastMessageUpdatedAt = message.updatedAt;
    return this.chatroomRepository.save(chatroom);
  }

  async deleteMessageFromChatroom(
    chatroomId: string,
    username: string,
    messageId: string,
  ) {
    const user = await this.userService.findByUsername(username);
    return this.chatMessageService.deleteMessage(chatroomId, user, messageId);
  }

  private async checkIfChatroomExists(participants: string[]): Promise<any[]> {
    return this.chatroomRepository.query(GET_EXISTING_PRIVATE_CHATROOM, [
      participants,
    ]);
  }

  private async checkIfUserPermitted(
    { id, role }: IUserJwt,
    participants: User[],
  ) {
    if (role === UserRole.USER) {
      const user = await this.userService.findOneById(id);
      if (!participants.find((x) => x.id === user.id)) {
        throw new UnauthorizedException(
          'The user is not allowed to access this chatroom',
        );
      }
    }
  }

  private async addLastMessagesToChatrooms(chatrooms: Chatroom[]) {
    const lastMessageIds = chatrooms.map((x) => {
      return x.lastMessageId;
    });

    const lastMessages = await this.chatMessageService.findMessageByIds(
      lastMessageIds,
    );

    return chatrooms.map((chatroom) => {
      return {
        ...chatroom,
        lastMessage: lastMessages.find((x) => x.id === chatroom.lastMessageId),
      };
    });
  }
}
