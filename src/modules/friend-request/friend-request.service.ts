import {
  Injectable,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { InjectConnection, InjectRepository } from '@nestjs/typeorm';
import { paginationHelper } from 'src/common/helpers/pagination';
import {
  Connection,
  FindOptionsWhere,
  In,
  Like,
  Not,
  UpdateResult,
  DataSource,
} from 'typeorm';

import { Repository } from 'typeorm';
import { UserService } from '../user/user.service';
import { FriendRequest, FriendRequest_Status } from './friend-request.entity';
import Errors from './errors';
import { ChatroomService } from '../chat/chatroom/chatroom.service';
import { User } from '../user/user.entity';

@Injectable()
export class FriendRequestService {
  constructor(
    @InjectRepository(FriendRequest)
    private friendRequestRepository: Repository<FriendRequest>,
    private userService: UserService,
    private chatroomService: ChatroomService,
    @InjectConnection() private connection: Connection,
  ) {}

  async getFriendRequests(senderId: string, page = null, pageSize = null) {
    const { skip, take } = paginationHelper(page, pageSize);
    // @TODO: add pagination

    const order: any = {
      updatedAt: 'ASC',
    };
    return this.friendRequestRepository.find({
      where: {
        sender: { id: senderId },
        friendshipStatus: Not(FriendRequest_Status.BLOCKED_BY_OTHER_USER),
      },
      relations: ['receiver'],
      skip,
      take,
      order,
    });
  }

  async search(
    senderId: string,
    queryString: string,
    page = null,
    pageSize = null,
  ) {
    const { skip, take } = paginationHelper(page, pageSize);
    const users = await this.userService.search(queryString);

    if (!users?.length) {
      return [];
    }

    const friends = await this.friendRequestRepository.find({
      where: {
        sender: { id: senderId },
        receiver: In(users.map((u) => u.id)),
      },
      relations: ['receiver'],
      skip,
      take,
    });

    return this.usersToFriendRequestJson(users, friends);
  }

  async searchFriendList(sender, queryString, page = null, pageSize = null) {
    const { skip, take } = paginationHelper(page, pageSize);
    // @TODO: add pagination
    const whereClause: FindOptionsWhere<FriendRequest> = {
      sender: { id: sender },
      friendshipStatus: Not(FriendRequest_Status.BLOCKED_BY_OTHER_USER),
    };

    return this.friendRequestRepository.find({
      relations: {
        receiver: true,
      },
      select: {
        sender: { id: true },
      },
      where: [
        { ...whereClause, receiver: { username: Like(`%${queryString}%`) } },
        { ...whereClause, receiver: { email: Like(`%${queryString}%`) } },
        { ...whereClause, receiver: { phoneNumber: Like(`%${queryString}%`) } },
        { ...whereClause, receiver: { fullName: Like(`%${queryString}%`) } },
      ],
      skip,
      take,
    });
  }

  async sendFriendRequest(
    senderId: string,
    receiverId: string,
    message: string,
  ) {
    const exists = await this.findFriendEntity(senderId, receiverId, false);

    if (exists) {
      switch (exists.friendshipStatus) {
        case FriendRequest_Status.WAITING_FOR_CURRENT_USER_RESPONSE:
          throw new BadRequestException(
            Errors.FriendRequest.FRIEND_REQUEST_ALREADY_SENT,
          );
        case FriendRequest_Status.ACCEPTED:
          throw new BadRequestException(
            Errors.FriendRequest.FRIEND_REQUEST_ALREADY_ACCEPTED,
          );
        case FriendRequest_Status.BLOCKED_BY_OTHER_USER:
          throw new BadRequestException(
            Errors.FriendRequest.YOU_ARE_BLOCKED_BY_OTHER_USER,
          );
        case FriendRequest_Status.BLOCKED_BY_ME:
          throw new BadRequestException(
            Errors.FriendRequest.YOU_HAVE_BLOCKED_THIS_USER,
          );
      }

      if (exists.friendshipStatus === FriendRequest_Status.PENDING) {
        return this.acceptFriendRequest(receiverId, senderId);
      }
    } else {
      return this.createFriendRequestRelations(
        senderId,
        FriendRequest_Status.WAITING_FOR_CURRENT_USER_RESPONSE,
        receiverId,
        FriendRequest_Status.PENDING,
        message,
      );
    }
  }

  /**
   * Accept a PENDING friend request
   * @param senderId The other User who sent this request
   * @param receiverId Me User who is accepting the request
   */
  async acceptFriendRequest(senderId: string, receiverId: string) {
    // @TODO
    // check if user is on accepting end
    // For Relation A->B and B->A, we are finding row of B->A
    const { friendshipStatus } = await this.findFriendEntity(
      receiverId,
      senderId,
    );
    switch (friendshipStatus) {
      case FriendRequest_Status.ACCEPTED:
        throw new BadRequestException(
          Errors.FriendRequest.FRIEND_REQUEST_ALREADY_ACCEPTED,
        );
    }

    if (friendshipStatus !== FriendRequest_Status.PENDING) {
      // @TODO: investigate logic here
      throw new BadRequestException('You cannot accept this friend request');
    }

    const { status, error } = await this.friendRequestUpdateTransaction(
      senderId,
      FriendRequest_Status.ACCEPTED,
      receiverId,
      FriendRequest_Status.ACCEPTED,
      true,
    );

    if (!status && error) {
      delete error['response'];
      throw new BadRequestException(error);
    }
  }

  async cancelSentFriendRequest(senderId: string, receiverId: string) {
    const { friendshipStatus } = await this.findFriendEntity(
      senderId,
      receiverId,
    );

    if (
      friendshipStatus ===
      FriendRequest_Status.WAITING_FOR_CURRENT_USER_RESPONSE
    ) {
      this.friendRequestDeleteTransaction(senderId, receiverId);
    } else {
      throw new BadRequestException(
        `Friend Request cannot be cancelled, Status: ${friendshipStatus}`,
      );
    }
  }

  async blockFriend(senderId: string, receiverId: string) {
    const senderFriendRequest = await this.findFriendEntity(
      senderId,
      receiverId,
      false,
    );

    if (senderFriendRequest) {
      const { friendshipStatus } = senderFriendRequest;
      if (friendshipStatus === FriendRequest_Status.BLOCKED_BY_OTHER_USER) {
        throw new BadRequestException(
          Errors.FriendRequest.YOU_ARE_BLOCKED_BY_OTHER_USER,
        );
      }

      await this.friendRequestUpdateTransaction(
        senderId,
        FriendRequest_Status.BLOCKED_BY_ME,
        receiverId,
        FriendRequest_Status.BLOCKED_BY_OTHER_USER,
      );
    } else {
      await this.createFriendRequestRelations(
        senderId,
        FriendRequest_Status.BLOCKED_BY_ME,
        receiverId,
        FriendRequest_Status.BLOCKED_BY_OTHER_USER,
      );
    }
  }

  async unblockFriend(senderId: string, receiverId: string) {
    const { friendshipStatus } = await this.findFriendEntity(
      senderId,
      receiverId,
    );

    if (friendshipStatus !== FriendRequest_Status.BLOCKED_BY_ME) {
      throw new Error(Errors.FriendRequest.YOU_HAVE_NOT_BLOCKED_THIS_USER);
    }

    await this.friendRequestDeleteTransaction(senderId, receiverId);
  }

  async unFriend(senderId: string, receiverId: string) {
    const senderFriendRequest = await this.findFriendEntity(
      senderId,
      receiverId,
    );

    if (
      senderFriendRequest.friendshipStatus !== FriendRequest_Status.ACCEPTED
    ) {
      throw new BadRequestException(Errors.FriendRequest.NOT_FRIEND_WITH_YOU);
    }

    await this.friendRequestDeleteTransaction(senderId, receiverId);
  }

  /*** HELPERS */

  async findFriendEntity(
    senderId: string,
    receiverId: string,
    errorOnNull = true,
  ): Promise<FriendRequest | null> {
    if (senderId === receiverId) {
      throw new BadRequestException(Errors.FriendRequest.BOTH_USERS_ARE_SAME);
    }

    const friendRequest = await this.friendRequestRepository.findOne({
      where: {
        sender: { id: senderId },
        receiver: { id: receiverId },
      },
    });

    if (!friendRequest && errorOnNull) {
      throw new NotFoundException(
        Errors.FriendRequest.FRIEND_REQUEST_DOESNT_EXISTS,
      );
    }

    return friendRequest;
  }

  async createFriendRequestRelations(
    senderId,
    senderStatus,
    receiverId,
    receiverStatus,
    message = '',
  ) {
    const user = await this.userService.findOneById(receiverId);
    if (!user) {
      throw new NotFoundException(`User: ${receiverId} does not exists`);
    }

    const sender = this.friendRequestRepository.create({
      sender: senderId,
      receiver: receiverId,
      friendshipStatus: senderStatus,
    });
    const receiver = this.friendRequestRepository.create({
      sender: receiverId,
      receiver: senderId,
      friendshipStatus: receiverStatus,
      message,
    });

    await this.friendRequestSaveTransaction(sender, receiver);
  }

  /*** TRANSACTIONS */
  async friendRequestSaveTransaction(
    sender: FriendRequest,
    receiver: FriendRequest,
  ) {
    const queryRunner = this.connection.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();
    let senderResponse: FriendRequest = null;
    let error: Error = null;
    try {
      senderResponse = await queryRunner.manager.save(sender);
      await queryRunner.manager.save(receiver);
      queryRunner.commitTransaction();
    } catch (e) {
      error = e;
      queryRunner.rollbackTransaction();
    } finally {
    }
  }

  async friendRequestUpdateTransaction(
    senderId: string,
    senderFriendShipStatus: FriendRequest_Status,
    receiverId: string,
    receiverFriendShipStatus: FriendRequest_Status,
    createOrEnableChatroom = false,
  ): Promise<{ status: boolean; error?: Error }> {
    const queryRunner = this.connection.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();
    try {
      await queryRunner.manager.update(
        FriendRequest,
        {
          sender: senderId,
          receiver: receiverId,
        },
        {
          friendshipStatus: senderFriendShipStatus,
        },
      );

      await queryRunner.manager.update(
        FriendRequest,
        {
          sender: receiverId,
          receiver: senderId,
        },
        {
          friendshipStatus: receiverFriendShipStatus,
        },
      );

      if (createOrEnableChatroom) {
        await this.chatroomService.findOrCreateChatroomTransaction(
          [senderId, receiverId],
          queryRunner.manager,
        );
      }
      await queryRunner.commitTransaction();
      return {
        status: true,
      };
    } catch (e) {
      await queryRunner.rollbackTransaction();
      return {
        status: false,
        error: e,
      };
    } finally {
    }
  }

  async friendRequestDeleteTransaction(senderId: string, receiverId: string) {
    const queryRunner = this.connection.createQueryRunner();
    const friendRequests = await this.friendRequestRepository.find({
      where: [
        {
          sender: { id: senderId },
          receiver: { id: receiverId },
        },
        {
          sender: { id: receiverId },
          receiver: { id: senderId },
        },
      ],
    });
    await queryRunner.connect();
    await queryRunner.startTransaction();
    let error: Error = null;
    try {
      await queryRunner.manager.remove(FriendRequest, friendRequests);
      queryRunner.commitTransaction();
    } catch (e) {
      error = e;
      queryRunner.rollbackTransaction();
      throw new BadRequestException(
        e.message,
        'We cannot delete friend request',
      );
    }
  }

  usersToFriendRequestJson(
    users: User[],
    friendRequests: FriendRequest[],
  ): any[] {
    const response = users.map((user) => {
      return {
        ...user,
        friendshipStatus: FriendRequest_Status.NOT_SENT,
      };
    });

    friendRequests.forEach((fr) => {
      const index = response.findIndex(u => u.id === fr.receiver.id);
      if (index > -1) {
        response[index].friendshipStatus = fr.friendshipStatus;
      }
    });

    return response;
  }
}
