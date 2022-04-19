import {
  Injectable,
  NotFoundException,
  UnprocessableEntityException,
} from '@nestjs/common';
import { InjectConnection, InjectRepository } from '@nestjs/typeorm';
import { paginationHelper } from 'src/common/helpers/pagination';
import {
  Connection,
  FindOptionsWhere,
  Like,
  Not,
} from 'typeorm';

import { Repository } from 'typeorm';
import { FriendRequest, FriendRequest_Status } from './friend-request.entity';

@Injectable()
export class FriendRequestService {
  constructor(
    @InjectRepository(FriendRequest)
    private friendRequestRepository: Repository<FriendRequest>,
    @InjectConnection() private connection: Connection,
  ) {}

  async getFriendRequests(senderId: string, page = null, pageSize = null) {
    const { skip, take } = paginationHelper(page, pageSize);
    // @TODO: add pagination

    const order: any = {
      updatedAt: "ASC",
    }
    return this.friendRequestRepository.find({
      where: {
        sender: {id: senderId },
        friendshipStatus: Not(FriendRequest_Status.BLOCKED_BY_OTHER_USER),
      },
      skip,
      take,
      order,
    });
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

  async sendFriendRequest(senderId: string, receiverId: string) {
    const exists = await this.friendRequestRepository.findOne({
      where: {
        sender: { id: senderId },
        receiver: { id: receiverId },
      },
    });

    if (exists) {
      if (
        exists.friendshipStatus ===
        FriendRequest_Status.WAITING_FOR_CURRENT_USER_RESPONSE
      ) {
        throw new UnprocessableEntityException('Friend Request alreadt sent');
      }

      if (exists.friendshipStatus === FriendRequest_Status.PENDING) {
        // Accept the request instead?
      }
      // @TODO: check if status is blocked or something
      // Update status
    }

    return this.createFriendRequestRelations(
      senderId,
      FriendRequest_Status.WAITING_FOR_CURRENT_USER_RESPONSE,
      receiverId,
      FriendRequest_Status.PENDING,
    );
  }

  async acceptFriendRequest(
    senderId: string,
    receiverId: string,
    status: FriendRequest_Status,
  ) {
    // @TODO
    // check if user is on accepting end
    const friendRequestReceiver = await this.friendRequestRepository.findOne({
      where: {
        sender: { id: senderId },
        receiver: { id: receiverId },
      },
    });

    if (
      friendRequestReceiver.friendshipStatus === FriendRequest_Status.PENDING
    ) {
      friendRequestReceiver.friendshipStatus = FriendRequest_Status.ACCEPTED;

      const friendRequestCreator = await this.friendRequestRepository.findOne({
        where: {
          sender: { id: receiverId },
          receiver: { id: senderId },
        },
      });

      friendRequestReceiver.friendshipStatus = FriendRequest_Status.ACCEPTED;
      return this.friendRequestSaveTransaction(
        friendRequestReceiver,
        friendRequestCreator,
      );
    }
  }

  async cancelSentFriendRequest(senderId: string, receiverId: string) {
    const sentFriendRequest = await this.friendRequestRepository.findOne({
      where: {
        sender: { id: senderId},
        receiver: { id: receiverId},
      },
    });

    if (!sentFriendRequest) {
      throw new NotFoundException("Friend Request doesn't exist");
    }
    if (
      sentFriendRequest.friendshipStatus ===
      FriendRequest_Status.WAITING_FOR_CURRENT_USER_RESPONSE
    ) {
      const receivedFriendRequest = await this.friendRequestRepository.findOne({
        where: {
          sender: { id: receiverId },
          receiver: { id: senderId },
        },
      });

      this.friendRequestDeleteTransaction(
        sentFriendRequest,
        receivedFriendRequest,
      );
    } else {
      throw new UnprocessableEntityException(
        `Friend Request cannot be cancelled, Status: ${sentFriendRequest.friendshipStatus}`,
      );
    }
  }

  async blockFriend(senderId: string, receiverId: string) {
    const senderFriendRequest = await this.friendRequestRepository.findOne({
      where: {
        sender: { id: senderId},
        receiver: { id: receiverId},
      },
    });

    if (
      senderFriendRequest?.friendshipStatus ===
      FriendRequest_Status.BLOCKED_BY_OTHER_USER
    ) {
      throw new UnprocessableEntityException('Already blocked by other user');
    }

    if (senderFriendRequest) {
      senderFriendRequest.friendshipStatus = FriendRequest_Status.BLOCKED_BY_ME;
      const receivedFriendRequest = await this.friendRequestRepository.findOne({
        where: {
          sender: { id: receiverId },
          receiver: { id: senderId },
        },
      });
      receivedFriendRequest.friendshipStatus =
        FriendRequest_Status.BLOCKED_BY_OTHER_USER;

      await this.friendRequestUpdateTransaction(
        senderFriendRequest,
        receivedFriendRequest,
      );
    } else {
      return this.createFriendRequestRelations(
        senderId,
        FriendRequest_Status.BLOCKED_BY_ME,
        receiverId,
        FriendRequest_Status.BLOCKED_BY_OTHER_USER,
      );
    }
  }

  async unFriend(senderId: string, receiverId: string) {
    const senderFriendRequest = await this.friendRequestRepository.findOne({
      where: {
        sender: { id: senderId},
        receiver: { id: receiverId},
      },
    });

    if (
      senderFriendRequest?.friendshipStatus ===
      FriendRequest_Status.BLOCKED_BY_OTHER_USER
    ) {
      throw new UnprocessableEntityException('Already blocked by other user');
    }

    if (senderFriendRequest) {
      senderFriendRequest.friendshipStatus = FriendRequest_Status.NOT_SENT;
      const receivedFriendRequest = await this.friendRequestRepository.findOne({
        where: {
          sender: { id: receiverId },
          receiver: { id: senderId },
        },
      });
      receivedFriendRequest.friendshipStatus = FriendRequest_Status.NOT_SENT;

      await this.friendRequestUpdateTransaction(
        senderFriendRequest,
        receivedFriendRequest,
      );
    } else {
      throw new NotFoundException('You are not friend with this user');
    }
  }

  /*** HELPERS */

  async createFriendRequestRelations(
    senderId,
    senderStatus,
    receiverId,
    receiverStatus,
  ) {
    const sender = this.friendRequestRepository.create({
      sender: senderId,
      receiver: receiverId,
      friendshipStatus: senderStatus,
    });
    const receiver = this.friendRequestRepository.create({
      sender: receiverId,
      receiver: senderId,
      friendshipStatus: receiverStatus,
    });

    return this.friendRequestSaveTransaction(sender, receiver);
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
    sender: FriendRequest,
    receiver: FriendRequest,
  ) {
    const queryRunner = this.connection.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();
    let senderResponse = null;
    let error: Error = null;
    try {
      senderResponse = await queryRunner.manager.update(
        FriendRequest,
        {
          sender: sender.sender,
          receiver: sender.receiver,
        },
        {
          ...sender,
        },
      );

      await queryRunner.manager.update(
        FriendRequest,
        {
          sender: receiver.sender,
          receiver: receiver.receiver,
        },
        {
          ...receiver,
        },
      );
      await queryRunner.commitTransaction();
    } catch (e) {
      error = e;
      await queryRunner.rollbackTransaction();
    } finally {
    }

    return senderResponse;
  }

  async friendRequestDeleteTransaction(
    sender: FriendRequest,
    receiver: FriendRequest,
  ) {
    const queryRunner = this.connection.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();
    let error: Error = null;
    try {
      await queryRunner.manager.remove([sender, receiver]);
      queryRunner.commitTransaction();
    } catch (e) {
      error = e;
      queryRunner.rollbackTransaction();
      throw new UnprocessableEntityException(
        e.message,
        'We cannot delete friend request',
      );
    }
  }
}
