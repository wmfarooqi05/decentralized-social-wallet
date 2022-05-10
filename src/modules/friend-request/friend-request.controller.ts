import {
  Body,
  Controller,
  Get,
  HttpStatus,
  Param,
  Post,
  Put,
  Query,
  Req,
  Res,
} from '@nestjs/common';
import { Response } from 'express';
import { Roles } from 'src/common/modules/roles/roles.decorator';
import RequestWithUser from '../auth/interfaces/request-with-user';
import { UserRole } from '../user/user.entity';
import { AcceptFriendRequestDto } from './dto/accept-friend-request.dto';
import { SendFriendRequestDto } from './dto/send-friend-request.dto';
import { FriendRequestService } from './friend-request.service';
import { BlockFriendRequestDto } from './dto/block-friend-request.dto';
import { CancelFriendRequestDto } from './dto/cancel-friend-request.dto';
import { UnFriendRequestDto } from './dto/un-friend-request.dto';
import { ApiResponse } from '@nestjs/swagger';
import { STATUS_CODES } from 'http';

@Controller('friend-request')
export class FriendRequestController {
  constructor(private friendRequestService: FriendRequestService) {}

  @Get('/search/:queryString')
  search(
    @Req() { currentUser: { id: senderId } }: RequestWithUser,
    @Param() { queryString },
    @Query() { page, pageSize },
  ) {
    return this.friendRequestService.search(senderId, queryString, page, pageSize);
  }

  @Get()
  @ApiResponse({ status: 200, description: 'Paginated friend list'})
  async getFriendRequests(
    @Req() { currentUser: { id: senderId } }: RequestWithUser,
    @Query() { page, pageSize },
  ) {
    return this.friendRequestService.getFriendRequests(senderId, page, pageSize);
  }

  @Get('/search-friend-list/:queryString')
  @ApiResponse({ status: 200, description: 'Paginated filtered friend list'})
  searchFriendList(
    @Req() { currentUser: { id: senderId } }: RequestWithUser,
    @Param() { queryString },
    @Query() { page, pageSize },
  ) {
    return this.friendRequestService.searchFriendList(senderId, queryString, page, pageSize);
  }

  @Post('send-request')
  @Roles(UserRole.USER)
  async sendFriendRequest(
    @Req() { currentUser: { id: senderId } }: RequestWithUser,
    @Body() { receiverId, message }: SendFriendRequestDto,
  ) {
    return this.friendRequestService.sendFriendRequest(senderId, receiverId, message);
  }

  // @TODO Put comments and verify sender vs receiver entity
  @Put('accept-request')
  @Roles(UserRole.USER)
  async acceptFriendRequest(
    @Req() { currentUser: { id: receiverId } }: RequestWithUser,
    @Body() { senderId }: AcceptFriendRequestDto,
    @Res() res: Response,
  ) {
    await this.friendRequestService.acceptFriendRequest(senderId, receiverId);
    res.sendStatus(HttpStatus.OK);
  }

  @Post('cancel-request')
  @Roles(UserRole.USER)
  async cancelFriendRequest(
    @Req() { currentUser: { id: senderId } }: RequestWithUser,
    @Res() res: Response,
    @Body() { receiverId }: CancelFriendRequestDto,
  ): Promise<void> {
    await this.friendRequestService.cancelSentFriendRequest(
      senderId,
      receiverId,
    );

    res.status(HttpStatus.OK).send();
  }

  @Post('block-friend')
  @Roles(UserRole.USER)
  async blockFriend(
    @Req() { currentUser: { id: senderId } }: RequestWithUser,
    @Res() res: Response,
    @Body() { receiverId }: BlockFriendRequestDto,
  ) {
    await this.friendRequestService.blockFriend(senderId, receiverId);

    res.status(HttpStatus.OK).send();
  }

  @Post('unblock-friend')
  @Roles(UserRole.USER)
  async unblockFriend(
    @Req() { currentUser: { id: senderId } }: RequestWithUser,
    @Res() res: Response,
    @Body() { receiverId }: BlockFriendRequestDto,
  ) {
    await this.friendRequestService.unblockFriend(senderId, receiverId);

    res.status(HttpStatus.OK).send();
  }

  @Post('un-friend')
  @Roles(UserRole.USER)
  async unFriend(
    @Req() { currentUser: { id: senderId } }: RequestWithUser,
    @Res() res: Response,
    @Body() { receiverId }: UnFriendRequestDto,
  ) {
    await this.friendRequestService.unFriend(senderId, receiverId);

    res.status(HttpStatus.OK).send();
  }
}
