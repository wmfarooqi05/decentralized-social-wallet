import {
  Body,
  Controller,
  Get,
  HttpStatus,
  Param,
  Post,
  Put,
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

@Controller('friend-request')
export class FriendRequestController {
  constructor(private friendRequestService: FriendRequestService) {}

  @Get()
  async getFriendRequests(
    @Req() { currentUser: { id: senderId } }: RequestWithUser,
  ) {
    return this.friendRequestService.getFriendRequests(senderId);
  }

  @Get('/search-friend-list/:queryString')
  searchFriendList(
    @Req() { currentUser: { id: sender } }: RequestWithUser,
    @Param() { queryString },
  ) {
    return this.friendRequestService.searchFriendList(sender, queryString);
  }

  @Post('send-request')
  @Roles(UserRole.USER)
  async sendFriendRequest(
    @Req() { currentUser: { id: senderId } }: RequestWithUser,
    @Body() { receiverId }: SendFriendRequestDto,
  ) {
    return this.friendRequestService.sendFriendRequest(senderId, receiverId);
  }

  @Put('accept-request')
  @Roles(UserRole.USER)
  async acceptFriendRequest(
    @Req() { currentUser: { id: receiverId } }: RequestWithUser,
    @Body() { senderId }: AcceptFriendRequestDto,
    @Res() res: Response,
  ) {
    const { status, error } =
      await this.friendRequestService.acceptFriendRequest(senderId, receiverId);

    if (status) {
      res.status(HttpStatus.OK).send();
    } else {
      res.status(HttpStatus.INTERNAL_SERVER_ERROR).json(error.message);
    }
  }

  @Post('cancel-request')
  @Roles(UserRole.USER)
  async cancelFriendRequest(
    @Req() { currentUser: { id: senderId } }: RequestWithUser,
    @Res() res: Response,
    @Body() { receiverId }: SendFriendRequestDto,
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
    @Body() { receiverId }: SendFriendRequestDto,
  ) {
    await this.friendRequestService.blockFriend(senderId, receiverId);

    res.status(HttpStatus.OK).send();
  }

  @Post('un-friend')
  @Roles(UserRole.USER)
  async unFriend(
    @Req() { currentUser: { id: senderId } }: RequestWithUser,
    @Res() res: Response,
    @Body() { receiverId }: SendFriendRequestDto,
  ) {
    await this.friendRequestService.unFriend(senderId, receiverId);

    res.status(HttpStatus.OK).send();
  }
}
