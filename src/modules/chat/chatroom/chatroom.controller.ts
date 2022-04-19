import {
  Body,
  Controller,
  Delete,
  Get,
  HttpStatus,
  Param,
  Post,
  Put,
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { Response } from 'express';
import { PaginationDto } from 'src/common/dto/PaginationDto';
import { JwtAuthGuard } from 'src/common/modules/jwt/jwt-auth.guard';
import { Roles } from 'src/common/modules/roles/roles.decorator';
import RequestWithUser from 'src/modules/auth/interfaces/request-with-user';
import { UserRole } from 'src/modules/user/user.entity';
import { ChatroomService } from './chatroom.service';
import { CreateChatroomDto } from './dto/create-chatroom.dto';

@Controller('chatrooms')
export class ChatroomController {
  constructor(private chatroomService: ChatroomService) {}

  @Get('/all')
  @UseGuards(JwtAuthGuard)
  @Roles(UserRole.ADMIN)
  findAllChatrooms(@Query() { page, pageSize }) {
    return this.chatroomService.findAllChatrooms(page, pageSize);
  }

  @Get('/:chatroomId')
  @UseGuards(JwtAuthGuard)
  @Roles(UserRole.ADMIN, UserRole.USER)
  findChatroomById(@Req() { user }: RequestWithUser, @Param() { chatroomId }) {
    return this.chatroomService.findChatroomById(chatroomId, user);
  }

  @Get('/:chatroomId/messages')
  @UseGuards(JwtAuthGuard)
  findMessagesByChatroomId(
    @Query() { page, pageSize }: PaginationDto,
    @Param() { chatroomId },
  ) {
    return this.chatroomService.findMessagesByChatroomId(
      chatroomId,
      page,
      pageSize,
    );
  }

  @Get()
  @UseGuards(JwtAuthGuard)
  findAllChatroomsByUser(
    @Req() { user }: RequestWithUser,
    @Query() { page, pageSize },
  ) {
    return this.chatroomService.findAllChatroomsByUser(
      user.id,
      page,
      pageSize,
    );
  }

  @Post('/find-or-create')
  @UseGuards(JwtAuthGuard)
  findOrCreateChatroom(
    @Req() { user }: RequestWithUser,
    @Body() { name, icon, participants }: CreateChatroomDto,
  ) {
    return this.chatroomService.findOrCreateChatroom(
      user.username,
      participants,
      name,
      icon,
    );
  }

  @Put('/:chatroomId/add-participant/:participantId')
  @UseGuards(JwtAuthGuard)
  async addParticipantToChatroom(
    @Req() { user }: RequestWithUser,
    @Res() res: Response,
    @Param() { chatroomId, participantId },
  ) {
    const updatedChatroom = await this.chatroomService.addParticipantToChatroom(
      user,
      participantId,
      chatroomId,
    );
    res.status(HttpStatus.CREATED).json(updatedChatroom);
  }

  @Delete('/:chatroomId/messages/:messageId')
  @UseGuards(JwtAuthGuard)
  async deleteMessageFromChatroom(
    @Req() { user }: RequestWithUser,
    @Param() { chatroomId, messageId },
  ) {
    return this.chatroomService.deleteMessageFromChatroom(
      chatroomId,
      user.username,
      messageId,
    );
  }

  /******* DEV TEST *********/

  @Post('/:chatroomId/message')
  @UseGuards(JwtAuthGuard)
  addNewMessage(
    @Req() { user }: RequestWithUser,
    @Param() { chatroomId },
  ) {
    return this.chatroomService.addNewMessageViaQueue(chatroomId, user);
  }

  @Put('/:chatroomId/messages')
  @UseGuards(JwtAuthGuard)
  async updateMessage(
    @Req() { user }: RequestWithUser,
    @Param() { chatroomId },
  ) {
    return this.chatroomService.updateMessageViaQueue(chatroomId, user);
  }

}
