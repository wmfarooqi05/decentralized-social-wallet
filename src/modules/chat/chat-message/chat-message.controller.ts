import { Body, Controller, Delete, Param, Put, Req, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from 'src/common/modules/jwt/jwt-auth.guard';
import RequestWithUser from 'src/modules/auth/interfaces/request-with-user';
import { ChatMessageService } from './chat-message.service';

// @TODO: All of the messages attributes are private
// and mainly should be accessable through chatroom controller
@Controller('messages')
export class ChatMessageController {
  constructor(private chatMessageService: ChatMessageService) {}

}
