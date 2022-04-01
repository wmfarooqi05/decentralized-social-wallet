import {
  Body,
  Controller,
  Post,
} from '@nestjs/common';
import { ChatMessageService } from './chat-message.service';

// @TODO: All of the messages attributes are private
// and mainly should be accessable through chatroom controller
@Controller('messages')
export class ChatMessageController {
  constructor(private chatMessageService: ChatMessageService) {}

  @Post('/chatmessages')
  async addMessages(
    @Body() { messages, seenStatus, currentRoomId, acknowledingUser },
  ) {
    await this.chatMessageService.updateMessageStatusesBulk(
      messages,
      seenStatus,
      currentRoomId,
      acknowledingUser,
    );
  }
}
