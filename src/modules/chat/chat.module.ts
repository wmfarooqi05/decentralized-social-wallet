import { Module } from '@nestjs/common';
import { ChatGateway } from './chat.gateway';
// import { ChatroomController } from './chatroom/chatroom.controller';
// import { ChatroomService } from './chatroom/chatroom.service';
import { ChatroomModule } from './chatroom/chatroom.module';
import { ChatMessageModule } from './chat-message/chat-message.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ChatMessage } from './chat-message/chat-message.entity';
import { ChatMessageController } from './chat-message/chat-message.controller';
import { ChatMessageService } from './chat-message/chat-message.service';
import { Chatroom } from './chatroom/chatroom.entity';
import { UserModule } from '../user/user.module';
import { ChatroomController } from './chatroom/chatroom.controller';
import { ChatroomService } from './chatroom/chatroom.service';
import { SocketService } from './socket.service';

@Module({
  imports: [TypeOrmModule.forFeature([ChatMessage, Chatroom]), UserModule],
  controllers: [ChatMessageController, ChatroomController],
  providers: [ChatMessageService, ChatroomService, ChatGateway, SocketService],
  exports: [ChatMessageService, ChatroomService],
})
export class ChatModule {}
