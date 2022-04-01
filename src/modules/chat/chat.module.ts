import { Module } from '@nestjs/common';
import { ChatGateway } from './socket/chat.gateway';
import { SocketService } from './socket.service';
import { ChatQueueService } from './redis/chat-queue.service';
import { BullModule } from '@nestjs/bull';
import { ChatDBQueueConsumer } from './redis/chat-queue.processor';
import{ChatMessageModule } from './chat-message/chat-message.module';
import { ChatroomModule } from './chatroom/chatroom.module';
@Module({
  imports: [
    BullModule.registerQueue({
      name: 'CHAT_QUEUE',
    }),
    ChatMessageModule,
    ChatroomModule,
  ],
  controllers: [],
  providers: [
    ChatGateway,
    SocketService,
    ChatQueueService,
    ChatDBQueueConsumer,
  ],
})
export class ChatModule {}
