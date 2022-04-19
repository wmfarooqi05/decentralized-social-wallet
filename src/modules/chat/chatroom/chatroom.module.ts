import { BullModule } from '@nestjs/bull';
import { forwardRef, Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserModule } from 'src/modules/user/user.module';
import { ChatMessageModule } from '../chat-message/chat-message.module';
import { ChatMessageService } from '../chat-message/chat-message.service';
import { ChatQueueService } from '../redis/chat-queue.service';
import { ChatroomController } from './chatroom.controller';
import { Chatroom } from './chatroom.entity';
import { ChatroomService } from './chatroom.service';
import { ChatDBQueueConsumer } from '../redis/chat-queue.processor';

@Module({
  imports: [
    // @TODO Bull Module is only for DEV test via postman
    BullModule.registerQueue({
      name: 'CHAT_QUEUE',
    }),
    TypeOrmModule.forFeature([Chatroom]),
    UserModule,
    forwardRef(() => ChatMessageModule),
  ],
  controllers: [ChatroomController],
  providers: [ChatroomService, ChatQueueService],
  exports: [ChatroomService],
})
export class ChatroomModule {}
