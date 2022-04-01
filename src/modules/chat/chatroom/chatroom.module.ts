import { forwardRef, Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserModule } from 'src/modules/user/user.module';
import { ChatMessageModule } from '../chat-message/chat-message.module';
import { ChatMessageService } from '../chat-message/chat-message.service';
import { ChatroomController } from './chatroom.controller';
import { Chatroom } from './chatroom.entity';
import { ChatroomService } from './chatroom.service';

@Module({
  imports: [
    TypeOrmModule.forFeature([Chatroom]),
    UserModule,
    forwardRef(() => ChatMessageModule),
  ],
  controllers: [ChatroomController],
  providers: [ChatroomService],
  exports: [ChatroomService],
})
export class ChatroomModule {}
