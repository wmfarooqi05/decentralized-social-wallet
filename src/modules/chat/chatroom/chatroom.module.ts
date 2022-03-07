import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserModule } from 'src/modules/user/user.module';
import { ChatMessageModule } from '../chat-message/chat-message.module';
import { ChatroomController } from './chatroom.controller';
import { Chatroom } from './chatroom.entity';
import { ChatroomService } from './chatroom.service';

@Module({
  imports: [
    TypeOrmModule.forFeature([Chatroom]),
    UserModule,
    ChatMessageModule,
  ],
  controllers: [ChatroomController],
  providers: [ChatroomService],
})
export class ChatroomModule {}
