import { forwardRef, Module } from '@nestjs/common';
import { ChatMessageService } from './chat-message.service';
import { ChatMessageController } from './chat-message.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ChatMessage } from './chat-message.entity';
import { ChatroomModule } from '../chatroom/chatroom.module';
import { UserModule } from 'src/modules/user/user.module';
import { GoogleCloudService } from 'src/common/services/google-cloud/google-cloud.service';

@Module({
  imports: [
    TypeOrmModule.forFeature([ChatMessage]),
    forwardRef(() => ChatroomModule),
    UserModule,
  ],
  controllers: [ChatMessageController],
  providers: [ChatMessageService, GoogleCloudService],
  exports: [ChatMessageService],
})
export class ChatMessageModule {}
