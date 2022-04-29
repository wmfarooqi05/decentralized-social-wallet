import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ChatroomModule } from '../chat/chatroom/chatroom.module';
import { UserModule } from '../user/user.module';
import { FriendRequestController } from './friend-request.controller';
import { FriendRequest } from './friend-request.entity';
import { FriendRequestService } from './friend-request.service';

@Module({
  imports: [
    TypeOrmModule.forFeature([FriendRequest]),
    UserModule,
    ChatroomModule,
  ],
  controllers: [FriendRequestController],
  providers: [FriendRequestService],
  exports: [FriendRequestService],
})
export class FriendRequestModule {}
