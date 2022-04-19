import { ApiProperty } from '@nestjs/swagger';
import {
    IsEnum,
  IsUUID,
} from 'class-validator';
import { FriendRequest_Status } from '../friend-request.entity';

export class AcceptFriendRequestDto {
  @IsUUID()
  @ApiProperty({ type: String, description: 'receiverId' })
  senderId: string;
}
