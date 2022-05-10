import { ApiProperty } from '@nestjs/swagger';
import {
  IsUUID,
} from 'class-validator';

export class UnFriendRequestDto {
  @IsUUID()
  @ApiProperty({ type: String, description: 'receiverId' })
  receiverId: string;
}
