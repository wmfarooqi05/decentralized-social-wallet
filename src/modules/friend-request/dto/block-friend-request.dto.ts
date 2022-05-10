import { ApiProperty } from '@nestjs/swagger';
import {
  IsUUID,
} from 'class-validator';

export class BlockFriendRequestDto {
  @IsUUID()
  @ApiProperty({ type: String, description: 'receiverId' })
  receiverId: string;
}
