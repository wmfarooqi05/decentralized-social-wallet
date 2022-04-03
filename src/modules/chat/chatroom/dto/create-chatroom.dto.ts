import { IsString, IsOptional, IsUUID } from 'class-validator';

export class CreateChatroomDto {
  @IsString()
  @IsOptional()
  name: string;

  @IsString()
  @IsOptional()
  icon: string;

  //   @ArrayMinSize(2)
  //   @ArrayMaxSize(MAX_CHATROOM_SIZE)
  @IsUUID('4', { each: true })
  participants: [string];
}
