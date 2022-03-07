import {
  IsEmail,
  IsString,
  IsOptional,
  IsPhoneNumber,
  IsUUID,
  ValidateNested,
  ArrayMinSize,
  ArrayMaxSize,
} from 'class-validator';

const MAX_CHATROOM_SIZE = 2;

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
