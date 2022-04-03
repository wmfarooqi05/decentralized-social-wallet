import { IsEnum, IsOptional, IsString, IsUUID } from 'class-validator';
import { MESSAGE_TYPE_ENUM } from '../../chat.types';

export class CreateNewMessageDto {
  @IsString()
  messageContent: string;

  @IsEnum(MESSAGE_TYPE_ENUM)
  messageType: MESSAGE_TYPE_ENUM;

  @IsString()
  @IsOptional()
  messageRandomId: string;
}
