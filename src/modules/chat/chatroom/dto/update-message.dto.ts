import { Type } from 'class-transformer';
import {
  IsArray,
  IsDate,
  IsJSON,
  IsOptional,
  IsString,
  IsUUID,
  ValidateNested,
} from 'class-validator';
import { Reaction, SeenStatus, SeenStatuses } from '../../chat.types';

export class UpdateMessageDto {
  @IsString()
  @IsOptional()
  messageContent: string;

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => SeenStatusesDto)
  @IsOptional()
  seenStatuses: SeenStatuses[];

  @IsJSON()
  @IsOptional()
  reactions: Reaction[];
}

class SeenStatusesDto {
  @IsUUID('4')
  userId: string;

  // @TODO: check
  @Type(() => Date)
  @IsDate()
  updatedAt: Date;

  // @TODO: Add validator for spell check
  @IsString()
  status: SeenStatus;
}
