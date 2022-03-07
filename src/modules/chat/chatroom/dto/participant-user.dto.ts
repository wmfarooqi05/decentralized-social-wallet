import { IsUUID } from 'class-validator';

export class ParticipantUserDto {
  @IsUUID('4')
  chatroomId: string;

  @IsUUID('4')
  participantId: string;
}
