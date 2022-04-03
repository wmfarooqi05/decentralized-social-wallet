import { IsString, IsUUID } from 'class-validator';

export class CompleteSignupWithDTO {
  @IsUUID('4')
  userId: string;

  @IsString()
  otp: string;
}
