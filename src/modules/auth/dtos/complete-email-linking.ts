import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNumberString, Length } from 'class-validator';

export class CompleteEmailLinking {
  @IsEmail()
  @ApiProperty({ type: String, description: 'email' })
  email: string;

  @IsNumberString()
  @Length(parseInt(process.env.OTP_LENGTH))
  @ApiProperty({ type: String, description: 'otp' })
  otp: string;
}
