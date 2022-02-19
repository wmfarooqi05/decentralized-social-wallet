import { ApiProperty } from '@nestjs/swagger';
import { IsNumberString, IsPhoneNumber, Length } from 'class-validator';

export class CompletePhoneLinking {
  @IsPhoneNumber()
  @ApiProperty({ type: String, description: 'phoneNumber' })
  phoneNumber: string;

  @IsNumberString()
  @Length(parseInt(process.env.OTP_LENGTH))
  @ApiProperty({ type: String, description: 'otp' })
  otp: string;
}
