import { ApiProperty } from '@nestjs/swagger';
import {
  IsString,
  Matches,
  IsNumberString,
  Length,
  
} from 'class-validator';
import { USERNAME_REGEX } from 'src/constants/auth';

export class SigninDTO {
  @IsString()
  @Matches(USERNAME_REGEX, {
    message: 'Username not valid'
  })
  @ApiProperty({ type: String, description: 'username' })
  username: string;

  @IsNumberString()
  @Length(parseInt(process.env.OTP_LENGTH))
  @ApiProperty({ type: String, description: 'otp' })
  otp: string;

  @IsString()
  @ApiProperty({ type: String, description: 'public-key' })
  publicKey: string;
}
