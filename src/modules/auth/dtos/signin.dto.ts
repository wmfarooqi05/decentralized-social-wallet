import { ApiProperty } from '@nestjs/swagger';
import {
  IsPhoneNumber,
  IsEmail,
  IsString,
  ValidateIf,
} from 'class-validator';

export class SigninDTO {
  @IsPhoneNumber()
  @ValidateIf((o) => !o.email || o.phoneNumber)
  @ApiProperty({ type: String, description: 'phoneNumber' })
  phoneNumber: string;

  @IsEmail()
  @ValidateIf((o) => o.email || !o.phoneNumber)
  @ApiProperty({ type: String, description: 'email' })
  email: string;

  @IsString()
  @ApiProperty({ type: String, description: 'password' })
  password: string;
}
