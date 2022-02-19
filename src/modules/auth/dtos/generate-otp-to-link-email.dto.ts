import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, ValidateIf } from 'class-validator';

export class GenerateOtpToLinkEmail {
  @IsEmail()
  @ValidateIf(o => o.email || !o.phoneNumber)
  @ApiProperty({ type: String, description: 'email' })
  email: string;
}