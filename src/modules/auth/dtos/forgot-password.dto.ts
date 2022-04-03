import { ApiProperty } from '@nestjs/swagger';
import { IsPhoneNumber, IsEmail, ValidateIf } from 'class-validator';

export class ForgotPasswordDto {
  @IsPhoneNumber()
  @ValidateIf((o) => !o.email || o.phoneNumber)
  @ApiProperty({ type: String, description: 'phoneNumber' })
  phoneNumber: string;

  @IsEmail()
  @ValidateIf((o) => o.email || !o.phoneNumber)
  @ApiProperty({ type: String, description: 'email' })
  email: string;
}
