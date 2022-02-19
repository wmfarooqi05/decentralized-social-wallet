import { ApiProperty } from '@nestjs/swagger';
import { IsPhoneNumber, ValidateIf } from 'class-validator';

export class GenerateOtpToLinkPhone {
  @IsPhoneNumber()
  @ValidateIf(o => !o.email || o.phoneNumber)
  @ApiProperty({ type: String, description: 'phoneNumber' })
  phoneNumber: string;
}