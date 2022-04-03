import { ApiProperty } from '@nestjs/swagger';
import {
  IsPhoneNumber,
  IsOptional,
  IsEmail,
  IsString,
  ValidateIf,
} from 'class-validator';

export class ChangePasswordDTO {
  @IsString()
  @ValidateIf((o) => !o.otp || o.oldPassword)
  @ApiProperty({ type: String, description: 'phoneNumber' })
  oldPassword: string;

  @IsString()
  @ApiProperty({ type: String, description: 'email' })
  newPassword: string;
}
