import { ApiProperty } from '@nestjs/swagger';
import {
  IsPhoneNumber,
  IsOptional,
  IsEmail,
  IsString,
  ValidateIf,
} from 'class-validator';

export class UpdatePasswordDto {
  @IsPhoneNumber()
  @ValidateIf((o) => !o.email || o.phoneNumber)
  @ApiProperty({ type: String, description: 'phoneNumber' })
  phoneNumber: string;

  @IsEmail()
  @ValidateIf((o) => o.email || !o.phoneNumber)
  @ApiProperty({ type: String, description: 'email' })
  email: string;

  @IsString()
  @ApiProperty({ type: String, description: 'oldPassword' })
  oldPassword: string;

  @IsString()
  @ApiProperty({ type: String, description: 'newPassword' })
  newPassword: string;
}
