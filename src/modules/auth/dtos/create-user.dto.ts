import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsOptional, IsPhoneNumber, IsString, ValidateIf } from 'class-validator';

export class CreateUserDto {

  @ValidateIf(o => o.email || !o.phoneNumber)
  @IsEmail()
  @ApiProperty({ type: String, description: 'email' })
  email: string;

  @ValidateIf(o => !o.email || o.phoneNumber)
  @IsPhoneNumber()
  @ApiProperty({ type: String, description: 'phoneNumber' })
  phoneNumber: string;

  @IsString()
  @ApiProperty({ type: String, description: 'password' })
  password: string;

  @IsString()
  @ApiProperty({ type: String, description: 'Full Name' })
  fullName: string;
}
