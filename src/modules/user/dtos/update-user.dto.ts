import {
  IsEmail,
  IsString,
  IsOptional,
  IsPhoneNumber,
  IsEnum,
} from 'class-validator';
import { UserStatus } from '../user.entity';
// import { UserStatus } from '../user.entity';

export class UpdateUserDto {
  @IsPhoneNumber()
  @IsOptional()
  phoneNumber: string;

  @IsEmail()
  @IsOptional()
  email: string;

  @IsString()
  @IsOptional()
  password: string;

  @IsOptional()
  fullName: string;

  @IsOptional()
  isEmailVerified: boolean;

  @IsOptional()
  isPhoneNumberVerified: boolean;
}
