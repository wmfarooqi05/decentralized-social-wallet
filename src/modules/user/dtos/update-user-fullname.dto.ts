import { IsEmail, IsString, IsOptional, IsPhoneNumber, IsEnum, IsNotEmpty, IsUUID } from 'class-validator';
import { UserStatus } from '../user.entity';
// import { UserStatus } from '../user.entity';

export class UpdateUserFullNameDto {
  @IsString()
  @IsNotEmpty()
  fullName: string;
}
