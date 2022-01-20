import { Expose } from 'class-transformer';
import { IsPhoneNumber, IsOptional, IsEmail } from 'class-validator';

export class UpdatePasswordDto {
  @IsPhoneNumber()
  @IsOptional()
  phoneNumber: string;
  
  @IsEmail()
  @IsOptional()
  email: string;
}