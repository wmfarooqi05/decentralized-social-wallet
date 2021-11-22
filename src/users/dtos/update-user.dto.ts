import { IsString, IsOptional, IsPhoneNumber } from 'class-validator';

export class UpdateUserDto {

  @IsPhoneNumber()
  @IsOptional()
  phoneNumber: string;
  
  @IsString()
  @IsOptional()
  password: string;
}
