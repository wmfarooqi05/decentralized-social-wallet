import { IsString, IsNotEmpty } from 'class-validator';
// import { UserStatus } from '../user.entity';

export class UpdateUserFullNameDto {
  @IsString()
  @IsNotEmpty()
  fullName: string;
}
