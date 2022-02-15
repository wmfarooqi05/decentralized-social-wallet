import { Expose } from 'class-transformer';
import { Timestamp } from 'typeorm';

export class UserDto {
  @Expose()
  id: string;

  @Expose()
  email: string;

  @Expose()
  phoneNumber: string;

  @Expose()
  fullName: string;

  @Expose()
  isEmailVerified: boolean;

  @Expose()
  isPhoneNumberVerified: boolean;

  @Expose()
  userStatus: string;

  @Expose()
  role: string;

  @Expose()
  createdAt: Timestamp;

  @Expose()
  updatedAt: Timestamp;
  
}
