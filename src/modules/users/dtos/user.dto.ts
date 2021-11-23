import { Expose } from 'class-transformer';
import { Timestamp } from 'typeorm';

export class UserDto {
  @Expose()
  id: number;

  @Expose()
  email: string;

  @Expose()
  phoneNumber: string;

  @Expose()
  fullName: string;

  @Expose()
  isEmailVerified: string;

  @Expose()
  isPhoneNumberVerified: string;

  @Expose()
  userStatus: string;

  @Expose()
  role: string;

  @Expose()
  createdAt: Timestamp;

  @Expose()
  updatedAt: Timestamp;
  
}
