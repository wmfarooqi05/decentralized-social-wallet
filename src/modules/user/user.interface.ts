import { UserRole, UserStatus } from './user.entity';

export interface IUser {
  id: number;
  email: string;
  phoneNumber: string;
  password: string;
  fullName: string;
  image?: string;
  isEmailVerified: boolean;
  isPhoneNumberVerified: boolean;
  role: UserRole;
  userStatus: UserStatus;
  createdAt: Date;
  updatedAt: Date;
}
