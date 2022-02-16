import { User } from "src/modules/user/user.entity";

export type JWT_VALID_KEYS = 'username' | 'fullName' | 'role' | 'userStatus'
export type IUser_Jwt = Pick<User, JWT_VALID_KEYS>;
export const IUser_Jwt_Keys: JWT_VALID_KEYS[] = ['username', 'fullName', 'role', 'userStatus'];