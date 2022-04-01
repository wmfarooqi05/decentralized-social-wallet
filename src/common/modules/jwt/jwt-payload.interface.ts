import { JwtPayload } from "jsonwebtoken";
import { User } from "src/modules/user/user.entity";

export type JWT_VALID_KEYS = 'id' | 'username' | 'fullName' | 'role' | 'userStatus'
export interface IUserJwt extends JwtPayload, Pick<User, JWT_VALID_KEYS> {}
export const IUser_Jwt_Keys: JWT_VALID_KEYS[] = ['id', 'username', 'fullName', 'role', 'userStatus'];
