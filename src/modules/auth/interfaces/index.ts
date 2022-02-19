import { User } from "src/modules/user/user.entity";

export type JwtAndRefreshToken = {
    jwtToken: string;
    refreshToken: string;
}

export interface UserWithTokens extends User, JwtAndRefreshToken {}