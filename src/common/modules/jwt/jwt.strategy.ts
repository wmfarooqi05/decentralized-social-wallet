import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { IUser_Jwt, IUser_Jwt_Keys } from './jwt-payload.interface';
import * as _ from "lodash";
import { JWT_CONSTANTS } from 'src/constants/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get(JWT_CONSTANTS.PUBLIC_FULLKEY),
      algorithms: ['RS256'],
    });
  }
  

  async validate(payload: any) {
    const jwtPayload: IUser_Jwt = _.pick(payload, IUser_Jwt_Keys);
    return jwtPayload;
  }
}