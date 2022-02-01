import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { JWT_USER_TYPE } from './jwt-payload';
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
    const jwtPayload: JWT_USER_TYPE = _.pick(payload, ["email", "name", "role"]);
    return jwtPayload;
  }
}