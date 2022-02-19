import { UnauthorizedException } from '@nestjs/common';
import * as Joi from 'joi';
import { USERNAME_REGEX } from 'src/constants/auth';
import { UserRole, UserStatus } from 'src/modules/user/user.entity';
import { IUserJwt } from './jwt-payload.interface';

export const validateUserJwt = (jwt: IUserJwt): void => {
  const schema: Joi.Schema = Joi.object().keys({
    username: Joi.string().regex(USERNAME_REGEX).required().label('username'),
    fullName: Joi.string().label('fullName').allow(null),
    role: Joi.string()
      .valid(...Object.values(UserRole))
      .required()
      .label('role'),
    userStatus: Joi.string()
      .valid(...Object.values(UserStatus))
      .required()
      .label('userStatus'),
  });

  const result = schema.validate(jwt, { allowUnknown: true, abortEarly: true });

  if (result.error) {
    throw new UnauthorizedException('Invalid Jwt Payload');
  }
};
