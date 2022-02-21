import * as Joi from 'joi';
import { JWT_CONSTANTS } from '../src/constants/jwt';

export const validationSchema = Joi.object({
  NODE_ENV: Joi.string().valid('development', 'production', 'test').required(),
  TWILIO_SID: Joi.string().required().label('TWILIO_SID'),
  TWILIO_AUTH_TOKEN: Joi.string().required().label('TWILIO_AUTH_TOKEN'),
  TWILIO_PHONE_NO: Joi.string().required().label('TWILIO_PHONE_NO'),
  SEND_GRID_KEY: Joi.string().required().label('SEND_GRID_KEY'),
  AUTHENTICATION_SENDER_EMAIL: Joi.string()
    .required()
    .label('AUTHENTICATION_SENDER_EMAIL'),
  TWILIO_ACCOUNT_SID: Joi.string().required().label('TWILIO_ACCOUNT_SID'),
  TWILIO_PHONE_NUMBER: Joi.string().required().label('TWILIO_PHONE_NUMBER'),
  OTP_LENGTH: Joi.number().required().label('OTP_LENGTH'),
  DB_HOST: Joi.string().required().label('DB_HOST'),
  DB_TYPE: Joi.string().required().label('DB_TYPE'),
  DB_PORT: Joi.number().required().label('DB_PORT'),
  DB_DATABASE_NAME: Joi.string().required().label('DB_DATABASE_NAME'),
  SERVER_PORT: Joi.number().required().label('SERVER_PORT'),
  DB_USERNAME: Joi.string().required().label('DB_USERNAME'),
  DB_PASSWORD: Joi.string().required().label('DB_PASSWORD'),
  REFRESH_TOKEN_LENGTH: Joi.number().required().label('REFRESH_TOKEN_LENGTH'),
  GOOGLE_STORAGE_MEDIA_BUCKET: Joi.string()
    .required()
    .label('GOOGLE_STORAGE_MEDIA_BUCKET'),
  BUGSNAG_ACCOUNT_API_KEY: Joi.string()
    .required()
    .label('BUGSNAG_ACCOUNT_API_KEY'),
  // [JWT_CONSTANTS.PUBLIC_FULLKEY]: Joi.string().required(),
  // [JWT_CONSTANTS.PRIVATE_FULLKEY]: Joi.string().required(),
});
