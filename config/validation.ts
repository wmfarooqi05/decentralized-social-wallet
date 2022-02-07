import * as Joi from "joi";
import { JWT_CONSTANTS } from '../src/constants/jwt';

export const validationSchema = Joi.object({
  NODE_ENV: Joi.string().valid("development", "production", "test").required(),
  TWILIO_SID: Joi.string().required(),
  TWILIO_AUTH_TOKEN:Joi.string().required(),
  TWILIO_PHONE_NO: Joi.string().required(),
  SEND_GRID_KEY: Joi.string().required(),
  AUTHENTICATION_SENDER_EMAIL: Joi.string().required(),
  TWILIO_ACCOUNT_SID: Joi.string().required(),
  TWILIO_PHONE_NUMBER: Joi.string().required(),
  OTP_LENGTH: Joi.number().required(),
  DB_HOST: Joi.string().required(),
  DB_TYPE: Joi.string().required(),
  DB_PORT: Joi.number().required(),
  DB_DATABASE_NAME: Joi.string().required(),
  SERVER_PORT: Joi.number().required(),
  DB_USERNAME: Joi.string().required(),
  DB_PASSWORD: Joi.string().required(),
  REFRESH_TOKEN_LENGTH: Joi.number().required(),
  // [JWT_CONSTANTS.PUBLIC_FULLKEY]: Joi.string().required(),
  // [JWT_CONSTANTS.PRIVATE_FULLKEY]: Joi.string().required(),
});