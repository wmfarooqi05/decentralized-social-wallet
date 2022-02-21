export const configuration = () => {
  return {
    NODE_ENV: process.env.NODE_ENV,
    TWILIO_SID: process.env.TWILIO_SID,
    TWILIO_AUTH_TOKEN: process.env.TWILIO_AUTH_TOKEN,
    TWILIO_PHONE_NO: process.env.TWILIO_PHONE_NO,
    SEND_GRID_KEY: process.env.SEND_GRID_KEY,
    AUTHENTICATION_SENDER_EMAIL: process.env.AUTHENTICATION_SENDER_EMAIL,
    TWILIO_ACCOUNT_SID: process.env.TWILIO_ACCOUNT_SID,
    TWILIO_PHONE_NUMBER: process.env.TWILIO_PHONE_NUMBER,
    OTP_LENGTH: process.env.OTP_LENGTH,
    DB_HOST: process.env.DB_HOST,
    DB_TYPE: process.env.DB_TYPE,
    DB_PORT: process.env.DB_PORT,
    DB_DATABASE_NAME: process.env.DB_DATABASE_NAME,
    SERVER_PORT: process.env.SERVER_PORT,
    DB_USERNAME: process.env.DB_USERNAME,
    DB_PASSWORD: process.env.DB_PASSWORD,
    REFRESH_TOKEN_LENGTH: process.env.REFRESH_TOKEN_LENGTH,
    GOOGLE_STORAGE_MEDIA_BUCKET: process.env.GOOGLE_STORAGE_MEDIA_BUCKET,
    BUGSNAG_ACCOUNT_API_KEY: process.env.BUGSNAG_ACCOUNT_API_KEY,
  };
};
