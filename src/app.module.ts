import { Module, ValidationPipe, MiddlewareConsumer } from '@nestjs/common';
import { APP_GUARD, APP_PIPE } from '@nestjs/core';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TwilioModule } from 'nestjs-twilio';
import { BugsnagModule } from 'nest-bugsnag';

import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UserModule } from './modules/user/user.module';
import { CryptoKeysModule } from './modules/crypto-keys/crypto-keys.module';
import { AuthModule } from './modules/auth/auth.module';
import { OtpModule } from './modules/otp/otp.module';
import { AuthMiddleware } from './modules/auth/middlewares/auth.middleware';
import { RolesGuard } from './common/modules/roles/roles.guard';
import jwtSecretConfig from 'config/jwt';
import { configuration } from 'config/configuration';
import { validationSchema } from 'config/validation';
import { CoreModule } from './common/modules/core/core.module';
import { UserSessionService } from './modules/user-session/user-session.service';
import { UserSessionModule } from './modules/user-session/user-session.module';
import { TransactionModule } from './modules/transaction/transaction.module';
import { GoogleCloudService } from './common/services/google-cloud/google-cloud.service';
require('dotenv').config();

const cookieSession = require('cookie-session');

// @TODO: repace process.env with config
@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration, jwtSecretConfig],
      validationSchema: validationSchema,
    }),
    TwilioModule.forRoot({
      accountSid: process.env.TWILIO_ACCOUNT_SID,
      authToken: process.env.TWILIO_AUTH_TOKEN,
    }),
    TwilioModule.forRoot({
      accountSid: process.env.TWILIO_ACCOUNT_SID,
      authToken: process.env.TWILIO_AUTH_TOKEN,
    }),
    BugsnagModule.forRoot({
      apiKey: process.env.BUGSNAG_ACCOUNT_API_KEY,
   }),
    TypeOrmModule.forRoot(),
    UserModule,
    CryptoKeysModule,
    AuthModule,
    OtpModule,
    CoreModule,
    UserSessionModule,
    TransactionModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_PIPE,
      useValue: new ValidationPipe({
        whitelist: true,
      }),
    },
    {
      provide: APP_GUARD,
      useClass: RolesGuard,
    },
    GoogleCloudService,
    // CustomLoggerService,
  ],
})
export class AppModule {
  constructor(private configService: ConfigService) {}

  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(
        cookieSession({
          keys: [this.configService.get('COOKIE_KEY')],
        }),
        AuthMiddleware,
      )
      .forRoutes('*');
  }
}
