import { Module, ValidationPipe, MiddlewareConsumer } from '@nestjs/common';
import { APP_GUARD, APP_PIPE } from '@nestjs/core';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TwilioModule } from 'nestjs-twilio';

import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UserModule } from './modules/user/user.module';
import { CryptoKeysModule } from './modules/crypto-keys/crypto-keys.module';
import { TransactionsModule } from './modules/transactions/transactions.module';
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
require('dotenv').config();

const cookieSession = require('cookie-session');

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
    TypeOrmModule.forRoot(),
    UserModule,
    CryptoKeysModule,
    TransactionsModule,
    AuthModule,
    OtpModule,
    CoreModule,
    UserSessionModule,
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
