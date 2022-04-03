import { Module } from '@nestjs/common';
import { AuthService } from '../auth/auth.service';
import { AuthController } from './auth.controller';
import { OtpModule } from '../otp/otp.module';
import { UserSessionModule } from '../user-session/user-session.module';
import { UserModule } from '../user/user.module';
import { CryptoKeysModule } from '../crypto-keys/crypto-keys.module';

@Module({
  imports: [OtpModule, UserSessionModule, UserModule, CryptoKeysModule],
  controllers: [AuthController],
  providers: [AuthService],
})
export class AuthModule {
  // configure(consumer: MiddlewareConsumer) {
  //   consumer.apply(CurrentUserMiddleware).forRoutes('*');
  // }
}
