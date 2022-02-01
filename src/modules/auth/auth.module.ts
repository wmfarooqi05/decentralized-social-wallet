import { Module, MiddlewareConsumer } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserController } from '../user/user.controller';
import { UserService } from '../user/user.service';
import { AuthService } from '../auth/auth.service';
import { PasswordService } from '../auth/password.service';
import { User } from '../user/user.entity';
import { CurrentUserMiddleware } from '../auth/middlewares/current-user.middleware';
import { AuthController } from './auth.controller';
import { JwtModule, JwtModuleOptions } from '@nestjs/jwt';
import { OtpModule } from '../otp/otp.module';
import { SendgridService } from 'src/common/services/email.service';
import { TwilioService } from 'src/common/services/twilio.service';
import { UserSessionService } from '../user-session/user-session.service';
import { UserSessionModule } from '../user-session/user-session.module';
import { UserSession } from '../user-session/user-session.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    TypeOrmModule.forFeature([UserSession]),
    /**
     * @DISCUSS
     * otp service is not being used in AuthModule but code is platform is requiring it to be imported here
     */
    OtpModule,
    UserSessionModule,
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    PasswordService,
    UserService,
    UserSessionService,
    SendgridService,
    TwilioService,
  ],
})
export class AuthModule {

  configure(consumer: MiddlewareConsumer) {
    consumer.apply(CurrentUserMiddleware).forRoutes('*');
  }
}
