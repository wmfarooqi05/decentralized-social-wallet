import { Module, MiddlewareConsumer } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UsersController } from '../users/users.controller';
import { UsersService } from '../users/users.service';
import { AuthService } from '../auth/auth.service';
import { PasswordService } from '../auth/password.service';
import { User } from '../users/user.entity';
import { CurrentUserMiddleware } from '../auth/middlewares/current-user.middleware';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { OtpModule } from '../otp/otp.module';
import { SendgridService } from 'src/common/services/email.service';
import { TwilioService } from 'src/common/services/twilio.service';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    JwtModule.register({
      secret: 'secret',
      signOptions: { expiresIn: '1d' },
      // secret: 'this_is_secret',
      // signOptions: {
      //   algorithm: 'RS512',
      //   expiresIn: '1D',
      // },
    }),
    /**
     * @DISCUSS
     * otp service is not being used in AuthModule but code is platform is requiring it to be imported here
     */
    OtpModule,
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    PasswordService,
    UsersService,
    SendgridService,
    TwilioService,
  ],
})
export class AuthModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(CurrentUserMiddleware).forRoutes('*');
  }
}
