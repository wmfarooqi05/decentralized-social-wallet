import { Module, MiddlewareConsumer } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { PasswordService } from '../auth/password.service';
import { User } from './user.entity';
import { CurrentUserMiddleware } from '../auth/middlewares/current-user.middleware';
import { OtpModule } from '../otp/otp.module';
import { SendgridService } from 'src/services/email.service';

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
    OtpModule,
  ],
  controllers: [UsersController],
  providers: [UsersService, PasswordService, SendgridService],
})
export class UsersModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(CurrentUserMiddleware).forRoutes('*');
  }
}
