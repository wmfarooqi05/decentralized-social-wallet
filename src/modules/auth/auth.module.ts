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
import { JwtService } from '@nestjs/jwt';

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
  ],
  controllers: [AuthController],
  providers: [AuthService, PasswordService, UsersService],
})
export class AuthModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(CurrentUserMiddleware).forRoutes('*');
  }
}
