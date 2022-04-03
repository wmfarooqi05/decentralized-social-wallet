import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { PasswordService } from '../auth/password.service';
import { User } from './user.entity';
import { OtpModule } from '../otp/otp.module';
import { SendgridService } from 'src/common/services/email.service';
import { TwilioService } from 'src/common/services/twilio.service';
import { GoogleCloudService } from 'src/common/services/google-cloud/google-cloud.service';

@Module({
  imports: [TypeOrmModule.forFeature([User]), OtpModule],
  controllers: [UserController],
  providers: [
    UserService,
    PasswordService,
    SendgridService,
    TwilioService,
    GoogleCloudService,
  ],
  exports: [UserService],
})
export class UserModule {
  // move this to app module
  // configure(consumer: MiddlewareConsumer) {
  //   consumer.apply(CurrentUserMiddleware).forRoutes('*');
  // }
}
