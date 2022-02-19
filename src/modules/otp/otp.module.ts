import { Module } from '@nestjs/common';
import { OtpService } from './otp.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Otp } from './otp.entity';
import { TwilioService } from 'src/common/services/twilio.service';
import { SendgridService } from 'src/common/services/email.service';

@Module({
  imports: [TypeOrmModule.forFeature([Otp])],
  providers: [OtpService, SendgridService, TwilioService],
  controllers: [],
  exports: [OtpService],
})
export class OtpModule {}
