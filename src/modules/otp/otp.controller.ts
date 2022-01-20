import { Controller, Get } from '@nestjs/common';
import { OtpService } from './otp.service';

@Controller('otp')
export class OtpController {
  constructor(
    private otpService: OtpService
  ) {}

  @Get()
  async getOtpCodes() {
    const codes = await this.otpService.getOtpCodes();
    return {
      data: codes
    };
  }
}
