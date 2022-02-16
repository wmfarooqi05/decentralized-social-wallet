import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { SendgridService } from 'src/common/services/email.service';
import { TwilioService } from 'src/common/services/twilio.service';
import { newAccountOtpEmailFormat, NEW_ACCOUNT_EMAIL, NEW_ACCOUNT_SMS } from 'src/constants/emails';
import { FindCondition, Repository } from 'typeorm';
import { User } from '../user/user.entity';
import { Otp, TokenType } from './otp.entity';

@Injectable()
export class OtpService {
  constructor(@InjectRepository(Otp) private otpRepo: Repository<Otp>,
  private readonly sendgridService: SendgridService,
  private readonly twilioService: TwilioService,
) {}

  async getOtpCodes() {
    return await this.otpRepo.find();
  }

  async createOTP(user: User, tokenType: TokenType): Promise<Otp> {
    if (!user)
      throw new NotFoundException('No user registered with given credentials.');
    const otp = await this.otpRepo.create({
      user,
      token: this.generateOTP(),
      type: TokenType.FORGOT_PASSWORD,
    });
    return this.otpRepo.save(otp);
  }

  private generateOTP = () => {
    const digits = '0123456789';
    let OTP = '';
    for (let i = 0; i < parseInt(process.env.OTP_LENGTH); i++) {
      OTP += digits[Math.floor(Math.random() * 10)];
    }
    return OTP;
  };

  async validateOTP(userId: string, otp: string) {
    const otpRecord = await this.otpRepo.findOne({
      where: { user: userId },
      order: { id: 'DESC' },
    });

    if (otpRecord?.token === otp && !otpRecord.expired) {
      return true;
    } 
    
    throw new BadRequestException('OTP has been expired');
  }

  INVALIDATE_ENTERIES = (userId: string, type: string) => `
    UPDATE otp
    SET expired=TRUE
    WHERE "userId"='${userId}' AND "type"='${type}'
  `;

  async invalidateAllTokens(userId: string, type: TokenType) {
    return this.otpRepo.query(this.INVALIDATE_ENTERIES(userId, type));
  }

  async invalidateToken(userId: string, otpCode: string) {
    // @TODO: Implement this
  }

  async generateAndSendOTP(user: User, tokenType: TokenType){
    const otp = await this.createOTP(user, TokenType.ACCOUNT_REGISTER);
    try {
      if (user.email) {
        await this.sendgridService.send(
          user.email,
          NEW_ACCOUNT_EMAIL,
          newAccountOtpEmailFormat(otp.token),
        );
      } else if (user.phoneNumber) {
        await this.twilioService.sendSMSToken(
          user.phoneNumber,
          NEW_ACCOUNT_SMS(otp.token),
        );
      }
    } catch (e) {
      if (e?.response?.body?.errors[0]) {
        throw new Error(e.response.body.errors[0].message);
      }
      console.log(e);
    }


  }
}
