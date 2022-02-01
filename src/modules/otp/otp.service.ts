import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { JWT_USER_TYPE } from 'src/common/modules/jwt/jwt-payload';
import { FindCondition, Repository } from 'typeorm';
import { User } from '../user/user.entity';
import { Otp, TokenType } from './otp.entity';

@Injectable()
export class OtpService {
  constructor(@InjectRepository(Otp) private otpRepo: Repository<Otp>) {}

  async getOtpCodes() {
    return await this.otpRepo.find();
  }

  async createCode(user: User): Promise<Otp> {
    if (!user)
      throw new NotFoundException('No user registered with given credentials.');
    const otp = await this.otpRepo.create({
      user,
      token: this.generateOTP(),
      type: TokenType.FORGOT_PASSWORD,
    });
    return this.otpRepo.save(otp);
  }

  generateOTP = () => {
    const digits = '0123456789';
    let OTP = '';
    for (let i = 0; i < parseInt(process.env.OTP_LENGTH); i++) {
      OTP += digits[Math.floor(Math.random() * 10)];
    }
    return OTP;
  };

  async validateOTP(userId: number, otp: string) {
    const otpRecord = await this.otpRepo.findOne({
      where: { user: userId },
      order: { id: 'DESC' },
    });

    if (otpRecord?.token === otp && !otpRecord.expired) {
      return true;
    } else {
      return false;
    }
  }

  INVALIDATE_ENTERIES = (userId: number, type: string) => `
    UPDATE otp
    SET expired=TRUE
    WHERE "userId"=${userId} AND type='${type}'
  `;

  async invalidateAllTokens(userId: number, type: string) {
    return this.otpRepo.query(this.INVALIDATE_ENTERIES(userId, type));
  }
}
