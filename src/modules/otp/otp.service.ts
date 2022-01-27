import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../users/user.entity';
import { Otp, TokenType } from './otp.entity';

@Injectable()
export class OtpService {
  constructor(
    @InjectRepository(Otp) private repo: Repository<Otp>,
  ) {}

  async getOtpCodes() {
    return await this.repo.find();
  }

  async createCode(user: User): Promise <Otp> {
    if (!user) throw new NotFoundException('No user registered with given credentials.');
    const otp = await this.repo.create({
      user,
      token: this.generateOTP(),
      type: TokenType.FORGOT_PASSWORD
    });
    return this.repo.save(otp);
  }

  generateOTP = () => {
    const digits = '0123456789';
    let OTP = '';
    for (let i = 0; i < parseInt(process.env.OTP_LENGTH); i++ ) {
        OTP += digits[Math.floor(Math.random() * 10)];
    }
    return OTP;
  }
}
