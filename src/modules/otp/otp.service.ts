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
    const otpCode = `${Math.floor(Math.random() * 10)}${Math.floor(Math.random() * 10)}${Math.floor(Math.random() * 10)}${Math.floor(Math.random() * 10)}`;
    if (!user) throw new NotFoundException('No user registered with given credentials.');
    const otp = await this.repo.create({
      user,
      token: otpCode,
      type: TokenType.FORGOT_PASSWORD
    });
    return this.repo.save(otp);
  }
}
