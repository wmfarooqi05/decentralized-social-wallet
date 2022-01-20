import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Response } from 'express';
import { User } from './user.entity';
import { SendgridService } from '../../services/email.service';
import { PasswordService } from '../auth/password.service';
import { UpdatePasswordDto } from './dtos/update-password.dto';
import { OtpService } from '../otp/otp.service';
import { otpEmailFormat } from 'src/constants/emails';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User) private repo: Repository<User>,
    private passwordService: PasswordService,
    private jwtService: JwtService,
    private otpService: OtpService,
    private readonly sendgridService: SendgridService,
  ) {}

  async create(email: string, phoneNumber: string, password: string, fullName: string) {
    // Hash the users password
    const hashedPassword = await this.passwordService.hashPassword(password);

    const user = this.repo.create({
      email,
      phoneNumber,
      password: hashedPassword,
      fullName,
    });

    return this.repo.save(user);
  }

  findOne(id: number) {
    if (!id) {
      return null;
    }
    return this.repo.findOne(id);
  }

  findByEmail(email: string) {
    return this.repo.findOne({ email });
  }

  findByPhoneNumber(phoneNumber: string) {
    return this.repo.findOne({ phoneNumber });
  }

  async update(id: number, attrs: Partial<User>) {
    const user = await this.findOne(id);
    if (!user) {
      throw new NotFoundException('user not found');
    }

    if (attrs.password) {
    }
    Object.assign(user, attrs);
    return this.repo.save(user);
  }

  async remove(id: number) {
    const user = await this.findOne(id);
    if (!user) {
      throw new NotFoundException('user not found');
    }
    return this.repo.remove(user);
  }

  async changePassword(request: UpdatePasswordDto, response: Response): Promise<any> {
    if (!request.email && !request.phoneNumber) throw new BadRequestException('Email or Phone Number is required.');
    let user;
    if (request.email) {
      user = await this.repo.find({email: request.email});
    } else {
      user = await this.repo.find({phoneNumber: request.phoneNumber});
    }
    
    if (!user || user.length === 0) throw new NotFoundException('No User found for given Email/Phone.');
    
    const otp = await this.otpService.createCode(user[0]);
    if (request.email) {
      if (user.length > 0) {
        const mail = {
          to: request.email,
          subject: 'Password change',
          from: process.env.AUTHENTICATION_SENDER_EMAIL, // Fill it with your validated email on SendGrid account
          html: otpEmailFormat(otp.token),
        };

        try {
          const responce = await this.sendgridService.send(mail);
          return {
            message: 'Code has been generated successfully.',
          };
        } catch(e) {
          if (e?.response?.body?.errors[0]) {
            throw new Error(e.response.body.errors[0].message);
          }
          console.log(e);
        }
      }
    }
  }
}
