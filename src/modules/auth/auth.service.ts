import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PasswordService } from 'src/modules/auth/password.service';
import { UsersService } from '../users/users.service';
import { User } from '../users/user.entity';
import { JwtService } from '@nestjs/jwt';
import { Response } from 'express';
import { UserDto } from '../users/dtos/user.dto';
import JWT_PERMISSIONS from 'src/constants/jwt';
import { UpdatePasswordDto } from './dtos/update-password.dto';
import { FORGOT_PASSWORD_HEADING, otpEmailFormat, otpPhoneFormat } from 'src/constants/emails';
import { ForgotPasswordDto } from '../auth/dtos/forgot-password.dto';
import Errors from 'src/constants/errors';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { OtpService } from '../otp/otp.service';
import { SendgridService } from 'src/common/services/email.service';
import { TwilioService } from 'src/common/services/twilio.service';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private usersRepository: Repository<User>,
    private usersService: UsersService,
    private passwordService: PasswordService,
    private jwtService: JwtService,
    private otpService: OtpService,
    private readonly sendgridService: SendgridService,
    private readonly twilioService: TwilioService,
  ) {}

  async signup(
    email: string,
    phoneNumber: string,
    password: string,
    fullName: string,
  ): Promise<User> {
    // See if phoneNumber is in use
    if (email) {
      const user = await this.usersService.findByEmail(email);
      if (user) {
        throw new ForbiddenException(Errors.EMAIL_ALREADY_IN_USE);
      }
    } else if (phoneNumber) {
      const user = await this.usersService.findByPhoneNumber(phoneNumber);
      if (user) {
        throw new ForbiddenException(Errors.PHONE_NUMBER_ALREADY_IN_USE);
      }
    }

    // Create a new user and save it
    return this.usersService.create(email, phoneNumber, password, fullName);
  }

  async signin(
    email: string,
    phoneNumber: string,
    password: string,
    response: Response,
  ): Promise<UserDto> {
    let user: User = null;
    if (email) {
      user = await this.usersService.findByEmail(email);
    } else if (phoneNumber) {
      user = await this.usersService.findByPhoneNumber(phoneNumber);
    }
    if (!user) {
      throw new NotFoundException('user not found');
    }

    if (!this.passwordService.validatePassword(password, user.password)) {
      throw new BadRequestException('bad password');
    }

    const jwtToken = await this.jwtService.signAsync({
      email: user.email,
      phoneNumber: user.phoneNumber,
      fullName: user.fullName,
      permissions: JWT_PERMISSIONS.USER_LEVEL_PERMISSION
    });
    response.cookie('jwt', jwtToken, {httpOnly: true});

    return user;
  }

  async forgotPassword(
    request: ForgotPasswordDto,
    response: Response,
  ): Promise<any> {
    if (!request.email && !request.phoneNumber)
      throw new BadRequestException('Email or Phone Number is required.');
    let user: User;
    if (request.email) {
      user = await this.usersRepository.findOne({ email: request.email });
    } else {
      user = await this.usersRepository.findOne({ phoneNumber: request.phoneNumber });
    }

    if (!user) {
      throw new NotFoundException('No User found for given Email/Phone.');
    }

    const otp = await this.otpService.createCode(user);
    try {
      if (request.email) {
        await this.sendgridService.send(
          request.email,
          FORGOT_PASSWORD_HEADING,
          otpEmailFormat(otp.token),
        );
        return {
          message: 'Code has been generated successfully.',
        };
      } else if (request.phoneNumber) {
        await this.twilioService.sendSMSToken(
          request.phoneNumber,
          otpPhoneFormat(otp.token),
        );
        return {
          message: 'Code has been generated successfully.',
        };
      }
    } catch (e) {
      if (e?.response?.body?.errors[0]) {
        throw new Error(e.response.body.errors[0].message);
      }
      console.log(e);
    }
  }

  async changePassword(
    request: UpdatePasswordDto,
    response: Response,
  ): Promise<any> {
    let user: User;
    if (request.email) {
      user = await this.usersRepository.findOne({ email: request.email });
    } else {
      user = await this.usersRepository.findOne({ phoneNumber: request.phoneNumber });
    }

    if (!user) {
      throw new NotFoundException('No User found for given Email/Phone.');
    }

    const passwordValid = await this.passwordService.validatePassword(request.oldPassword, user.password);
    if (!passwordValid) {
      throw new ForbiddenException(Errors.PASSWORD_INCORRECT);
    }

    const newPasswordHash = await this.passwordService.hashPassword(request.newPassword);
    return this.usersRepository.update(user.id, { password: newPasswordHash });
  }

  async validateOTPAndGenerateJWT () {

  }
}
