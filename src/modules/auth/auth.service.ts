import {
  BadRequestException,
  ForbiddenException,
  GoneException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PasswordService } from 'src/modules/auth/password.service';
import { UserService } from '../user/user.service';
import { User } from '../user/user.entity';
import { JwtService } from '@nestjs/jwt';
import { Request, Response } from 'express';
import { UserDto } from '../user/dtos/user.dto';
import {
  FORGOT_PASSWORD_HEADING,
  otpEmailFormat,
  otpPhoneFormat,
} from 'src/constants/emails';
import { ForgotPasswordDto } from '../auth/dtos/forgot-password.dto';
import Errors from 'src/constants/errors';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { OtpService } from '../otp/otp.service';
import { SendgridService } from 'src/common/services/email.service';
import { TwilioService } from 'src/common/services/twilio.service';
import { ChangePasswordDTO } from './dtos/change-password.dto';
import { ValidateOTPDTO } from './dtos/validate-otp.dto';
import { TokenType } from '../otp/otp.entity';
import { ResetPasswordDTO } from './dtos/reset-password.dto';
import { ConfigService } from '@nestjs/config';
import { UserSessionService } from '../user-session/user-session.service';
import jwt from 'config/jwt';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
    private readonly userService: UserService,
    private readonly passwordService: PasswordService,
    private readonly jwtService: JwtService,
    private readonly otpService: OtpService,
    private readonly sendgridService: SendgridService,
    private readonly twilioService: TwilioService,
    private readonly configService: ConfigService,
    private readonly userSessionService: UserSessionService,
  ) {}

  async signup(
    email: string,
    phoneNumber: string,
    password: string,
    fullName: string,
  ): Promise<User> {
    // See if phoneNumber is in use
    if (email) {
      const user = await this.userService.findByEmail(email);
      if (user) {
        throw new ForbiddenException(Errors.EMAIL_ALREADY_IN_USE);
      }
    } else if (phoneNumber) {
      const user = await this.userService.findByPhoneNumber(phoneNumber);
      if (user) {
        throw new ForbiddenException(Errors.PHONE_NUMBER_ALREADY_IN_USE);
      }
    }

    // Create a new user and save it
    return this.userService.create(email, phoneNumber, password, fullName);
  }

  async signin(
    request: Request,
    email: string,
    phoneNumber: string,
    password: string,
    response: Response,
  ): Promise<UserDto> {
    const user: User = await this.userService.findUser({ email, phoneNumber });

    if (!user) {
      throw new NotFoundException('user not found');
    }

    if (!this.passwordService.validatePassword(password, user.password)) {
      throw new BadRequestException('bad password');
    }

    const jwtToken = this.jwtService.sign({
      email: user.email,
      phoneNumber: user.phoneNumber,
      name: user.fullName,
      role: user.role,
    });
    const refreshToken = this.userSessionService.generateRefreshToken(
      user,
      request.ip,
    );
    response.cookie('access-token', jwtToken, { httpOnly: true });
    response.cookie('refresh-token', refreshToken, { httpOnly: true });

    return user;
  }

  async forgotPassword(
    request: ForgotPasswordDto,
    response: Response,
  ): Promise<any> {
    if (!request.email && !request.phoneNumber)
      throw new BadRequestException('Email or Phone Number is required.');
    const user: User = await this.userService.findUser(request);

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

  async changePassword(reqUser: any, body: ChangePasswordDTO): Promise<any> {
    const user: User = await this.userService.findUser(reqUser);
    if (!user) {
      throw new NotFoundException('No User found for given Email/Phone.');
    }
    const passwordValid = await this.passwordService.validatePassword(
      body.oldPassword,
      user.password,
    );

    if (!passwordValid) {
      throw new ForbiddenException(Errors.PASSWORD_INCORRECT);
    }

    const newPasswordHash = await this.passwordService.hashPassword(
      body.newPassword,
    );
    return this.userRepository.update(user.id, { password: newPasswordHash });
  }

  async validateOTPAndResetPassword(payload: ResetPasswordDTO) {
    const user: User = await this.userService.findUser(payload);
    if (!user) {
      throw new NotFoundException('No User found for given Email/Phone.');
    }

    const validOTP = await this.otpService.validateOTP(user.id, payload.otp);
    if (!validOTP) {
      throw new GoneException('OTP expired or invalid');
    }

    const newPasswordHash = await this.passwordService.hashPassword(
      payload.newPassword,
    );
    await this.userRepository.update(user.id, { password: newPasswordHash });
    await this.otpService.invalidateAllTokens(
      user.id,
      TokenType.FORGOT_PASSWORD,
    );
  }

  async validateOTP(payload: ValidateOTPDTO, response: Response) {
    const user: User = await this.userService.findUser(payload);
    if (!user) {
      throw new NotFoundException('No User found for given Email/Phone.');
    }

    const validOTP = await this.otpService.validateOTP(user.id, payload.otp);
    if (!validOTP) {
      throw new GoneException('OTP expired or invalid');
    }
    response.status(200).json({
      message: 'OTP Valid',
    });
  }

  async refreshToken(jwtToken, refreshToken) {
    const userPayload: any = this.jwtService.decode(jwtToken);
    const user: User = await this.userService.findUser(userPayload);
    this.userSessionService.verifyTokenExists(user?.id, refreshToken);
    return {
      jwtToken: this.jwtService.sign({
        email: user.email,
        phoneNumber: user.phoneNumber,
        name: user.fullName,
        role: user.role,
      }),
    };
  }

  async logout(userId, refreshToken) {
    return this.userSessionService.logout(userId, refreshToken);
  }
}
