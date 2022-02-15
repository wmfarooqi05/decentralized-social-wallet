import {
  BadRequestException,
  ForbiddenException,
  GoneException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PasswordService } from 'src/modules/auth/password.service';
import { UserService } from '../user/user.service';
import { User, UserStatus } from '../user/user.entity';
import { JwtService } from '@nestjs/jwt';
import { Request, Response } from 'express';
import { UserDto } from '../user/dtos/user.dto';
import { ForgotPasswordDto } from '../auth/dtos/forgot-password.dto';
import Errors from 'src/constants/errors';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { OtpService } from '../otp/otp.service';
import { ChangePasswordDTO } from './dtos/change-password.dto';
import { ValidateOTPDTO } from './dtos/validate-otp.dto';
import { TokenType } from '../otp/otp.entity';
import { ResetPasswordDTO } from './dtos/reset-password.dto';
import { UserSessionService } from '../user-session/user-session.service';

@Injectable()
export class AuthService {
  constructor(
    // @TODO: remove user Repo and call user service instead
    @InjectRepository(User) private userRepository: Repository<User>,
    private readonly userService: UserService,
    private readonly passwordService: PasswordService,
    private readonly jwtService: JwtService,
    private readonly otpService: OtpService,
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
    const newUser = await this.userService.create(
      email,
      phoneNumber,
      password,
      fullName,
    );

    await this.otpService.generateAndSendOTP(
      newUser,
      TokenType.ACCOUNT_REGISTER,
    );
    return newUser;
  }

  async verifiySignupOTP() {}

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

    await this.passwordService.validatePassword(password, user.password);

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

  // @TODO: Implement this
  async resendOTP(userId: string, tokenType: TokenType) {
    const user = await this.userService.findOneById(userId);
    return this.otpService.generateAndSendOTP(user, tokenType);
  }

  async completeSignupWithOTP(userId: string, otp: string): Promise<User> {
    await this.otpService.validateOTP(userId, otp);
    const updatedUser = await this.userService.update(userId, {
      userStatus: UserStatus.ACTIVE,
    });
    await this.otpService.invalidateAllTokens(
      userId,
      TokenType.ACCOUNT_REGISTER,
    );
    return updatedUser;
  }

  async forgotPassword(
    email?: string, phoneNumber?: string,
  ): Promise<any> {
    if (!email && !phoneNumber) {
      throw new BadRequestException('Email or Phone Number is required.');
    }
    const user: User = await this.userService.findUser({ email, phoneNumber });

    if (!user) {
      throw new NotFoundException('No User found for given Email/Phone.');
    }

    await this.otpService.generateAndSendOTP(user, TokenType.FORGOT_PASSWORD);
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
