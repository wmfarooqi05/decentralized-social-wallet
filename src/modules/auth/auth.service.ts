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
import errors from 'src/constants/errors';
import { IUser_Jwt } from 'src/common/modules/jwt/jwt-payload.interface';

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

  async signup(req: Request, res: Response, username: string): Promise<User> {
    // Check if username already exists
    const exists = await this.userRepository.findOne({
      username,
    });

    if (exists) {
      throw new ForbiddenException(errors.USERNAME_ALREADY_EXISTS);
    }

    const user = await this.userService.create(username);

    await this.generateAndAttachJwtAndRefreshToken(req, res, user);
    return user;
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

  async checkUsernameAvailable(username): Promise<boolean> {
    const exists = await this.userRepository.findOne({ username });
    return exists ? true : false;
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

  async generateAndAttachJwtAndRefreshToken(req: Request, res: Response, user: User) {
    const jwtPayload: IUser_Jwt = {
      fullName: user.fullName,
      role: user.role,
      username: user.username,
      userStatus: user.userStatus,
    }

    const jwtToken = this.jwtService.sign(jwtPayload);
    const refreshToken = await this.userSessionService.generateRefreshToken(
      user,
      req.ip,
    );
    res.cookie('access-token', jwtToken, { httpOnly: true });
    res.cookie('refresh-token', refreshToken, { httpOnly: true });
  }
}
