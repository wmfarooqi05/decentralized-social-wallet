import {
  ForbiddenException,
  GoneException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { UserService } from '../user/user.service';
import { User, UserStatus } from '../user/user.entity';
import { JwtService } from '@nestjs/jwt';
import { Request, Response } from 'express';
import { UserDto } from '../user/dtos/user.dto';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { OtpService } from '../otp/otp.service';
import { ValidateOTPDTO } from './dtos/validate-otp.dto';
import { TokenType, TransportType } from '../otp/otp.entity';
import { UserSessionService } from '../user-session/user-session.service';
import errors from 'src/constants/errors';
import { IUserJwt } from 'src/common/modules/jwt/jwt-payload.interface';
import { JwtAndRefreshToken, UserWithTokens } from './interfaces';

@Injectable()
export class AuthService {
  constructor(
    // @TODO: remove user Repo and call user service instead
    @InjectRepository(User) private userRepository: Repository<User>,
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
    private readonly otpService: OtpService,
    private readonly userSessionService: UserSessionService,
  ) {}

  async signup(
    req: Request,
    res: Response,
    username: string,
  ): Promise<UserWithTokens> {
    // Check if username already exists
    const exists = await this.userRepository.findOne({
      username,
    });

    if (exists) {
      throw new ForbiddenException(errors.USERNAME_ALREADY_EXISTS);
    }

    const user: User = await this.userService.create(username);
    const tokens: JwtAndRefreshToken =
      await this.generateAndAttachJwtAndRefreshToken(req, res, user);
    return Object.assign({}, user, tokens);
  }

  async signin(
    request: Request,
    email: string,
    phoneNumber: string,
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
    return exists ? false : true;
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

  async generateAndAttachJwtAndRefreshToken(
    req: Request,
    res: Response,
    user: User,
  ): Promise<JwtAndRefreshToken> {
    const jwtPayload: IUserJwt = {
      fullName: user.fullName,
      role: user.role,
      username: user.username,
      userStatus: user.userStatus,
    };

    const jwtToken = this.jwtService.sign(jwtPayload, {
      expiresIn: '365D',
    });
    const refreshToken = await this.userSessionService.generateRefreshToken(
      user,
      req.ip,
    );
    res.cookie('access-token', jwtToken, { httpOnly: true });
    res.cookie('refresh-token', refreshToken, { httpOnly: true });
    return {
      jwtToken,
      refreshToken,
    };
  }

  async linkEmail(username: string, email: string) {
    const user = await this.userService.updateWithUsername(username, {
      email,
      isEmailVerified: false,
    });

    return this.otpService.generateAndSendOTP(
      user,
      TokenType.LINK_EMAIL,
      [TransportType.EMAIL],
      email,
    );
  }

  async linkPhoneNumber(username: string, phoneNumber: string) {
    const user = await this.userService.updateWithUsername(username, {
      phoneNumber,
      isPhoneNumberVerified: false,
    });

    return this.otpService.generateAndSendOTP(
      user,
      TokenType.LINK_PHONE_NUMBER,
      [TransportType.SMS],
      phoneNumber,
    );
  }

  async completeEmailUsingOtp(username: string, email: string, otp: string) {
    const user = await this.userService.findByUsername(username);
    const otpItem = await this.otpService.findOtpCodeByIdAndType(
      otp,
      TokenType.LINK_EMAIL,
      user.id,
      email,
    );

    if (!otp || otpItem?.token !== otp) {
      throw new Error('Expired or invalid OTP');
    }

    await this.userService.updateWithUsername(username, {
      isEmailVerified: true,
    });

    await this.otpService.invalidateAllTokens(user.id, TokenType.LINK_EMAIL);
  }

  async completePhoneUsingOtp(
    username: string,
    phoneNumber: string,
    otp: string,
  ) {
    const user = await this.userService.findByUsername(username);
    const otpItem = await this.otpService.findOtpCodeByIdAndType(
      otp,
      TokenType.LINK_PHONE_NUMBER,
      user.id,
      phoneNumber,
    );

    if (!otp || otpItem?.token !== otp) {
      throw new UnauthorizedException('Expired or invalid OTP');
    }

    await this.userService.updateWithUsername(username, {
      isPhoneNumberVerified: true,
    });

    await this.otpService.invalidateAllTokens(
      user.id,
      TokenType.LINK_PHONE_NUMBER,
    );
  }

  async getAccessTokens(req, res, username) {
    const user = await this.userService.findByUsername(username);
    return this.generateAndAttachJwtAndRefreshToken(req, res, user);
  }
}
