import {
  Body,
  Controller,
  Post,
  Get,
  Session,
  Req,
  Res,
  HttpStatus,
  HttpCode,
  UseGuards,
  Param,
} from '@nestjs/common';
import { UsernameDTO } from './dtos/username.dto';
import { CurrentUser } from './decorators/current-user.decorator';
import { User } from '../user/user.entity';
import {
  ApiBody,
  ApiOkResponse,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { UserDto } from '../user/dtos/user.dto';
import { Serialize } from 'src/interceptors/serialize.interceptor';
import { SigninDTO } from './dtos/signin.dto';
import { ValidateOTPDTO } from './dtos/validate-otp.dto';
import { LogoutDTO } from './dtos/logout.dto';
import { RefreshTokenDTO } from './dtos/refresh-token.dto';
import { CompleteSignupWithDTO } from './dtos/complete-signup-with-otp.dto';
import { ResendOTPDTO } from './dtos/resend-otp-dto';
import { GenerateOtpToLinkEmail } from './dtos/generate-otp-to-link-email.dto';
import { GenerateOtpToLinkPhone } from './dtos/generate-otp-to-link-phone.dto';
import { JwtAuthGuard } from 'src/common/modules/jwt/jwt-auth.guard';
import { CompletePhoneLinking } from './dtos/complete-phone-linking';
import { CompleteEmailLinking } from './dtos/complete-email-linking';

@Controller('auth')
// This decorator will exclude password and other secrets on basis of UserDTO
@Serialize(UserDto)
export class AuthController {
  constructor(private authService: AuthService) {}

  @Get('/whoami')
  // @UseGuards(AuthGuard)
  whoAmI(@CurrentUser() user: User) {
    return user;
  }

  @Post('/signout')
  signOut(@Session() session: any) {
    session.userId = null;
  }

  @Post('/signup')
  async createUser(
    @Req() req: Request,
    @Res() res: Response,
    @Body() { username }: UsernameDTO,
  ) {
    const user = await this.authService.signup(req, res, username);
    res.status(HttpStatus.CREATED).json(user);
  }

  @Post('/signin')
  @ApiOkResponse({ description: 'User Login' })
  @ApiUnauthorizedResponse({ description: 'Invalid Credentials' })
  @ApiBody({ type: SigninDTO })
  @HttpCode(HttpStatus.OK)
  async signin(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
    @Body() body: SigninDTO,
  ): Promise<UserDto> {
    return await this.authService.signin(
      request,
      body.email,
      body.phoneNumber,
      response,
    );
  }

  @Post('/resend-otp')
  async resendOTP(@Body() { userId, tokenType }: ResendOTPDTO) {
    return this.authService.resendOTP(userId, tokenType);
  }

  @Post('/complete-signup-with-otp')
  async completeSignupWithOTP(@Body() { otp, userId }: CompleteSignupWithDTO) {
    return this.authService.completeSignupWithOTP(userId, otp);
  }

  @Post('/check-username-available')
  async checkUsernameAvailable(@Body() { username }: UsernameDTO) {
    return this.authService.checkUsernameAvailable(username);
  }

  /**
   * It will return a short JWT to change password
   */
  @HttpCode(HttpStatus.OK)
  @Post('/validate-otp')
  async validateOTP(
    @Body() body: ValidateOTPDTO,
    @Res({ passthrough: true }) response: Response,
  ) {
    return this.authService.validateOTP(body, response);
  }

  @HttpCode(HttpStatus.OK)
  @Post('/logout')
  async logout(@Body() body: LogoutDTO) {
    const { userId, refreshToken } = body;
    return this.authService.logout(userId, refreshToken);
  }

  @HttpCode(HttpStatus.OK)
  @Post('/refresh-token')
  async refreshToken(@Body() body: RefreshTokenDTO) {
    const { jwtToken, refreshToken } = body;
    return this.authService.refreshToken(jwtToken, refreshToken);
  }

  @Post('/link-email')
  @UseGuards(JwtAuthGuard)
  async linkEmail(
    @Req() { currentUser }: Request,
    @Body() { email }: GenerateOtpToLinkEmail,
  ) {
    return this.authService.linkEmail(currentUser.username, email);
  }

  @Post('/link-phone-number')
  @UseGuards(JwtAuthGuard)
  async linkPhoneNumber(
    @Req() { currentUser }: Request,
    @Body() { phoneNumber }: GenerateOtpToLinkPhone,
  ) {
    return this.authService.linkPhoneNumber(currentUser.username, phoneNumber);
  }

  @Post('/complete-email-linking')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async completeEmailUsingOtp(
    @Req() { currentUser }: Request,
    @Body() { email, otp }: CompleteEmailLinking,
  ) {
    return this.authService.completeEmailUsingOtp(
      currentUser.username,
      email,
      otp,
    );
  }

  @Post('/complete-phone-linking')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async completePhoneUsingOtp(
    @Req() { currentUser }: Request,
    @Body() { phoneNumber, otp }: CompletePhoneLinking,
  ) {
    return this.authService.completePhoneUsingOtp(
      currentUser.username,
      phoneNumber,
      otp,
    );
  }

  @Post('/get-access-tokens/:username')
  @HttpCode(HttpStatus.OK)
  async getAccessTokens(
    @Req() req: Request,
    @Res() res: Response,
    @Param() { username },
  ) {
    const payload = await this.authService.getAccessTokens(req, res, username);
    res.status(HttpStatus.CREATED).json(payload);
  }
}
