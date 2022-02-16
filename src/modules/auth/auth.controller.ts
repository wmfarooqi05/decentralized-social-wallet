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
} from '@nestjs/common';
import { UsernameDTO } from './dtos/username.dto';
import { CurrentUser } from './decorators/current-user.decorator';
import { IUser_Jwt } from '../../common/modules/jwt/jwt-payload.interface';
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
import { ForgotPasswordDto } from './dtos/forgot-password.dto';
import { SigninDTO } from './dtos/signin.dto';
import { Roles } from 'src/common/modules/roles/roles.decorator';
import { Role } from 'src/common/modules/roles/roles.enum';
import { ChangePasswordDTO } from './dtos/change-password.dto';
import { ValidateOTPDTO } from './dtos/validate-otp.dto';
import { ResetPasswordDTO } from './dtos/reset-password.dto';
import { LogoutDTO } from './dtos/logout.dto';
import { RefreshTokenDTO } from './dtos/refresh-token.dto';
import { CompleteSignupWithDTO } from './dtos/complete-signup-with-otp.dto';
import { ResendOTPDTO } from './dtos/resend-otp-dto';

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
      body.password,
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
}
