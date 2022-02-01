import {
  Body,
  Controller,
  Post,
  Get,
  Session,
  UseGuards,
  Req,
  Res,
  HttpStatus,
  HttpCode,
} from '@nestjs/common';
import { CreateUserDto } from './dtos/create-user.dto';
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
import { UpdatePasswordDto } from './dtos/update-password.dto';
import { ForgotPasswordDto } from './dtos/forgot-password.dto';
import { SigninDTO } from './dtos/signin.dto';
import { Roles } from 'src/common/modules/roles/roles.decorator';
import { Role } from 'src/common/modules/roles/roles.enum';
import { JWT_USER_TYPE } from 'src/common/modules/jwt/jwt-payload';
import { ChangePasswordDTO } from './dtos/change-password.dto';
import { ValidateOTPDTO } from './dtos/validate-otp.dto';
import { ResetPasswordDTO } from './dtos/reset-password.dto';
import { LogoutDTO } from './dtos/logout.dto';
import { RefreshTokenDTO } from './dtos/refresh-token.dto';

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
  async createUser(@Req() req: Request, @Body() body: CreateUserDto) {
    return this.authService.signup(
      body.email,
      body.phoneNumber,
      body.password,
      body.fullName,
    );
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

  @Post('/forgot-password')
  // @Roles(Role.ADMIN_ROLE, Role.TEMP_PASSWORD_RESET_ROLE, Role.USER_ROLE)
  async forgotPassword(
    @Body() body: ForgotPasswordDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    return await this.authService.forgotPassword(body, response);
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

  /**
   * @param body
   * @param response
   */
  @Post('/change-password')
  @Roles(Role.ADMIN_ROLE, Role.USER_ROLE)
  async changePassword(
    @Req() req: Request,
    @Body() body: ChangePasswordDTO,
    @Res({ passthrough: true }) response: Response,
  ) {
    const { user } = req;
    await this.authService.changePassword(user, body);
    response.status(HttpStatus.OK).json({
      message: 'Password Updated Successfully.',
    });
  }

  @Post('/reset-password')
  @Roles(Role.TEMP_PASSWORD_RESET_ROLE)
  async resetPassword(
    @Req() req: Request,
    @Body() body: ResetPasswordDTO,
    @Res({ passthrough: true }) response: Response,
  ) {
    await this.authService.validateOTPAndResetPassword(body);
    response.status(HttpStatus.OK).json({
      message: 'Password Updated Successfully.',
    });
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
