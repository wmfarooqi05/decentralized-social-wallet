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
import { User } from '../users/user.entity';
import { AuthGuard } from '../../guards/auth.guard';
import {
  ApiBody,
  ApiOkResponse,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { UserDto } from '../users/dtos/user.dto';
import { Serialize } from 'src/interceptors/serialize.interceptor';
import { UpdatePasswordDto } from './dtos/update-password.dto';
import { ForgotPasswordDto } from './dtos/forgot-password.dto';
import { SigninDTO } from './dtos/signin.dto';

@Controller('auth')
// This decorator will exclude password and other secrets on basis of UserDTO
@Serialize(UserDto)
export class AuthController {
  constructor(private authService: AuthService) {}

  @Get('/whoami')
  @UseGuards(AuthGuard)
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
    @Res({ passthrough: true }) response: Response,
    @Body() body: SigninDTO,
  ): Promise<UserDto> {
    return await this.authService.signin(
      body.email,
      body.phoneNumber,
      body.password,
      response,
    );
  }

  @Post('/forgot-password')
  async forgotPassword(
    @Body() body: ForgotPasswordDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    return await this.authService.forgotPassword(body, response);
  }

  /**
   * It will return a short JWT to change password
   */
  @Post('/validate-otp')
  async validateOTP(
    @Body() body: UpdatePasswordDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    return this.authService.validateOTPAndGenerateJWT();
  }

  /**
   * This API will be called with a JWT. Either with a user JWT or validateOTP JWT
   * @param body
   * @param response
   */
  @Post('/change-password')
  async changePassword(
    @Body() body: UpdatePasswordDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    await this.authService.changePassword(body, response);
    response.status(HttpStatus.OK).json({
      message: 'Password Updated Successfully.',
    });
  }
}
