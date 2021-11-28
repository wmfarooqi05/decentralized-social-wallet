import {
  Body,
  Controller,
  Post,
  Get,
  Session,
  UseGuards,
  Req,
  Res,
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
    return this.authService.signup(body.email, body.phoneNumber, body.password, body.fullName);
  }

  @Post('/signin')
  @ApiOkResponse({ description: 'User Login' })
  @ApiUnauthorizedResponse({ description: 'Invalid Credentials' })
  @ApiBody({ type: CreateUserDto })
  async signin(
    @Res({ passthrough: true }) response: Response,
    @Body() body: CreateUserDto,
  ): Promise<UserDto> {
    return await this.authService.signin(
      body.email,
      body.phoneNumber,
      body.password,
      response,
    );
  }
}
