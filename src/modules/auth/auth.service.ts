import {
  Injectable,
  BadRequestException,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { PasswordService } from 'src/modules/auth/password.service';
import { UsersService } from '../users/users.service';
import Errors from '../../constants/errors';
import { User } from '../users/user.entity';
import { JwtService } from '@nestjs/jwt';
import { Response } from 'express';
import { UserDto } from '../users/dtos/user.dto';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private passwordService: PasswordService,
    private jwtService: JwtService,
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
      fullName: user.fullName
    });
    response.cookie('jwt', jwtToken, {httpOnly: true});

    return user;
  }
}
