import {
  Injectable,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { PasswordService } from 'src/services/password.service';
import { UsersService } from './users.service';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private passwordService: PasswordService,
  ) {}

  async signup(email: string, phoneNumber: string, password: string) {
    // See if phoneNumber is in use
    let users = null;

    if (email) {
      users = await this.usersService.findByEmail(email);
    } else if (phoneNumber) {
      users = await this.usersService.findByPhoneNumber(password);
    }
    if (users.length) {
      throw new BadRequestException('phoneNumber in use');
    }

    // Hash the users password
    const hashedPassword = await this.passwordService.hashPassword(password);

    // Create a new user and save it
    const user = await this.usersService.create(
      email,
      phoneNumber,
      hashedPassword,
    );

    // return the user
    return user;
  }

  async signin(email: string, phoneNumber: string, password: string) {
    let user = null;
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

    return user;
  }
}
