import {
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './user.entity';
import { PasswordService } from '../auth/password.service';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User) private usersRepository: Repository<User>,
    private passwordService: PasswordService,
  ) {}

  async create(
    email: string,
    phoneNumber: string,
    password: string,
    fullName: string,
  ) {
    // Hash the users password
    const hashedPassword = await this.passwordService.hashPassword(password);

    const user = this.usersRepository.create({
      email,
      phoneNumber,
      password: hashedPassword,
      fullName,
    });

    return this.usersRepository.save(user);
  }

  async findOne(id: number) {
    if (!id) {
      return null;
    }
    return this.usersRepository.findOne(id);
  }

  async findByEmail(email: string) {
    return this.usersRepository.findOne({ email });
  }

  async findByPhoneNumber(phoneNumber: string) {
    return this.usersRepository.findOne({ phoneNumber });
  }

  async update(id: number, attrs: Partial<User>) {
    const user: User = await this.findOne(id);
    if (!user) {
      throw new NotFoundException('user not found');
    }

    if (attrs.password) {
    }
    Object.assign(user, attrs);
    return this.usersRepository.save(user);
  }

  async remove(id: number) {
    const user = await this.findOne(id);
    if (!user) {
      throw new NotFoundException('user not found');
    }
    return this.usersRepository.remove(user);
  }
}
