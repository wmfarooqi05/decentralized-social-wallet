import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './user.entity';
import { PasswordService } from '../auth/password.service';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
    private passwordService: PasswordService,
  ) {}

  async create(
    email: string,
    phoneNumber: string,
    password: string,
    fullName: string,
  ) {
    // Hash the user password
    const hashedPassword = await this.passwordService.hashPassword(password);

    const user = this.userRepository.create({
      email,
      phoneNumber,
      password: hashedPassword,
      fullName,
    });

    return this.userRepository.save(user);
  }

  async findAll() {
    return this.userRepository.find();
  }

  async findOne(id: number) {
    if (!id) {
      return null;
    }
    return this.userRepository.findOne(id);
  }

  async findUser(user: { email?: string, phoneNumber?: string}): Promise<User> {
    if (user.email) {
      return this.findByEmail(user.email);
    } else if (user.phoneNumber) {
      return this.findByPhoneNumber(user.phoneNumber)
    } else {
      throw new BadRequestException('No Email/Phone Number provided');
    }
  }

  async findByEmail(email: string) {
    return this.userRepository.findOne({ email });
  }

  async findByPhoneNumber(phoneNumber: string) {
    return this.userRepository.findOne({ phoneNumber });
  }

  async update(id: number, attrs: Partial<User>) {
    const user: User = await this.findOne(id);
    if (!user) {
      throw new NotFoundException('user not found');
    }

    if (attrs.password) {
    }
    Object.assign(user, attrs);
    return this.userRepository.save(user);
  }

  async remove(id: number) {
    const user = await this.findOne(id);
    if (!user) {
      throw new NotFoundException('user not found');
    }
    return this.userRepository.remove(user);
  }
}
