import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './user.entity';
import { PasswordService } from '../auth/password.service';
import { GoogleCloudService } from 'src/common/services/google-cloud/google-cloud.service';
import { uuid } from 'uuidv4';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
    private passwordService: PasswordService,
    private googleCloudService: GoogleCloudService,
  ) {}

  async create(username: string) {
    const user = this.userRepository.create({
      username,
    });

    return this.userRepository.save(user);
  }

  async findAll() {
    return this.userRepository.find();
  }

  async findOneById(id: string) {
    if (!id) {
      return null;
    }
    return this.userRepository.findOne(id);
  }

  async findUser(user: {
    username?: string;
    email?: string;
    phoneNumber?: string;
  }): Promise<User> {
    if (user.username) {
      return this.findByUsername(user.username);
    } else if (user.email) {
      return this.findByEmail(user.email);
    } else if (user.phoneNumber) {
      return this.findByPhoneNumber(user.phoneNumber);
    } else {
      throw new BadRequestException('No Email/Phone Number provided');
    }
  }

  async findByUsername(username: string) {
    return this.userRepository.findOne({ username });
  }

  async findByEmail(email: string) {
    return this.userRepository.findOne({ email });
  }

  async findByPhoneNumber(phoneNumber: string) {
    return this.userRepository.findOne({ phoneNumber });
  }

  async update(id: string, attrs: Partial<User>) {
    const user: User = await this.findOneById(id);
    if (!user) {
      throw new NotFoundException('user not found');
    }
    Object.assign(user, attrs);
    return this.userRepository.save(user);
  }

  async updateWithUsername(
    username: string,
    attrs: Partial<Omit<User, 'id' | 'username'>>,
  ) {
    const user: User = await this.findByUsername(username);
    if (!user) {
      throw new NotFoundException('user not found');
    }
    Object.assign(user, attrs);
    return this.userRepository.save(user);
  }

  async remove(id: string) {
    const user = await this.findOneById(id);
    if (!user) {
      throw new NotFoundException('user not found');
    }
    return this.userRepository.remove(user);
  }

  async updateProfilePicture(
    username: string,
    buffer: Buffer,
    mimetype: string,
    filename: string,
  ) {
    const id = uuid();
    const url = await this.googleCloudService.save(
      `media/profiles/${id}.${mimetype.split('/')[1]}`,
      buffer,
    );
    await this.updateWithUsername(username, {
      image: url,
    });

    return url;
  }
}
