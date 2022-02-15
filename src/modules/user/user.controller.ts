import {
  Body,
  Controller,
  Get,
  Patch,
  Delete,
  Param,
  NotFoundException,
} from '@nestjs/common';
import { UpdateUserDto } from './dtos/update-user.dto';
import { UserService } from './user.service';
import { Serialize } from '../../interceptors/serialize.interceptor';
import { UserDto } from './dtos/user.dto';
import { User } from './user.entity';
import Errors from 'src/constants/errors';
import { Roles } from 'src/common/modules/roles/roles.decorator';
import { Role } from 'src/common/modules/roles/roles.enum';
import { RolesGuard } from 'src/common/modules/roles/roles.guard';
// import { RolesGuard } from 'src/common/modules/roles/roles.guard';

// @TODO: change this with ADMIN
@Roles(Role.USER_ROLE)
@Controller('user')
@Serialize(UserDto)
export class UserController {
  constructor(
    private userService: UserService,
  ) {}

  @Get('/:id')
  async findUser(@Param('id') id: string): Promise<User> {
    const user = await this.userService.findOneById(id);
    if (!user) {
      throw new NotFoundException(Errors.ENTITY_NOT_FOUND('User'));
    }
    return user;
  }

  @Get()
  findAllUser() {
    return this.userService.findAll();
  }

  @Delete('/:id')
  removeUser(@Param('id') id: string) {
    return this.userService.remove(id);
  }

  @Patch('/:id')
  updateUser(@Param('id') id: string, @Body() body: UpdateUserDto) {
    return this.userService.update(id, body);
  }
}
