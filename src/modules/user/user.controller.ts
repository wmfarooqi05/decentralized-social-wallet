import {
  Body,
  Controller,
  Get,
  Patch,
  Delete,
  Param,
  NotFoundException,
  Put,
  UseGuards,
  Req,
  UploadedFile,
  UseInterceptors,
} from '@nestjs/common';
import { UpdateUserDto } from './dtos/update-user.dto';
import { UserService } from './user.service';
import { Serialize } from '../../interceptors/serialize.interceptor';
import { UserDto } from './dtos/user.dto';
import { User, UserRole } from './user.entity';
import Errors from 'src/constants/errors';
import { Roles } from 'src/common/modules/roles/roles.decorator';
import { RolesGuard } from 'src/common/modules/roles/roles.guard';
import { UpdateUserFullNameDto } from './dtos/update-user-fullname.dto';
import { AuthGuard } from '@nestjs/passport';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import { JwtAuthGuard } from 'src/common/modules/jwt/jwt-auth.guard';
import RequestWithUser from '../auth/interfaces/request-with-user';
import { ApiBearerAuth, ApiOperation } from '@nestjs/swagger';
import { FileInterceptor } from '@nestjs/platform-express';
import 'multer';

// @TODO: change this with ADMIN
@Controller('user')
@ApiBearerAuth()
@Serialize(UserDto)
export class UserController {
  constructor(private userService: UserService) {}

  @Get('/:id')
  @ApiOperation({ summary: 'Find a user by id' })
  @ApiBearerAuth()
  @Roles(UserRole.ADMIN)
  async findUser(@Param('id') id: string): Promise<User> {
    const user = await this.userService.findOneById(id);
    if (!user) {
      throw new NotFoundException(Errors.ENTITY_NOT_FOUND('User'));
    }
    return user;
  }

  @Get()
  // @Roles(UserRole.ADMIN)
  findAllUser() {
    return this.userService.findAll();
  }

  @Get('/whoami')
  // @UseGuards(AuthGuard)
  whoAmI(@CurrentUser() user: User) {
    return user;
  }

  @Delete('/:id')
  @Roles(UserRole.ADMIN)
  removeUser(@Param('id') id: string) {
    return this.userService.remove(id);
  }

  // Remove this later
  @Patch('/:id')
  @Roles(UserRole.ADMIN)
  updateUser(@Param('id') id: string, @Body() body: UpdateUserDto) {
    return this.userService.update(id, body);
  }

  @Put('update-fullname')
  @UseGuards(JwtAuthGuard)
  updateUserFullName(
    @Req() req: RequestWithUser,
    @Body() { fullName }: UpdateUserFullNameDto,
  ) {
    return this.userService.updateWithUsername(req.user.username, {
      fullName,
    });
  }

  @Put('update-profile-picture')
  // @UseGuards(JwtAuthGuard)
  @UseInterceptors(FileInterceptor('file'))
  async updateProfilePicture(
    @Req() request: RequestWithUser,
    @UploadedFile() file: Express.Multer.File,
  ) {
    return this.userService.updateProfilePicture(
      request.currentUser.username,
      file.buffer,
      file.mimetype,
      file.originalname,
    );
  }
}
