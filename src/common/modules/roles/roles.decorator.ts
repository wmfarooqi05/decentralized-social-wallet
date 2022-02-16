import { SetMetadata } from '@nestjs/common';
import { UserRole } from 'src/modules/user/user.entity';
import { Role } from './roles.enum';

export const ROLES_KEY = 'roles';
export const Roles = (...roles: UserRole[]) => SetMetadata(ROLES_KEY, roles);