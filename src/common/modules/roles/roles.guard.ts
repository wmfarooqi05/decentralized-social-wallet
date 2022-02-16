import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { UserRole } from 'src/modules/user/user.entity';
import { IUser_Jwt } from '../jwt/jwt-payload.interface';
import { ROLES_KEY } from './roles.decorator';
import { Role } from './roles.enum';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndMerge<UserRole[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!requiredRoles || requiredRoles?.length === 0) {
      return true;
    }
    const { user }: { user: IUser_Jwt } = context.switchToHttp().getRequest();
    if (!user) {
      return false;
    }
    return requiredRoles.some((role) => user.role === role);
  }
}
