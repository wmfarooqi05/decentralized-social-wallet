import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JWT_USER_TYPE } from '../jwt/jwt-payload';
import { ROLES_KEY } from './roles.decorator';
import { Role } from './roles.enum';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndMerge<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!requiredRoles || requiredRoles?.length === 0) {
      return true;
    }
    const { user }: { user: JWT_USER_TYPE } = context.switchToHttp().getRequest();
    if (!user) {
      return false;
    }
    return requiredRoles.some((role) => user.role === role);
  }
}
