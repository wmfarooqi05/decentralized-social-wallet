import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import RequestWithUser from 'src/modules/auth/interfaces/request-with-user';
import { UserRole } from 'src/modules/user/user.entity';
import { ROLES_KEY } from './roles.decorator';

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
    const { currentUser }: RequestWithUser = context
      .switchToHttp()
      .getRequest();
    if (!currentUser) {
      return false;
    }

    if (currentUser.role === UserRole.ADMIN) {
      // All routes are allowed for Admin
      return true;
    }

    return requiredRoles.some((role) => currentUser.role === role);
  }
}
