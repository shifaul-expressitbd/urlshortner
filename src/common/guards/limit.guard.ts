import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { CHECK_LIMIT_KEY } from '../decorators/check-limit.decorator';

/**
 * LimitGuard - Placeholder for future rate/usage limiting
 * TODO: Implement when API key management is added
 */
@Injectable()
export class LimitGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const resource = this.reflector.get<string>(CHECK_LIMIT_KEY, context.getHandler());
    if (!resource) {
      return true;
    }

    // TODO: Implement usage limiting when UsageService is added
    // For now, always allow
    return true;
  }
}
