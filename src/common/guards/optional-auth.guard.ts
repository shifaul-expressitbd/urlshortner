import { Injectable, ExecutionContext } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

/**
 * OptionalAuthGuard - Attempts JWT authentication but doesn't require it.
 * If valid token present, user is attached to request.
 * If no token or invalid token, request proceeds without user.
 */
@Injectable()
export class OptionalAuthGuard extends AuthGuard('jwt') {
  canActivate(context: ExecutionContext) {
    return super.canActivate(context);
  }

  handleRequest(err: any, user: any) {
    // Don't throw errors - just return user if valid, undefined otherwise
    return user || undefined;
  }
}
