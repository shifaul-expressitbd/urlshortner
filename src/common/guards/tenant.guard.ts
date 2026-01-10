import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { IS_TENANT_SCOPED_KEY } from '../decorators/tenant-scoped.decorator';

/**
 * TenantGuard - Placeholder, not used in URL shortener (no multi-tenancy)
 * Kept for potential future use
 */
@Injectable()
export class TenantGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Multi-tenancy is not used in this application
    // Always allow access
    return true;
  }
}
