import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { ContextService } from '../services/context.service';

export const Tenantcontext = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    // Try getting from ContextService first (CLS)
    const tid = ContextService.getTenantId();
    if (tid) return tid;

    // Fallback to Request object (if middleware set it)
    const request = ctx.switchToHttp().getRequest();
    return request.tenantId || request.headers['x-tenant-id'];
  },
);
