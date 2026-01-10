import { Injectable, OnModuleInit } from '@nestjs/common';
import { AsyncLocalStorage } from 'async_hooks';

export interface RequestContext {
  storeId?: string; // Tenant ID
  userId?: string;
  requestId: string;
}

@Injectable()
export class ContextService implements OnModuleInit {
  private static readonly als = new AsyncLocalStorage<RequestContext>();

  onModuleInit() {
    // No-op init
  }

  static run(ctx: RequestContext, callback: () => any) {
    return this.als.run(ctx, callback);
  }

  static get<K extends keyof RequestContext>(key: K): RequestContext[K] | undefined {
    const store = this.als.getStore();
    return store ? store[key] : undefined;
  }

  static getStore(): RequestContext | undefined {
    return this.als.getStore();
  }

  static getTenantId(): string | undefined {
    return this.get('storeId');
  }

  static getUserId(): string | undefined {
    return this.get('userId');
  }

  static getRequestId(): string | undefined {
    return this.get('requestId');
  }
}
