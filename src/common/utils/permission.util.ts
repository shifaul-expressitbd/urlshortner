import { ForbiddenException } from '@nestjs/common';
import { SystemRole } from 'prisma/generated/client';

/**
 * Permission utility class for consistent role-based access control
 * Checks SystemRole for global permissions.
 */
export class PermissionUtils {
  /**
   * Check if user has admin role
   */
  static isAdmin(systemRole: string): boolean {
    return systemRole === SystemRole.SYSTEM_ADMIN;
  }

  /**
   * Check if user has staff role (admin, staff, or support agent)
   */
  static isStaff(systemRole: string): boolean {
    return (
      systemRole === SystemRole.SYSTEM_ADMIN || 
      systemRole === SystemRole.SYSTEM_DEVELOPER || 
      systemRole === SystemRole.SYSTEM_AGENT
    );
  }

  /**
   * Check if user has support agent role
   */
  static isSupportAgent(systemRole: string): boolean {
    return systemRole === SystemRole.SYSTEM_AGENT || 
           systemRole === SystemRole.SYSTEM_ADMIN;
  }

  /**
   * Check if user has developer role
   */
  static isDeveloper(systemRole: string): boolean {
    return systemRole === SystemRole.SYSTEM_DEVELOPER || 
           systemRole === SystemRole.SYSTEM_ADMIN;
  }

  /**
   * Check if user has any of the specified roles
   */
  static hasAnyRole(role: string, requiredRoles: string[]): boolean {
    return requiredRoles.includes(role);
  }

  /**
   * Check if user has all of the specified roles
   * Note: With singular role, this only passes if requiredRoles contains only the user's role or is empty.
   */
  static hasAllRoles(role: string, requiredRoles: string[]): boolean {
    return requiredRoles.every(r => r === role);
  }

  /**
   * Check if user has explicit tenant role or system override
   * Note: Multi-tenancy is not currently used in URL shortener
   */
  static hasTenantRole(systemRole: string, tenantRole: string | null, requiredRole: string): boolean {
      if (systemRole === SystemRole.SYSTEM_ADMIN) return true;
      return tenantRole === requiredRole;
  }

  /**
   * Throw ForbiddenException if user doesn't have required role
   */
  static requireRole(role: string, requiredRole: string): void {
    if (role !== requiredRole) {
      throw new ForbiddenException(`Access denied. Required role: ${requiredRole}`);
    }
  }

  /**
   * Throw ForbiddenException if user doesn't have any of the required roles
   */
  static requireAnyRole(role: string, requiredRoles: string[]): void {
    if (!this.hasAnyRole(role, requiredRoles)) {
      throw new ForbiddenException(`Access denied. Required roles: ${requiredRoles.join(', ')}`);
    }
  }

  /**
   * Throw ForbiddenException if user doesn't have admin role
   */
  static requireAdmin(systemRole: string): void {
    if (!this.isAdmin(systemRole)) {
      throw new ForbiddenException('Access denied. Admin role required.');
    }
  }

  /**
   * Throw ForbiddenException if user doesn't have staff role
   */
  static requireStaff(systemRole: string): void {
    if (!this.isStaff(systemRole)) {
      throw new ForbiddenException('Access denied. Staff role required.');
    }
  }

  /**
   * Throw ForbiddenException if user doesn't have support agent role
   */
  static requireSupportAgent(systemRole: string): void {
    if (!this.isSupportAgent(systemRole)) {
      throw new ForbiddenException('Access denied. Support agent role required.');
    }
  }

  /**
   * Throw ForbiddenException if user doesn't have developer role
   */
  static requireDeveloper(systemRole: string): void {
    if (!this.isDeveloper(systemRole)) {
      throw new ForbiddenException('Access denied. Developer role required.');
    }
  }

  /**
   * Get user permission level (0=user, 1=support, 2=staff, 3=admin, 4=developer)
   */
  static getPermissionLevel(systemRole: string): number {
    if (this.isDeveloper(systemRole)) return 4;
    if (this.isAdmin(systemRole)) return 3;
    if (this.isStaff(systemRole)) return 2;
    if (this.isSupportAgent(systemRole)) return 1;
    return 0;
  }

  /**
   * Check if user has minimum permission level
   */
  static hasMinPermissionLevel(systemRole: string, minLevel: number): boolean {
    return this.getPermissionLevel(systemRole) >= minLevel;
  }

  /**
   * Throw ForbiddenException if user doesn't have minimum permission level
   */
  static requireMinPermissionLevel(systemRole: string, minLevel: number): void {
    if (!this.hasMinPermissionLevel(systemRole, minLevel)) {
      throw new ForbiddenException(`Access denied. Minimum permission level required: ${minLevel}`);
    }
  }
}

/**
 * Custom exception for permission errors
 */
export class PermissionException extends ForbiddenException {
  constructor(message: string, code?: string) {
    super(message, code);
  }
}

/**
 * Decorator for requiring specific roles
 */
export function RequireRoles(...roles: string[]) {
  return (target: any, propertyName: string, descriptor: PropertyDescriptor) => {
    const originalMethod = descriptor.value;
    
    descriptor.value = function (...args: any[]) {
      // Try to find user in arguments. Looking for object with id and systemRole.
      const user = args.find(arg => arg?.id && typeof arg?.systemRole === 'string');
      
      if (!user) {
         // Fallback: looking for object with id and role? No, we require systemRole now.
         throw new PermissionException('User authentication required (missing systemRole)');
      }
      
      PermissionUtils.requireAnyRole(user.systemRole, roles);
      return originalMethod.apply(this, args);
    };
  };
}