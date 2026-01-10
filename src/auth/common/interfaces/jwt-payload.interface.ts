export interface JwtPayload {
  sub: string;
  email: string;
  role?: string;
  systemRole?: string;
  type?: string;
  permissions?: string[];
  iat?: number;
  exp?: number;
  impersonatedBy?: string;
  rememberMe?: boolean;
  impersonatorEmail?: string;
  isImpersonation?: boolean;
  sessionId?: string;
  tokenFamily?: string;
}
