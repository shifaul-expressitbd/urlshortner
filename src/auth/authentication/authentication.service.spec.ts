import { Test, TestingModule } from '@nestjs/testing';
import { AuthenticationService } from './authentication.service';
import { UsersService } from 'src/users/users.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { MailService } from 'src/mail/mail.service';
import { DatabaseService } from 'src/database/database.service';
import { LoggerService } from 'src/utils/logger/logger.service';
import { IpGeolocationService } from '../common/services/ip-geolocation.service';
import { BadRequestException, ConflictException, UnauthorizedException, InternalServerErrorException } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';

// --- MOCK DATA STUBS ---
const mockUser = {
  id: 'user-123',
  email: 'test@example.com',
  password: 'hashed-password',
  firstName: 'Test',
  lastName: 'User',
  isEmailVerified: false,
  verificationToken: 'valid-token',
  roles: ['user'],
};

const mockVerifiedUser = { ...mockUser, isEmailVerified: true, verificationToken: null };

const mockTokens = {
  accessToken: 'access-token-123',
  refreshToken: 'refresh-token-123',
  session: { sessionId: 'session-123' },
};

// --- DEPENDENCY STUBS (No Logic Mocks) ---
class UsersServiceStub {
  findByEmail(email: string) {
    if (email === 'test@example.com') return Promise.resolve(mockUser);
    if (email === 'verified@example.com') return Promise.resolve(mockVerifiedUser);
    // Return null for new registration
    return Promise.resolve(null);
  }

  create(data: any) {
    // Return a user with 'new-user-id'
    return Promise.resolve({ ...mockUser, ...data, id: 'new-user-id' });
  }

  markEmailAsVerified(id: string) {
    return Promise.resolve({ user: mockVerifiedUser, wasAlreadyVerified: false });
  }

  resetPassword(id: string, hash: string) {
    return Promise.resolve({ ...mockVerifiedUser, password: hash });
  }
}

class JwtServiceStub {
  signAsync(payload: any) {
    return Promise.resolve('mock-jwt-token');
  }
}

class ConfigServiceStub {
  get(key: string) {
    if (key === 'JWT_SECRET') return 'so-secret';
    if (key === 'jwt.accessTokenExpiresInSeconds') return 3600;
    return null;
  }
}

class MailServiceStub {
  // Method names MUST match what AuthenticationService calls on the injected MailService
  async sendVerificationEmail(email: string, token: string) {
    return Promise.resolve();
  }
  async sendPasswordResetEmail(email: string, token: string) {
      return Promise.resolve();
  }
}

class DatabaseServiceStub {
  authProvider = {
    create: () => Promise.resolve({}),
    findUnique: () => Promise.resolve(null), // Default null means no existing provider
    findFirst: () => Promise.resolve({ provider: 'local' }),
    update: () => Promise.resolve({}),
    updateMany: () => Promise.resolve({}),
    count: () => Promise.resolve(0),
  };
  user = {
      findUnique: (args: any) => {
          // Allow finding the newly created user 'new-user-id'
          if (args.where.id === 'new-user-id') {
              return Promise.resolve({ 
                  ...mockUser, 
                  email: 'new@example.com', // Fix email for new user
                  id: args.where.id,
                  authProviders: [{ provider: 'local', isPrimary: true }] 
              });
          }
          if (args.where.id === 'user-123') {
              return Promise.resolve({ 
                  ...mockUser, 
                  id: args.where.id,
                  authProviders: [{ provider: 'local', isPrimary: true }] 
              });
          }
          return Promise.resolve(null);
      }
  };
  userSession = {
    create: () => Promise.resolve({ sessionId: 'session-123' }),
  };
  passwordResetRequest = {
      create: () => Promise.resolve({}),
      findUnique: (args: any) => {
          if (args.where.token === 'valid-reset-token') {
              return Promise.resolve({ 
                  id: 'req-1', 
                  userId: 'user-123', 
                  expiresAt: new Date(Date.now() + 10000),
                  usedAt: null,
                  user: mockUser // Nested user object required by resetPassword
              });
          }
           if (args.where.token === 'expired-token') {
              return Promise.resolve({ 
                  id: 'req-2', 
                  userId: 'user-123', 
                  expiresAt: new Date(Date.now() - 10000),
                  usedAt: null,
                  user: mockUser
              });
          }
          return Promise.resolve(null);
      },
      update: () => Promise.resolve({})
  }
}

class LoggerServiceStub {
  log() {}
  error() {}
  warn() {}
  debug() {} 
}

class IpGeolocationServiceStub {
  detectGeolocation() {
    return Promise.resolve({});
  }
}

// --- MOCK BCRYPT ---
jest.mock('bcryptjs', () => ({
  compare: jest.fn().mockResolvedValue(true),
  hash: jest.fn().mockResolvedValue('hashed-password'),
}));

// --- TEST SUITE ---
describe('AuthenticationService (Workflow)', () => {
  let service: AuthenticationService;

  beforeAll(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthenticationService,
        { provide: UsersService, useClass: UsersServiceStub },
        { provide: JwtService, useClass: JwtServiceStub },
        { provide: ConfigService, useClass: ConfigServiceStub },
        { provide: MailService, useClass: MailServiceStub },
        { provide: DatabaseService, useClass: DatabaseServiceStub },
        { provide: LoggerService, useClass: LoggerServiceStub },
        { provide: IpGeolocationService, useClass: IpGeolocationServiceStub },
      ],
    }).compile();

    service = module.get<AuthenticationService>(AuthenticationService);
  });

  // 1. REGISTRATION WORKFLOW
  describe('1. Registration Workflow', () => {
    it('RG-01: Should register a new user successfully', async () => {
      const dto = {
        email: 'new@example.com',
        password: 'password123',
        firstName: 'New',
        lastName: 'User',
      };
      
      const result = await service.register(dto);
      
      expect(result.user).toBeDefined();
      expect(result.user.email).toBe(dto.email);
    });

    it('RG-05: Should throw BadRequest if password is too short', async () => {
       const dto = {
        email: 'new@example.com',
        password: 'short',
        firstName: 'New',
        lastName: 'User',
      };
      
      await expect(service.register(dto)).rejects.toThrow(BadRequestException);
    });

    it('RG-11: Should throw Conflict if user already exists', async () => {
       const dto = {
        email: 'test@example.com',
        password: 'password123',
        firstName: 'Exist',
        lastName: 'User',
      };
      
      await expect(service.register(dto)).rejects.toThrow(ConflictException);
    });
  });

  // 3. LOGIN WORKFLOW
  describe('3. Login Workflow', () => {
      it('LG-01: Should login successfully with valid credentials', async () => {
          const loginDto = {
             email: 'verified@example.com',
             password: 'password123'
          };

          const user = await service.validateUser(loginDto.email, loginDto.password);
          expect(user).toBeDefined();

          const result = await service.login(user); 
          const authResult = result as any; 

          expect(authResult.accessToken).toBeDefined();
          expect(authResult.refreshToken).toBeDefined();
      });

      it('LG-03: Should throw Unauthorized if password invalid', async () => {
           require('bcryptjs').compare.mockResolvedValueOnce(false);
           
           await expect(service.validateUser('verified@example.com', 'wrongpass'))
            .rejects.toThrow(UnauthorizedException);
      });

      it('LG-06: Should throw Unauthorized/Forbidden if email not verified', async () => {
           require('bcryptjs').compare.mockResolvedValueOnce(true);

           await expect(service.validateUser('test@example.com', 'password'))
            .rejects.toThrow(UnauthorizedException);
      });
  });

  // 6. PASSWORD RECOVERY LOOP
  describe('6. Password Recovery', () => {
      it('PR-01: Should request password reset successfully', async () => {
          const email = 'verified@example.com';
          await expect(service.requestPasswordReset(email)).resolves.not.toThrow();
      });

       it('PR-03: Should handle non-existent email gracefully (Security)', async () => {
          const email = 'unknown@example.com';
          await expect(service.requestPasswordReset(email)).resolves.not.toThrow();
      });

      it('PR-05: Should reset password with valid token', async () => {
          const token = 'valid-reset-token';
          const newPass = 'newPassword123';
          
          await expect(service.resetPassword(token, newPass)).resolves.not.toThrow();
      });

       it('PR-06: Should fail reset with invalid/expired token', async () => {
          const token = 'expired-token';
          const newPass = 'newPassword123';
          
          await expect(service.resetPassword(token, newPass)).rejects.toThrow(BadRequestException);
      });
  });
});
