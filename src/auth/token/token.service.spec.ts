import { Test, TestingModule } from '@nestjs/testing';
import { TokenService } from './token.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { DatabaseService } from '../../database/database.service';
import { UsersService } from '../../users/users.service';
import { IpGeolocationService } from '../common/services/ip-geolocation.service';
import { UnauthorizedException } from '@nestjs/common';

// Mock DatabaseService to avoid PrismaClient import errors
jest.mock('../../database/database.service', () => {
    return {
        DatabaseService: class {
            userSession = {
                create: jest.fn(),
                findUnique: jest.fn(),
                update: jest.fn(),
            };
        },
    };
});

describe('TokenService', () => {
  let service: TokenService;
  let jwtService: JwtService;
  let configService: ConfigService;
  let prisma: DatabaseService;

  const mockJwtService = {
    signAsync: jest.fn(),
    verifyAsync: jest.fn(),
  };

  const mockConfigService = {
    get: jest.fn(),
  };

  const mockDatabaseService = {
    userSession: {
      create: jest.fn(),
      findUnique: jest.fn(),
      update: jest.fn(),
    },
  };

  const mockUsersService = {
    findById: jest.fn(),
  };

  const mockIpGeolocationService = {
    detectGeolocation: jest.fn().mockResolvedValue({}),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TokenService,
        { provide: JwtService, useValue: mockJwtService },
        { provide: ConfigService, useValue: mockConfigService },
        { provide: DatabaseService, useValue: mockDatabaseService },
        { provide: UsersService, useValue: mockUsersService },
        { provide: IpGeolocationService, useValue: mockIpGeolocationService },
      ],
    }).compile();

    service = module.get<TokenService>(TokenService);
    jwtService = module.get<JwtService>(JwtService);
    configService = module.get<ConfigService>(ConfigService);
    prisma = module.get<DatabaseService>(DatabaseService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('generateTokens', () => {
    it('should generate access and refresh tokens', async () => {
      mockConfigService.get.mockReturnValue('super-secret-key-that-is-long-enough');
      mockJwtService.signAsync.mockResolvedValue('mock-token');
      mockDatabaseService.userSession.create.mockResolvedValue({
        id: 'session-id',
        sessionId: 'session-uuid',
      });

      const result = await service.generateTokens(
        'user-id',
        'test@example.com',
        ['user'],
      );

      expect(result).toHaveProperty('accessToken', 'mock-token');
      expect(result).toHaveProperty('refreshToken', 'mock-token');
      expect(result).toHaveProperty('session');
      expect(mockDatabaseService.userSession.create).toHaveBeenCalled();
    });

    it('should throw error if JWT secret is missing', async () => {
      mockConfigService.get.mockReturnValue(null);

      await expect(
        service.generateTokens('user-id', 'test@example.com', ['user']),
      ).rejects.toThrow('JWT secrets missing');
    });
  });

  describe('validateAndConsumeRefreshToken', () => {
    it('should validate and return session', async () => {
      mockConfigService.get.mockReturnValue('super-secret-key');
      mockJwtService.verifyAsync.mockResolvedValue({ sessionId: 'session-uuid' });
      mockDatabaseService.userSession.findUnique.mockResolvedValue({
        id: 'session-id',
        sessionId: 'session-uuid',
        isActive: true,
        expiresAt: new Date(Date.now() + 10000),
      });

      const result = await service.validateAndConsumeRefreshToken(
        'valid-token',
        'user-id',
      );

      expect(result.session).toBeDefined();
      expect(mockDatabaseService.userSession.update).toHaveBeenCalled();
    });

    it('should throw UnauthorizedException if session not found', async () => {
      mockConfigService.get.mockReturnValue('super-secret-key');
      mockJwtService.verifyAsync.mockResolvedValue({ sessionId: 'session-uuid' });
      mockDatabaseService.userSession.findUnique.mockResolvedValue(null);

      await expect(
        service.validateAndConsumeRefreshToken('token', 'user-id'),
      ).rejects.toThrow(UnauthorizedException);
    });
  });
});
