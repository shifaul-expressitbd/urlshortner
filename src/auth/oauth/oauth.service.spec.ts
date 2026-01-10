import { Test, TestingModule } from '@nestjs/testing';
import { OAuthService } from './oauth.service';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../../users/users.service';
import { DatabaseService } from '../../database/database.service';
import { LoggerService } from 'src/utils/logger/logger.service';
import { AuthenticationService } from '../authentication/authentication.service';
import { UrlConfigService } from 'src/config/url.config';

// Mock DatabaseService
jest.mock('../../database/database.service', () => {
    return {
        DatabaseService: class {
            authProvider = {
                findFirst: jest.fn(),
                create: jest.fn(),
                update: jest.fn(),
                delete: jest.fn(),
            };
            user = {
                findUnique: jest.fn(),
                update: jest.fn(),
            };
        },
    };
});

// Mock provider types
jest.mock('../common/types/provider.types', () => ({
    mapStringToProviderEnum: jest.fn((provider) => provider.toUpperCase()),
    AuthProviderType: {
        GOOGLE: 'GOOGLE',
        FACEBOOK: 'FACEBOOK',
        GITHUB: 'GITHUB',
    },
}));

describe('OAuthService', () => {
  let service: OAuthService;
  let authService: AuthenticationService;

  const mockConfigService = {
    get: jest.fn(),
  };

  const mockUsersService = {
    findByEmail: jest.fn(),
    create: jest.fn(),
  };

  const mockLoggerService = {
    log: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  };

  const mockAuthenticationService = {
    validateOAuthUser: jest.fn(),
  };
  
  const mockUrlConfigService = {
      getOAuthCallbackUrl: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        OAuthService,
        { provide: ConfigService, useValue: mockConfigService },
        { provide: UsersService, useValue: mockUsersService },
        { provide: DatabaseService, useValue: new (jest.requireMock('../../database/database.service').DatabaseService)() },
        { provide: LoggerService, useValue: mockLoggerService },
        { provide: AuthenticationService, useValue: mockAuthenticationService },
        { provide: UrlConfigService, useValue: mockUrlConfigService },
      ],
    }).compile();

    service = module.get<OAuthService>(OAuthService);
    authService = module.get<AuthenticationService>(AuthenticationService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
