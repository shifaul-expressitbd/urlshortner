import { Test, TestingModule } from '@nestjs/testing';
import { SessionService } from './session.service';
import { DatabaseService } from '../../database/database.service';
import { UsersService } from '../../users/users.service';
import { LoggerService } from 'src/utils/logger/logger.service';
import { MailService } from 'src/mail/mail.service';

// Mock DatabaseService to avoid PrismaClient import errors
jest.mock('../../database/database.service', () => {
    return {
        DatabaseService: class {
            userSession = {
                findMany: jest.fn(),
                update: jest.fn(),
                deleteMany: jest.fn(),
            };
            $transaction = jest.fn((cb) => cb(this));
        },
    };
});

describe('SessionService', () => {
  let service: SessionService;
  let prisma: DatabaseService;
  let usersService: UsersService;

  const mockUsersService = {
    findById: jest.fn(),
  };

  const mockLoggerService = {
    log: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  };

  const mockMailService = {
    sendEmail: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SessionService,
        { provide: DatabaseService, useValue: new (jest.requireMock('../../database/database.service').DatabaseService)() },
        { provide: UsersService, useValue: mockUsersService },
        { provide: LoggerService, useValue: mockLoggerService },
        { provide: MailService, useValue: mockMailService },
      ],
    }).compile();

    service = module.get<SessionService>(SessionService);
    prisma = module.get<DatabaseService>(DatabaseService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
