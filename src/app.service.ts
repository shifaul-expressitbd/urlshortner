import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { DatabaseService } from './database/database.service';

@Injectable()
export class AppService {
  constructor(
    private configService: ConfigService,
    private DatabaseService: DatabaseService,
  ) {}

  getHello(): string {
    return 'Application is running! 🚀';
  }

  private async checkApiHealth() {
    const startTime = Date.now();
    try {
      // Simple API check - just verify the service is running
      const duration = Date.now() - startTime;
      return {
        status: 'UP' as const,
        duration,
        lastChecked: new Date(),
      };
    } catch (error) {
      const duration = Date.now() - startTime;
      return {
        status: 'DOWN' as const,
        duration,
        error: error instanceof Error ? error.message : String(error),
        lastChecked: new Date(),
      };
    }
  }

  async getHealth() {
    const [apiHealth] = await Promise.all([
      this.checkApiHealth(),
    ]);

    const overallStatus =
      apiHealth.status === 'UP'
        ? 'UP'
        : 'DOWN';

    return {
      status: overallStatus,
      timestamp: new Date(),
      uptime: process.uptime(),
      environment: this.configService.get<string>('NODE_ENV', 'development'),
      version: this.configService.get<string>('npm_package_version', '1.0.0'),
      components: {
        api: apiHealth,
      },
    };
  }
}
