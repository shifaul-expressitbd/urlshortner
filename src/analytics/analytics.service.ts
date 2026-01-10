import { Injectable } from '@nestjs/common';
import { DatabaseService } from '../database/database.service';
import { UAParser } from 'ua-parser-js';
import { createHash } from 'crypto';
import { DeviceType } from 'prisma/generated/client';
import * as geoip from 'geoip-lite';

interface ClickData {
  urlId: string;
  ipAddress?: string;
  userAgent?: string;
  referer?: string;
  utmSource?: string;
  utmMedium?: string;
  utmCampaign?: string;
  utmTerm?: string;
  utmContent?: string;
}

@Injectable()
export class AnalyticsService {
  constructor(private readonly prisma: DatabaseService) {}

  /**
   * Record a click with all tracking data
   */
  async recordClick(data: ClickData): Promise<void> {
    // Parse user agent
    const deviceInfo = this.parseUserAgent(data.userAgent);

    // Get location data from IP
    let geo: geoip.Lookup | null = null;
    if (data.ipAddress) {
      // Handle localhost/private IPs if needed, or just let geoip return null
      geo = geoip.lookup(data.ipAddress);
    }

    // Hash IP for unique counting
    const ipHash = data.ipAddress ? this.hashIp(data.ipAddress) : undefined;

    // Check if this is a unique click (new IP hash)
    const isUnique = await this.isUniqueClick(data.urlId, ipHash);

    // Create click record
    await this.prisma.click.create({
      data: {
        urlId: data.urlId,
        ipAddress: data.ipAddress,
        ipHash,
        userAgent: data.userAgent,
        referer: data.referer,
        country: geo?.country,
        // geoip-lite only provides country code. For full names we might need mapped list or use a different lib?
        // Actually geoip-lite usually doesn't give full country name, just code. 
        // We can leave countryName undefined or map it later. 
        // Or if we want to be fancy we can map it. 
        // For now, let's just use what we have. 
        // Wait, looking at types, Lookup result has: country, region, city.
        countryName: undefined, // Standard geoip-lite doesn't give this.
        region: geo?.region,
        city: geo?.city,
        deviceType: deviceInfo.deviceType,
        browser: deviceInfo.browser,
        browserVersion: deviceInfo.browserVersion,
        os: deviceInfo.os,
        osVersion: deviceInfo.osVersion,
        utmSource: data.utmSource,
        utmMedium: data.utmMedium,
        utmCampaign: data.utmCampaign,
        utmTerm: data.utmTerm,
        utmContent: data.utmContent,
      },
    });

    // Update URL click counts
    await this.prisma.shortenedUrl.update({
      where: { id: data.urlId },
      data: {
        totalClicks: { increment: 1 },
        ...(isUnique && { uniqueClicks: { increment: 1 } }),
        lastClickAt: new Date(),
      },
    });
  }

  /**
   * Get aggregated analytics summary for a user
   */
  async getUserAnalyticsSummary(userId: string, days: number = 30) {
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    // 1. Total Links
    const totalLinks = await this.prisma.shortenedUrl.count({
      where: { userId },
    });

    // 2. Total Clicks (All time)
    const totalClicks = await this.prisma.click.count({
      where: {
        url: { userId },
      },
    });

    // 3. Clicks in period
    const clicksInPeriod = await this.prisma.click.count({
      where: {
        url: { userId },
        createdAt: { gte: startDate },
      },
    });

    // 4. Top performing link (by clicks in period)
    const topLink = await this.prisma.shortenedUrl.findFirst({
      where: { userId },
      orderBy: {
        clicks: { _count: 'desc' },
      },
      take: 1,
      include: {
        _count: {
          select: { clicks: true },
        }
      }
    });

    return {
      totalLinks,
      totalClicks,
      clicksInPeriod,
      topLink: topLink ? {
        ...topLink,
        clicks: topLink._count.clicks
      } : null,
    };
  }

  /**
   * Get clicks timeseries for a user across all links
   */
  async getUserClicksTimeseries(userId: string, days: number = 30) {
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const clicks = await this.prisma.click.findMany({
      where: {
        url: { userId },
        createdAt: { gte: startDate },
      },
      select: { createdAt: true },
      orderBy: { createdAt: 'asc' },
    });

    // Group by date
    const dateMap = new Map<string, number>();
    clicks.forEach((click) => {
      const dateKey = click.createdAt.toISOString().split('T')[0];
      dateMap.set(dateKey, (dateMap.get(dateKey) || 0) + 1);
    });

    // Fill in missing dates
    const result: { date: string; clicks: number }[] = [];
    const current = new Date(startDate);
    const end = new Date();

    while (current <= end) {
      const dateKey = current.toISOString().split('T')[0];
      result.push({
        date: dateKey,
        clicks: dateMap.get(dateKey) || 0,
      });
      current.setDate(current.getDate() + 1);
    }

    return result;
  }

  /**
   * Get top devices for a user
   */
  async getUserDeviceBreakdown(userId: string) {
    const devices = await this.prisma.click.groupBy({
      by: ['deviceType'],
      where: { url: { userId } },
      _count: { _all: true },
      orderBy: {
        _count: {
            deviceType: 'desc' // or just _count: 'desc' depending on prisma version, but let's try sorting by count
        }
      }
    });
    // Actually standard prisma is orderBy: { _count: 'desc' } or { _count: { field: 'desc' } } logic is a bit tricky with groupBy
    // Let's try simple orderBy: { _count: 'desc' } which usually sorts by the count of the group.
    
    // Fallback: fetch and sort in JS if prisma is complaining about _all in orderBy
    const devicesUnsorted = await this.prisma.click.groupBy({
        by: ['deviceType'],
        where: { url: { userId } },
        _count: { _all: true },
    });
    
    const devicesSorted = devicesUnsorted.sort((a, b) => b._count._all - a._count._all);

    const total = devicesSorted.reduce((sum, c) => sum + c._count._all, 0);

    return devicesSorted.map((c) => ({
      name: c.deviceType || 'UNKNOWN',
      value: c._count._all,
      percentage: total > 0 ? Math.round((c._count._all / total) * 100) : 0,
    }));
  }

  /**
   * Get top locations for a user
   */
  async getUserLocationBreakdown(userId: string, limit: number = 5) {
    const locationsUnsorted = await this.prisma.click.groupBy({
      by: ['country', 'countryName'],
      where: { url: { userId } },
      _count: { _all: true },
    });

    const locations = locationsUnsorted
        .sort((a, b) => b._count._all - a._count._all)
        .slice(0, limit);

    return locations.map((l) => ({
      country: l.country || 'Unknown',
      countryName: l.countryName || 'Unknown',
      count: l._count._all,
    }));
  }

  /**
   * Get top links for a user
   */
   async getUserTopLinks(userId: string, limit: number = 5) {
     const links = await this.prisma.shortenedUrl.findMany({
       where: { userId },
       include: {
         _count: {
           select: { clicks: true }
         }
       },
       orderBy: {
         totalClicks: 'desc'
       },
       take: limit
     });

     return links.map(link => ({
       id: link.id,
       originalUrl: link.originalUrl,
       shortCode: link.shortCode,
       title: link.title,
       clicks: link.totalClicks, // Use totalClicks which is aggregated
       createdAt: link.createdAt
     }));
   }

  /**
   * Get analytics summary for a URL
   */
  async getAnalyticsSummary(urlId: string, days: number = 30) {
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const [url, totalClicks, uniqueClicks, recentClicks] = await Promise.all([
      this.prisma.shortenedUrl.findUnique({
        where: { id: urlId },
        select: { totalClicks: true, uniqueClicks: true, lastClickAt: true, createdAt: true },
      }),
      this.prisma.click.count({
        where: { urlId, createdAt: { gte: startDate } },
      }),
      this.prisma.click.groupBy({
        by: ['ipHash'],
        where: { urlId, createdAt: { gte: startDate } },
      }),
      this.prisma.click.findMany({
        where: { urlId, createdAt: { gte: startDate } },
        orderBy: { createdAt: 'desc' },
        take: 10,
        select: {
          createdAt: true,
          country: true,
          city: true,
          deviceType: true,
          browser: true,
          referer: true,
        },
      }),
    ]);

    return {
      allTime: {
        totalClicks: url?.totalClicks || 0,
        uniqueClicks: url?.uniqueClicks || 0,
      },
      period: {
        days,
        totalClicks,
        uniqueClicks: uniqueClicks.length,
      },
      lastClickAt: url?.lastClickAt,
      createdAt: url?.createdAt,
      recentClicks,
    };
  }

  /**
   * Get clicks over time (timeseries data)
   */
  async getClicksTimeseries(urlId: string, days: number = 30) {
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const clicks = await this.prisma.click.findMany({
      where: { urlId, createdAt: { gte: startDate } },
      select: { createdAt: true },
      orderBy: { createdAt: 'asc' },
    });

    // Group by date
    const dateMap = new Map<string, number>();
    clicks.forEach((click) => {
      const dateKey = click.createdAt.toISOString().split('T')[0];
      dateMap.set(dateKey, (dateMap.get(dateKey) || 0) + 1);
    });

    // Fill in missing dates
    const result: { date: string; clicks: number }[] = [];
    const current = new Date(startDate);
    const end = new Date();

    while (current <= end) {
      const dateKey = current.toISOString().split('T')[0];
      result.push({
        date: dateKey,
        clicks: dateMap.get(dateKey) || 0,
      });
      current.setDate(current.getDate() + 1);
    }

    return result;
  }

  /**
   * Get top referrers
   */
  async getTopReferrers(urlId: string, limit: number = 10) {
    const clicks = await this.prisma.click.groupBy({
      by: ['referer'],
      where: { urlId, referer: { not: null } },
      _count: { id: true },
      orderBy: { _count: { id: 'desc' } },
      take: limit,
    });

    return clicks
      .filter((c) => c.referer)
      .map((c) => ({
        referer: c.referer,
        clicks: c._count.id,
      }));
  }

  /**
   * Get device breakdown
   */
  async getDeviceBreakdown(urlId: string) {
    const clicks = await this.prisma.click.groupBy({
      by: ['deviceType'],
      where: { urlId },
      _count: { id: true },
    });

    const total = clicks.reduce((sum, c) => sum + c._count.id, 0);

    return clicks.map((c) => ({
      deviceType: c.deviceType || 'UNKNOWN',
      clicks: c._count.id,
      percentage: total > 0 ? Math.round((c._count.id / total) * 100) : 0,
    }));
  }

  /**
   * Get browser breakdown
   */
  async getBrowserBreakdown(urlId: string, limit: number = 10) {
    const clicks = await this.prisma.click.groupBy({
      by: ['browser'],
      where: { urlId },
      _count: { id: true },
      orderBy: { _count: { id: 'desc' } },
      take: limit,
    });

    return clicks
      .filter((c) => c.browser)
      .map((c) => ({
        browser: c.browser,
        clicks: c._count.id,
      }));
  }

  /**
   * Get geographic breakdown
   */
  async getLocationBreakdown(urlId: string, limit: number = 10) {
    const clicks = await this.prisma.click.groupBy({
      by: ['country', 'countryName'],
      where: { urlId },
      _count: { id: true },
      orderBy: { _count: { id: 'desc' } },
      take: limit,
    });

    return clicks
      .filter((c) => c.country)
      .map((c) => ({
        country: c.country,
        countryName: c.countryName,
        clicks: c._count.id,
      }));
  }

  /**
   * Parse user agent string
   */
  private parseUserAgent(userAgent?: string): {
    deviceType: DeviceType;
    browser?: string;
    browserVersion?: string;
    os?: string;
    osVersion?: string;
  } {
    if (!userAgent) {
      return { deviceType: DeviceType.UNKNOWN };
    }

    const parser = new UAParser(userAgent);
    const result = parser.getResult();

    // Determine device type
    let deviceType: DeviceType = DeviceType.DESKTOP;
    const deviceTypeStr = result.device.type?.toLowerCase();
    
    if (deviceTypeStr === 'mobile') {
      deviceType = DeviceType.MOBILE;
    } else if (deviceTypeStr === 'tablet') {
      deviceType = DeviceType.TABLET;
    } else if (this.isBot(userAgent)) {
      deviceType = DeviceType.BOT;
    }

    return {
      deviceType,
      browser: result.browser.name,
      browserVersion: result.browser.version,
      os: result.os.name,
      osVersion: result.os.version,
    };
  }

  /**
   * Check if user agent is a bot
   */
  private isBot(userAgent: string): boolean {
    const botPatterns = [
      'bot', 'crawler', 'spider', 'slurp', 'googlebot',
      'bingbot', 'yandex', 'baidu', 'duckduck', 'facebookexternalhit',
      'twitterbot', 'linkedinbot', 'whatsapp', 'telegram', 'curl', 'wget',
    ];
    const ua = userAgent.toLowerCase();
    return botPatterns.some((pattern) => ua.includes(pattern));
  }

  /**
   * Hash IP address for privacy-preserving unique counting
   */
  private hashIp(ip: string): string {
    return createHash('sha256').update(ip).digest('hex');
  }

  /**
   * Check if this is a unique click
   */
  private async isUniqueClick(urlId: string, ipHash?: string): Promise<boolean> {
    if (!ipHash) return true;

    const existing = await this.prisma.click.findFirst({
      where: { urlId, ipHash },
    });

    return !existing;
  }
}
