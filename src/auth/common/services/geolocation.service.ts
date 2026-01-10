// Enhanced geolocation service to replace hardcoded timezone detection
// Provides accurate location-based security features

import { Injectable, Logger } from '@nestjs/common';
import * as dns from 'dns/promises';
import * as net from 'net';

export interface GeolocationData {
  latitude?: number;
  longitude?: number;
  timezone?: string;
  location?: string;
  country?: string;
  region?: string;
  city?: string;
  accuracy?: 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface IPLocationResult {
  location: string;
  timezone: string;
  coordinates?: { lat: number; lng: number };
  confidence: number;
  isReliable: boolean;
}

interface IPRange {
  start: number;
  end: number;
  timezone?: string;
}

@Injectable()
export class GeolocationService {
  private readonly logger = new Logger(GeolocationService.name);
  
  // IP range definitions for private networks
  private readonly privateIPRanges: IPRange[] = [
    { start: ipToLong('10.0.0.0'), end: ipToLong('10.255.255.255') },
    { start: ipToLong('172.16.0.0'), end: ipToLong('172.31.255.255') },
    { start: ipToLong('192.168.0.0'), end: ipToLong('192.168.255.255') },
    { start: ipToLong('127.0.0.0'), end: ipToLong('127.255.255.255') },
    { start: ipToLong('169.254.0.0'), end: ipToLong('169.254.255.255') },
    { start: ipToLong('::1'), end: ipToLong('::1') },
    { start: ipToLong('fc00::'), end: ipToLong('fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff') },
    { start: ipToLong('fe80::'), end: ipToLong('febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff') },
  ];

  // Timezone mapping with more comprehensive coverage
  private readonly timezoneMapping = {
    // North America
    'America/New_York': { location: 'New York, US', lat: 40.7128, lng: -74.0060 },
    'America/Chicago': { location: 'Chicago, US', lat: 41.8781, lng: -87.6298 },
    'America/Denver': { location: 'Denver, US', lat: 39.7392, lng: -104.9903 },
    'America/Los_Angeles': { location: 'Los Angeles, US', lat: 34.0522, lng: -118.2437 },
    'America/Phoenix': { location: 'Phoenix, US', lat: 33.4484, lng: -112.0740 },
    'America/Anchorage': { location: 'Anchorage, US', lat: 61.2181, lng: -149.9003 },
    'Pacific/Honolulu': { location: 'Honolulu, US', lat: 21.3099, lng: -157.8581 },
    'America/Toronto': { location: 'Toronto, CA', lat: 43.6532, lng: -79.3832 },
    'America/Vancouver': { location: 'Vancouver, CA', lat: 49.2827, lng: -123.1207 },
    'America/Mexico_City': { location: 'Mexico City, MX', lat: 19.4326, lng: -99.1332 },

    // Europe
    'Europe/London': { location: 'London, UK', lat: 51.5074, lng: -0.1278 },
    'Europe/Dublin': { location: 'Dublin, IE', lat: 53.3498, lng: -6.2603 },
    'Europe/Paris': { location: 'Paris, FR', lat: 48.8566, lng: 2.3522 },
    'Europe/Berlin': { location: 'Berlin, DE', lat: 52.5200, lng: 13.4050 },
    'Europe/Amsterdam': { location: 'Amsterdam, NL', lat: 52.3676, lng: 4.9041 },
    'Europe/Brussels': { location: 'Brussels, BE', lat: 50.8503, lng: 4.3517 },
    'Europe/Madrid': { location: 'Madrid, ES', lat: 40.4168, lng: -3.7038 },
    'Europe/Rome': { location: 'Rome, IT', lat: 41.9028, lng: 12.4964 },
    'Europe/Vienna': { location: 'Vienna, AT', lat: 48.2082, lng: 16.3738 },
    'Europe/Stockholm': { location: 'Stockholm, SE', lat: 59.3293, lng: 18.0686 },
    'Europe/Oslo': { location: 'Oslo, NO', lat: 59.9139, lng: 10.7522 },
    'Europe/Copenhagen': { location: 'Copenhagen, DK', lat: 55.6761, lng: 12.5683 },
    'Europe/Helsinki': { location: 'Helsinki, FI', lat: 60.1699, lng: 24.9384 },
    'Europe/Warsaw': { location: 'Warsaw, PL', lat: 52.2297, lng: 21.0122 },
    'Europe/Prague': { location: 'Prague, CZ', lat: 50.0755, lng: 14.4378 },
    'Europe/Budapest': { location: 'Budapest, HU', lat: 47.4979, lng: 19.0402 },
    'Europe/Bucharest': { location: 'Bucharest, RO', lat: 44.4268, lng: 26.1025 },
    'Europe/Athens': { location: 'Athens, GR', lat: 37.9838, lng: 23.7275 },
    'Europe/Lisbon': { location: 'Lisbon, PT', lat: 38.7223, lng: -9.1393 },
    'Europe/Zurich': { location: 'Zurich, CH', lat: 47.3769, lng: 8.5417 },

    // Asia
    'Asia/Tokyo': { location: 'Tokyo, Japan', lat: 35.6762, lng: 139.6503 },
    'Asia/Seoul': { location: 'Seoul, South Korea', lat: 37.5665, lng: 126.9780 },
    'Asia/Shanghai': { location: 'Shanghai, China', lat: 31.2304, lng: 121.4737 },
    'Asia/Hong_Kong': { location: 'Hong Kong', lat: 22.3193, lng: 114.1694 },
    'Asia/Singapore': { location: 'Singapore', lat: 1.3521, lng: 103.8198 },
    'Asia/Kuala_Lumpur': { location: 'Kuala Lumpur, MY', lat: 3.1390, lng: 101.6869 },
    'Asia/Bangkok': { location: 'Bangkok, Thailand', lat: 13.7563, lng: 100.5018 },
    'Asia/Jakarta': { location: 'Jakarta, Indonesia', lat: -6.2088, lng: 106.8456 },
    'Asia/Manila': { location: 'Manila, Philippines', lat: 14.5995, lng: 120.9842 },
    'Asia/Taipei': { location: 'Taipei, Taiwan', lat: 25.0330, lng: 121.5654 },
    'Asia/Dubai': { location: 'Dubai, UAE', lat: 25.2048, lng: 55.2708 },
    'Asia/Kolkata': { location: 'Kolkata, India', lat: 22.5726, lng: 88.3639 },
    'Asia/Tehran': { location: 'Tehran, Iran', lat: 35.6892, lng: 51.3890 },
    'Asia/Jerusalem': { location: 'Jerusalem, Israel', lat: 31.7683, lng: 35.2137 },
    'Asia/Riyadh': { location: 'Riyadh, Saudi Arabia', lat: 24.7136, lng: 46.6753 },
    'Asia/Qatar': { location: 'Doha, Qatar', lat: 25.2854, lng: 51.5310 },
    'Asia/Karachi': { location: 'Karachi, Pakistan', lat: 24.8607, lng: 67.0011 },
    'Asia/Dhaka': { location: 'Dhaka, Bangladesh', lat: 23.8103, lng: 90.4125 },

    // Oceania
    'Australia/Sydney': { location: 'Sydney, Australia', lat: -33.8688, lng: 151.2093 },
    'Australia/Melbourne': { location: 'Melbourne, Australia', lat: -37.8136, lng: 144.9631 },
    'Australia/Brisbane': { location: 'Brisbane, Australia', lat: -27.4698, lng: 153.0251 },
    'Australia/Perth': { location: 'Perth, Australia', lat: -31.9505, lng: 115.8605 },
    'Pacific/Auckland': { location: 'Auckland, New Zealand', lat: -36.8485, lng: 174.7633 },
    'Pacific/Fiji': { location: 'Suva, Fiji', lat: -18.1248, lng: 178.4501 },

    // Africa
    'Africa/Cairo': { location: 'Cairo, Egypt', lat: 30.0444, lng: 31.2357 },
    'Africa/Lagos': { location: 'Lagos, Nigeria', lat: 6.5244, lng: 3.3792 },
    'Africa/Johannesburg': { location: 'Johannesburg, South Africa', lat: -26.2041, lng: 28.0473 },
    'Africa/Nairobi': { location: 'Nairobi, Kenya', lat: -1.2921, lng: 36.8219 },
    'Africa/Casablanca': { location: 'Casablanca, Morocco', lat: 33.5731, lng: -7.5898 },
    'Africa/Algiers': { location: 'Algiers, Algeria', lat: 36.7538, lng: 3.0588 },
    'Africa/Addis_Ababa': { location: 'Addis Ababa, Ethiopia', lat: 8.9806, lng: 38.7578 },
    'Africa/Accra': { location: 'Accra, Ghana', lat: 5.6037, lng: -0.1870 },

    // South America
    'America/Sao_Paulo': { location: 'São Paulo, Brazil', lat: -23.5505, lng: -46.6333 },
    'America/Argentina/Buenos_Aires': { location: 'Buenos Aires, Argentina', lat: -34.6037, lng: -58.3816 },
    'America/Santiago': { location: 'Santiago, Chile', lat: -33.4489, lng: -70.6693 },
    'America/Lima': { location: 'Lima, Peru', lat: -12.0464, lng: -77.0428 },
    'America/Bogota': { location: 'Bogotá, Colombia', lat: 4.7110, lng: -74.0721 },
    'America/Quito': { location: 'Quito, Ecuador', lat: -0.1807, lng: -78.4678 },
    'America/Caracas': { location: 'Caracas, Venezuela', lat: 10.4806, lng: -66.9036 },
    'America/Montevideo': { location: 'Montevideo, Uruguay', lat: -34.9011, lng: -56.1645 },
    'America/Asuncion': { location: 'Asunción, Paraguay', lat: -25.2637, lng: -57.5759 },
    'America/La_Paz': { location: 'La Paz, Bolivia', lat: -16.4897, lng: -68.1193 },

    // Others
    'UTC': { location: 'Unknown', lat: 0, lng: 0 },
  };

  /**
   * Detects geolocation from IP address with improved accuracy
   */
  async detectGeolocation(ipAddress: string): Promise<GeolocationData> {
    try {
      // Handle special cases
      if (!ipAddress || ipAddress === 'unknown' || ipAddress === '::1') {
        return this.getDefaultGeolocation('Local Network');
      }

      // Check if it's a private IP
      if (this.isPrivateIP(ipAddress)) {
        return this.getDefaultGeolocation('Local Network');
      }

      // Enhanced IP-based geolocation
      const locationResult = await this.enhancedIPLookup(ipAddress);
      
      return {
        latitude: locationResult.coordinates?.lat,
        longitude: locationResult.coordinates?.lng,
        timezone: locationResult.timezone,
        location: locationResult.location,
        accuracy: locationResult.confidence > 0.8 ? 'HIGH' : 
                  locationResult.confidence > 0.5 ? 'MEDIUM' : 'LOW',
        country: this.extractCountryFromLocation(locationResult.location),
        region: this.extractRegionFromLocation(locationResult.location),
        city: this.extractCityFromLocation(locationResult.location),
      };
    } catch (error) {
      this.logger.warn(`Failed to detect geolocation for IP ${ipAddress}:`, error);
      return this.getDefaultGeolocation('Unknown');
    }
  }

  /**
   * Enhanced IP lookup using multiple strategies
   */
  private async enhancedIPLookup(ipAddress: string): Promise<IPLocationResult> {
    // Strategy 1: DNS reverse lookup for more detailed info
    try {
      const reverseLookup = await this.reverseDNSCheck(ipAddress);
      if (reverseLookup) {
        return reverseLookup;
      }
    } catch (error) {
      // Continue to next strategy
    }

    // Strategy 2: IP range-based approximation
    const rangeBased = this.ipRangeBasedLookup(ipAddress);
    if (rangeBased) {
      return rangeBased;
    }

    // Strategy 3: Default fallback
    return {
      location: 'Unknown',
      timezone: 'UTC',
      confidence: 0.1,
      isReliable: false,
    };
  }

  /**
   * Reverse DNS lookup to get more detailed location information
   */
  private async reverseDNSCheck(ipAddress: string): Promise<IPLocationResult | null> {
    try {
      const hostname = await dns.reverse(ipAddress);
      
      // Parse hostname for location hints
      const hostParts = hostname[0]?.toLowerCase().split('.') || [];
      
      // Common patterns in hostnames that indicate location
      for (const part of hostParts) {
        if (part.includes('nyc') || part.includes('newyork')) {
          return this.getTimezoneResult('America/New_York', 0.9);
        }
        if (part.includes('la') || part.includes('losangeles')) {
          return this.getTimezoneResult('America/Los_Angeles', 0.9);
        }
        if (part.includes('london')) {
          return this.getTimezoneResult('Europe/London', 0.9);
        }
        if (part.includes('tokyo')) {
          return this.getTimezoneResult('Asia/Tokyo', 0.9);
        }
        if (part.includes('dhaka')) {
          return this.getTimezoneResult('Asia/Dhaka', 0.9);
        }
        if (part.includes('sydney')) {
          return this.getTimezoneResult('Australia/Sydney', 0.9);
        }
      }
      
      return null;
    } catch (error) {
      return null;
    }
  }

  /**
   * IP range-based approximation for major regions
   */
  private ipRangeBasedLookup(ipAddress: string): IPLocationResult | null {
    const ipLong = ipToLong(ipAddress);
    
    // This is a simplified example - in production, you'd use a comprehensive IP database
    const ipRanges: IPRange[] = [
      // US ranges
      { start: ipToLong('1.0.0.0'), end: ipToLong('1.255.255.255'), timezone: 'Australia/Sydney' },
      { start: ipToLong('8.0.0.0'), end: ipToLong('8.255.255.255'), timezone: 'America/New_York' },
      { start: ipToLong('17.0.0.0'), end: ipToLong('17.255.255.255'), timezone: 'America/Los_Angeles' },
      
      // European ranges
      { start: ipToLong('62.0.0.0'), end: ipToLong('62.255.255.255'), timezone: 'Europe/London' },
      { start: ipToLong('80.0.0.0'), end: ipToLong('95.255.255.255'), timezone: 'Europe/Paris' },
      
      // Asian ranges
      { start: ipToLong('14.0.0.0'), end: ipToLong('14.255.255.255'), timezone: 'Asia/Tokyo' },
      { start: ipToLong('42.0.0.0'), end: ipToLong('42.255.255.255'), timezone: 'Asia/Shanghai' },
      
      // Indian subcontinent
      { start: ipToLong('14.0.0.0'), end: ipToLong('14.255.255.255'), timezone: 'Asia/Kolkata' },
      { start: ipToLong('103.0.0.0'), end: ipToLong('103.255.255.255'), timezone: 'Asia/Dhaka' },
    ];

    for (const range of ipRanges) {
      if (ipLong >= range.start && ipLong <= range.end) {
        return this.getTimezoneResult(range.timezone!, 0.6);
      }
    }

    return null;
  }

  /**
   * Creates a location result from timezone mapping
   */
  private getTimezoneResult(timezone: string, confidence: number): IPLocationResult {
    const timezoneData = this.timezoneMapping[timezone as keyof typeof this.timezoneMapping];
    
    return {
      location: timezoneData?.location || 'Unknown',
      timezone,
      coordinates: timezoneData ? { lat: timezoneData.lat, lng: timezoneData.lng } : undefined,
      confidence,
      isReliable: confidence > 0.7,
    };
  }

  /**
   * Checks if IP address is in private ranges
   */
  private isPrivateIP(ip: string): boolean {
    if (net.isIPv4(ip)) {
      const ipLong = ipToLong(ip);
      return this.privateIPRanges.some(range => 
        ipLong >= range.start && ipLong <= range.end
      );
    }
    
    if (net.isIPv6(ip)) {
      // Simple IPv6 private range check
      return ip === '::1' || 
             ip.startsWith('fc') || 
             ip.startsWith('fd') || 
             ip.startsWith('fe80') || 
             ip.startsWith('fe90') || 
             ip.startsWith('fea0') || 
             ip.startsWith('feb0');
    }
    
    return false;
  }

  /**
   * Default geolocation for unknown or private IPs
   */
  private getDefaultGeolocation(location: string): GeolocationData {
    return {
      location,
      timezone: location === 'Local Network' ? 'UTC' : 'UTC',
      accuracy: 'LOW',
    };
  }

  /**
   * Extract country from location string
   */
  private extractCountryFromLocation(location: string): string {
    const parts = location.split(', ');
    return parts[parts.length - 1] || 'Unknown';
  }

  /**
   * Extract region/state from location string
   */
  private extractRegionFromLocation(location: string): string {
    const parts = location.split(', ');
    return parts.length > 2 ? parts[parts.length - 2] : 'Unknown';
  }

  /**
   * Extract city from location string
   */
  private extractCityFromLocation(location: string): string {
    const parts = location.split(', ');
    return parts[0] || 'Unknown';
  }
}

/**
 * Utility function to convert IP address to long integer
 */
function ipToLong(ip: string): number {
  const parts = ip.split('.');
  if (parts.length !== 4) return 0;
  
  return (parseInt(parts[0]) << 24) + 
         (parseInt(parts[1]) << 16) + 
         (parseInt(parts[2]) << 8) + 
         parseInt(parts[3]);
}