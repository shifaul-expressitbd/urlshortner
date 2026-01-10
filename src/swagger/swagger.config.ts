import { DocumentBuilder } from '@nestjs/swagger';

export const SWAGGER_CONFIG = {
  title: 'URL Shortener API',
  description:
    'A powerful URL shortener service API. Features include custom aliases, analytics, custom domains, QR codes, password protection, and organization (folders/tags).',
  version: '1.0.0',
  tags: [
    {
      name: 'Authentication',
      description: 'User authentication and authorization',
    },
    {
      name: 'OAuth Authentication',
      description: 'OAuth-based authentication methods',
    },
    {
      name: 'Two-Factor Authentication',
      description: 'Two-factor authentication operations',
    },
    {
      name: 'Session Management',
      description: 'Session handling and management',
    },
    { name: 'Users', description: 'User management' },
    {
      name: 'URL Shortener',
      description: 'Core URL shortening and redirection',
    },
    {
      name: 'Analytics',
      description: 'Detailed click tracking and statistics',
    },
    {
      name: 'Custom Domains',
      description: 'Manage custom domains for branded links',
    },
    {
      name: 'Folders',
      description: 'Organize URLs into folders',
    },
    {
      name: 'Tags',
      description: 'Organize URLs with tags',
    },
    {
      name: 'Admin',
      description: 'Administrative operations',
    },
  ],
  // Tag groups for ReDoc or similar tools (optional but good for organization)
  'x-tagGroups': [
    {
      name: 'Core Features',
      tags: ['URL Shortener', 'Analytics', 'Custom Domains'],
    },
    {
      name: 'Organization',
      tags: ['Folders', 'Tags'],
    },
    {
      name: 'Authentication & Users',
      tags: [
        'Authentication',
        'OAuth Authentication',
        'Two-Factor Authentication',
        'Session Management',
        'Users',
      ],
    },
    {
      name: 'Administration',
      tags: ['Admin'],
    },
  ],
};

export function createSwaggerConfig(baseUrl: string) {
  const config = new DocumentBuilder()
    .setTitle(SWAGGER_CONFIG.title)
    .setDescription(SWAGGER_CONFIG.description)
    .setVersion(SWAGGER_CONFIG.version)

    // Main JWT Auth
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'Enter your **access token**',
      },
      'access-token',
    )
    // Refresh Token
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'Enter your **refresh token**',
      },
      'refresh-token',
    )
    .addServer(baseUrl)
    .setExternalDoc('Full Documentation', `${baseUrl}/api/docs`);

  return config;
}
