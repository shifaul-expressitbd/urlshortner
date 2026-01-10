-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "base";

-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "system";

-- CreateEnum
CREATE TYPE "base"."SystemRole" AS ENUM ('SYSTEM_ADMIN', 'SYSTEM_DEVELOPER', 'SYSTEM_AGENT', 'USER');

-- CreateEnum
CREATE TYPE "base"."UserStatus" AS ENUM ('ACTIVE', 'INACTIVE', 'SUSPENDED', 'DELETED');

-- CreateEnum
CREATE TYPE "base"."AuthProviderType" AS ENUM ('LOCAL', 'GOOGLE', 'FACEBOOK', 'GITHUB');

-- CreateEnum
CREATE TYPE "base"."DeviceType" AS ENUM ('DESKTOP', 'MOBILE', 'TABLET', 'BOT', 'UNKNOWN');

-- CreateEnum
CREATE TYPE "base"."DomainStatus" AS ENUM ('PENDING', 'VERIFIED', 'FAILED', 'EXPIRED');

-- CreateEnum
CREATE TYPE "base"."SslStatus" AS ENUM ('PENDING', 'ACTIVE', 'EXPIRED', 'FAILED');

-- CreateEnum
CREATE TYPE "base"."RedirectType" AS ENUM ('PERMANENT', 'TEMPORARY');

-- CreateTable
CREATE TABLE "base"."users" (
    "id" TEXT NOT NULL,
    "email" VARCHAR(255) NOT NULL,
    "firstName" VARCHAR(255) NOT NULL,
    "lastName" VARCHAR(255) NOT NULL,
    "password" VARCHAR(255),
    "avatar" TEXT,
    "systemRole" "base"."SystemRole" NOT NULL DEFAULT 'USER',
    "status" "base"."UserStatus" NOT NULL DEFAULT 'ACTIVE',
    "isEmailVerified" BOOLEAN NOT NULL DEFAULT false,
    "emailVerifiedAt" TIMESTAMP(3),
    "verificationToken" TEXT,
    "isTwoFactorEnabled" BOOLEAN NOT NULL DEFAULT false,
    "twoFactorSecret" VARCHAR(255),
    "backupCodes" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "suspensionReason" TEXT,
    "suspendedAt" TIMESTAMP(3),
    "deletedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "base"."auth_providers" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "provider" "base"."AuthProviderType" NOT NULL,
    "providerId" VARCHAR(255) NOT NULL,
    "email" VARCHAR(255),
    "accessToken" TEXT,
    "refreshToken" TEXT,
    "tokenExpiresAt" TIMESTAMP(3),
    "providerData" JSONB,
    "isPrimary" BOOLEAN NOT NULL DEFAULT false,
    "linkedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastUsedAt" TIMESTAMP(3),

    CONSTRAINT "auth_providers_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "base"."user_sessions" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "sessionId" VARCHAR(255) NOT NULL,
    "deviceInfo" JSONB,
    "ipAddress" VARCHAR(45),
    "userAgent" TEXT,
    "location" VARCHAR(100),
    "browserFingerprintHash" VARCHAR(255),
    "deviceFingerprintConfidence" DOUBLE PRECISION DEFAULT 0.5,
    "latitude" DOUBLE PRECISION,
    "longitude" DOUBLE PRECISION,
    "timezone" VARCHAR(50),
    "riskScore" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "lastIpChangeAt" TIMESTAMP(3),
    "accessCount" INTEGER NOT NULL DEFAULT 0,
    "unusualActivityCount" INTEGER NOT NULL DEFAULT 0,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "lastActivity" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "rememberMe" BOOLEAN NOT NULL DEFAULT false,
    "invalidatedAt" TIMESTAMP(3),
    "invalidationReason" VARCHAR(100),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "user_sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "base"."password_reset_requests" (
    "id" TEXT NOT NULL,
    "token" VARCHAR(255) NOT NULL,
    "userId" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "usedAt" TIMESTAMP(3),
    "cancelledAt" TIMESTAMP(3),
    "ipAddress" VARCHAR(45),
    "userAgent" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "password_reset_requests_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "base"."shortened_urls" (
    "id" TEXT NOT NULL,
    "shortCode" VARCHAR(12) NOT NULL,
    "customAlias" VARCHAR(50),
    "originalUrl" TEXT NOT NULL,
    "title" VARCHAR(255),
    "description" TEXT,
    "userId" TEXT,
    "domainId" TEXT,
    "folderId" TEXT,
    "password" VARCHAR(255),
    "expiresAt" TIMESTAMP(3),
    "maxClicks" INTEGER,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "totalClicks" INTEGER NOT NULL DEFAULT 0,
    "uniqueClicks" INTEGER NOT NULL DEFAULT 0,
    "lastClickAt" TIMESTAMP(3),
    "qrCodeUrl" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),

    CONSTRAINT "shortened_urls_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "base"."clicks" (
    "id" TEXT NOT NULL,
    "urlId" TEXT NOT NULL,
    "ipAddress" VARCHAR(45),
    "ipHash" VARCHAR(64),
    "userAgent" TEXT,
    "referer" TEXT,
    "country" VARCHAR(2),
    "countryName" VARCHAR(100),
    "region" VARCHAR(100),
    "city" VARCHAR(100),
    "deviceType" "base"."DeviceType",
    "browser" VARCHAR(50),
    "browserVersion" VARCHAR(20),
    "os" VARCHAR(50),
    "osVersion" VARCHAR(20),
    "utmSource" VARCHAR(100),
    "utmMedium" VARCHAR(100),
    "utmCampaign" VARCHAR(100),
    "utmTerm" VARCHAR(100),
    "utmContent" VARCHAR(100),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "clicks_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "base"."url_folders" (
    "id" TEXT NOT NULL,
    "name" VARCHAR(100) NOT NULL,
    "description" TEXT,
    "color" VARCHAR(7),
    "userId" TEXT NOT NULL,
    "parentId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "url_folders_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "base"."url_tags" (
    "id" TEXT NOT NULL,
    "name" VARCHAR(50) NOT NULL,
    "color" VARCHAR(7),
    "userId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "url_tags_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "base"."custom_domains" (
    "id" TEXT NOT NULL,
    "domain" VARCHAR(255) NOT NULL,
    "userId" TEXT NOT NULL,
    "verificationStatus" "base"."DomainStatus" NOT NULL DEFAULT 'PENDING',
    "verificationToken" VARCHAR(64),
    "verifiedAt" TIMESTAMP(3),
    "sslStatus" "base"."SslStatus" NOT NULL DEFAULT 'PENDING',
    "sslExpiresAt" TIMESTAMP(3),
    "isActive" BOOLEAN NOT NULL DEFAULT false,
    "redirectType" "base"."RedirectType" NOT NULL DEFAULT 'TEMPORARY',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),

    CONSTRAINT "custom_domains_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "base"."api_keys" (
    "id" TEXT NOT NULL,
    "name" VARCHAR(100) NOT NULL,
    "keyHash" VARCHAR(64) NOT NULL,
    "keyPrefix" VARCHAR(8) NOT NULL,
    "userId" TEXT NOT NULL,
    "permissions" TEXT[],
    "rateLimit" INTEGER NOT NULL DEFAULT 1000,
    "lastUsedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3),
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "api_keys_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "system"."activity_logs" (
    "id" TEXT NOT NULL,
    "userId" TEXT,
    "action" VARCHAR(100) NOT NULL,
    "resource" VARCHAR(100),
    "resourceId" TEXT,
    "details" JSONB,
    "ipAddress" VARCHAR(45),
    "userAgent" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "activity_logs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "system"."activity_logs_archive" (
    "id" TEXT NOT NULL,
    "userId" TEXT,
    "action" VARCHAR(100) NOT NULL,
    "resource" VARCHAR(100),
    "resourceId" TEXT,
    "details" JSONB,
    "ipAddress" VARCHAR(45),
    "userAgent" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL,
    "archivedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "activity_logs_archive_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "system"."change_logs" (
    "id" TEXT NOT NULL,
    "modelName" VARCHAR(100) NOT NULL,
    "recordId" TEXT NOT NULL,
    "action" VARCHAR(50) NOT NULL,
    "oldData" JSONB,
    "newData" JSONB,
    "changedFields" TEXT[],
    "rowHash" TEXT,
    "clientIp" VARCHAR(45),
    "userAgent" TEXT,
    "changeReason" TEXT,
    "isHighRisk" BOOLEAN NOT NULL DEFAULT false,
    "changedById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "change_logs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "system"."change_logs_archive" (
    "id" TEXT NOT NULL,
    "modelName" VARCHAR(100) NOT NULL,
    "recordId" TEXT NOT NULL,
    "action" VARCHAR(50) NOT NULL,
    "oldData" JSONB,
    "newData" JSONB,
    "changedFields" TEXT[],
    "rowHash" TEXT,
    "clientIp" VARCHAR(45),
    "userAgent" TEXT,
    "changeReason" TEXT,
    "isHighRisk" BOOLEAN NOT NULL DEFAULT false,
    "changedById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL,
    "archivedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "change_logs_archive_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "base"."_ShortenedUrlToUrlTag" (
    "A" TEXT NOT NULL,
    "B" TEXT NOT NULL,

    CONSTRAINT "_ShortenedUrlToUrlTag_AB_pkey" PRIMARY KEY ("A","B")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "base"."users"("email");

-- CreateIndex
CREATE UNIQUE INDEX "users_verificationToken_key" ON "base"."users"("verificationToken");

-- CreateIndex
CREATE INDEX "users_email_status_idx" ON "base"."users"("email", "status");

-- CreateIndex
CREATE INDEX "users_deletedAt_idx" ON "base"."users"("deletedAt");

-- CreateIndex
CREATE INDEX "users_createdAt_idx" ON "base"."users"("createdAt");

-- CreateIndex
CREATE INDEX "users_firstName_lastName_idx" ON "base"."users"("firstName", "lastName");

-- CreateIndex
CREATE INDEX "users_systemRole_idx" ON "base"."users"("systemRole");

-- CreateIndex
CREATE INDEX "auth_providers_provider_idx" ON "base"."auth_providers"("provider");

-- CreateIndex
CREATE INDEX "auth_providers_providerId_idx" ON "base"."auth_providers"("providerId");

-- CreateIndex
CREATE UNIQUE INDEX "auth_providers_userId_provider_key" ON "base"."auth_providers"("userId", "provider");

-- CreateIndex
CREATE UNIQUE INDEX "user_sessions_sessionId_key" ON "base"."user_sessions"("sessionId");

-- CreateIndex
CREATE INDEX "user_sessions_userId_isActive_idx" ON "base"."user_sessions"("userId", "isActive");

-- CreateIndex
CREATE INDEX "user_sessions_expiresAt_idx" ON "base"."user_sessions"("expiresAt");

-- CreateIndex
CREATE INDEX "user_sessions_riskScore_idx" ON "base"."user_sessions"("riskScore");

-- CreateIndex
CREATE INDEX "user_sessions_ipAddress_createdAt_idx" ON "base"."user_sessions"("ipAddress", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "password_reset_requests_token_key" ON "base"."password_reset_requests"("token");

-- CreateIndex
CREATE INDEX "password_reset_requests_userId_idx" ON "base"."password_reset_requests"("userId");

-- CreateIndex
CREATE INDEX "password_reset_requests_token_idx" ON "base"."password_reset_requests"("token");

-- CreateIndex
CREATE UNIQUE INDEX "shortened_urls_shortCode_key" ON "base"."shortened_urls"("shortCode");

-- CreateIndex
CREATE UNIQUE INDEX "shortened_urls_customAlias_key" ON "base"."shortened_urls"("customAlias");

-- CreateIndex
CREATE INDEX "shortened_urls_shortCode_idx" ON "base"."shortened_urls"("shortCode");

-- CreateIndex
CREATE INDEX "shortened_urls_customAlias_idx" ON "base"."shortened_urls"("customAlias");

-- CreateIndex
CREATE INDEX "shortened_urls_userId_idx" ON "base"."shortened_urls"("userId");

-- CreateIndex
CREATE INDEX "shortened_urls_domainId_idx" ON "base"."shortened_urls"("domainId");

-- CreateIndex
CREATE INDEX "shortened_urls_folderId_idx" ON "base"."shortened_urls"("folderId");

-- CreateIndex
CREATE INDEX "shortened_urls_expiresAt_idx" ON "base"."shortened_urls"("expiresAt");

-- CreateIndex
CREATE INDEX "shortened_urls_isActive_idx" ON "base"."shortened_urls"("isActive");

-- CreateIndex
CREATE INDEX "shortened_urls_createdAt_idx" ON "base"."shortened_urls"("createdAt");

-- CreateIndex
CREATE INDEX "shortened_urls_deletedAt_idx" ON "base"."shortened_urls"("deletedAt");

-- CreateIndex
CREATE INDEX "clicks_urlId_idx" ON "base"."clicks"("urlId");

-- CreateIndex
CREATE INDEX "clicks_urlId_createdAt_idx" ON "base"."clicks"("urlId", "createdAt");

-- CreateIndex
CREATE INDEX "clicks_country_idx" ON "base"."clicks"("country");

-- CreateIndex
CREATE INDEX "clicks_deviceType_idx" ON "base"."clicks"("deviceType");

-- CreateIndex
CREATE INDEX "clicks_createdAt_idx" ON "base"."clicks"("createdAt");

-- CreateIndex
CREATE INDEX "url_folders_userId_idx" ON "base"."url_folders"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "url_folders_userId_name_parentId_key" ON "base"."url_folders"("userId", "name", "parentId");

-- CreateIndex
CREATE INDEX "url_tags_userId_idx" ON "base"."url_tags"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "url_tags_userId_name_key" ON "base"."url_tags"("userId", "name");

-- CreateIndex
CREATE UNIQUE INDEX "custom_domains_domain_key" ON "base"."custom_domains"("domain");

-- CreateIndex
CREATE INDEX "custom_domains_domain_idx" ON "base"."custom_domains"("domain");

-- CreateIndex
CREATE INDEX "custom_domains_userId_idx" ON "base"."custom_domains"("userId");

-- CreateIndex
CREATE INDEX "custom_domains_verificationStatus_idx" ON "base"."custom_domains"("verificationStatus");

-- CreateIndex
CREATE UNIQUE INDEX "api_keys_keyHash_key" ON "base"."api_keys"("keyHash");

-- CreateIndex
CREATE INDEX "api_keys_keyHash_idx" ON "base"."api_keys"("keyHash");

-- CreateIndex
CREATE INDEX "api_keys_userId_idx" ON "base"."api_keys"("userId");

-- CreateIndex
CREATE INDEX "activity_logs_userId_idx" ON "system"."activity_logs"("userId");

-- CreateIndex
CREATE INDEX "activity_logs_action_idx" ON "system"."activity_logs"("action");

-- CreateIndex
CREATE INDEX "activity_logs_createdAt_idx" ON "system"."activity_logs"("createdAt");

-- CreateIndex
CREATE INDEX "activity_logs_userId_createdAt_idx" ON "system"."activity_logs"("userId", "createdAt");

-- CreateIndex
CREATE INDEX "activity_logs_archive_userId_idx" ON "system"."activity_logs_archive"("userId");

-- CreateIndex
CREATE INDEX "activity_logs_archive_action_idx" ON "system"."activity_logs_archive"("action");

-- CreateIndex
CREATE INDEX "activity_logs_archive_createdAt_idx" ON "system"."activity_logs_archive"("createdAt");

-- CreateIndex
CREATE INDEX "change_logs_modelName_recordId_idx" ON "system"."change_logs"("modelName", "recordId");

-- CreateIndex
CREATE INDEX "change_logs_changedById_idx" ON "system"."change_logs"("changedById");

-- CreateIndex
CREATE INDEX "change_logs_createdAt_idx" ON "system"."change_logs"("createdAt");

-- CreateIndex
CREATE INDEX "change_logs_archive_modelName_recordId_idx" ON "system"."change_logs_archive"("modelName", "recordId");

-- CreateIndex
CREATE INDEX "change_logs_archive_changedById_idx" ON "system"."change_logs_archive"("changedById");

-- CreateIndex
CREATE INDEX "change_logs_archive_createdAt_idx" ON "system"."change_logs_archive"("createdAt");

-- CreateIndex
CREATE INDEX "_ShortenedUrlToUrlTag_B_index" ON "base"."_ShortenedUrlToUrlTag"("B");

-- AddForeignKey
ALTER TABLE "base"."auth_providers" ADD CONSTRAINT "auth_providers_userId_fkey" FOREIGN KEY ("userId") REFERENCES "base"."users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "base"."user_sessions" ADD CONSTRAINT "user_sessions_userId_fkey" FOREIGN KEY ("userId") REFERENCES "base"."users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "base"."password_reset_requests" ADD CONSTRAINT "password_reset_requests_userId_fkey" FOREIGN KEY ("userId") REFERENCES "base"."users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "base"."shortened_urls" ADD CONSTRAINT "shortened_urls_userId_fkey" FOREIGN KEY ("userId") REFERENCES "base"."users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "base"."shortened_urls" ADD CONSTRAINT "shortened_urls_domainId_fkey" FOREIGN KEY ("domainId") REFERENCES "base"."custom_domains"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "base"."shortened_urls" ADD CONSTRAINT "shortened_urls_folderId_fkey" FOREIGN KEY ("folderId") REFERENCES "base"."url_folders"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "base"."clicks" ADD CONSTRAINT "clicks_urlId_fkey" FOREIGN KEY ("urlId") REFERENCES "base"."shortened_urls"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "base"."url_folders" ADD CONSTRAINT "url_folders_userId_fkey" FOREIGN KEY ("userId") REFERENCES "base"."users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "base"."url_folders" ADD CONSTRAINT "url_folders_parentId_fkey" FOREIGN KEY ("parentId") REFERENCES "base"."url_folders"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "base"."url_tags" ADD CONSTRAINT "url_tags_userId_fkey" FOREIGN KEY ("userId") REFERENCES "base"."users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "base"."custom_domains" ADD CONSTRAINT "custom_domains_userId_fkey" FOREIGN KEY ("userId") REFERENCES "base"."users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "base"."api_keys" ADD CONSTRAINT "api_keys_userId_fkey" FOREIGN KEY ("userId") REFERENCES "base"."users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "system"."activity_logs" ADD CONSTRAINT "activity_logs_userId_fkey" FOREIGN KEY ("userId") REFERENCES "base"."users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "system"."change_logs" ADD CONSTRAINT "change_logs_changedById_fkey" FOREIGN KEY ("changedById") REFERENCES "base"."users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "base"."_ShortenedUrlToUrlTag" ADD CONSTRAINT "_ShortenedUrlToUrlTag_A_fkey" FOREIGN KEY ("A") REFERENCES "base"."shortened_urls"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "base"."_ShortenedUrlToUrlTag" ADD CONSTRAINT "_ShortenedUrlToUrlTag_B_fkey" FOREIGN KEY ("B") REFERENCES "base"."url_tags"("id") ON DELETE CASCADE ON UPDATE CASCADE;
