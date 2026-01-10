import { Module } from '@nestjs/common';
import { MailService } from './mail.service';
import { UrlConfigService } from '../config/url.config';
import { UrlShortenerModule } from '../url-shortener/url-shortener.module';

@Module({
  imports: [UrlShortenerModule],
  providers: [MailService, UrlConfigService],
  exports: [MailService],
})
export class MailModule {}

