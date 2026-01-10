import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

@Injectable()
export class ApiRewriteMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    if (req.url.startsWith('/api/s/')) {
      req.url = req.url.replace('/api/s/', '/s/');
    }
    next();
  }
}
