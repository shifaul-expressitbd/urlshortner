import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

@Injectable()
export class DomainRedirectMiddleware implements NestMiddleware {
    use(req: Request, res: Response, next: NextFunction) {
        const host = req.get('host');
        const path = req.originalUrl;

        // Check if host is exactly 'cutzy.app'
        if (host === 'cutzy.app') {
            // Exclude API routes, short links, and files
            if (
                !path.startsWith('/api') &&
                !path.startsWith('/s/') &&
                !path.startsWith('/files/') &&
                path !== '/api'
            ) {
                const newUrl = `https://www.cutzy.app${path}`;
                return res.redirect(301, newUrl);
            }
        }

        next();
    }
}
