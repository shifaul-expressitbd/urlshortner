import {
    ExecutionContext,
    Injectable,
    UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';

@Injectable()
export class RefreshTokenGuard extends AuthGuard(['refresh-token']) {
    constructor(private reflector: Reflector) {
        super();
    }

    canActivate(context: ExecutionContext) {
        console.log('🔍 ========== REFRESH TOKEN GUARD CAN ACTIVATE ==========');
        const request = context.switchToHttp().getRequest();
        const handler = context.getHandler();
        const controller = context.getClass();

        const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
            handler,
            controller,
        ]);

        console.log(`🔍 Refresh Token Guard Check - Controller: ${controller.name}, Handler: ${handler.name}, isPublic: ${isPublic}`);
        console.log(`🔍 Authorization Header: ${request.headers.authorization ? 'Present' : 'Missing'}`);
        console.log(`🔍 Request Method: ${request.method}, URL: ${request.url}`);

        if (isPublic) {
            console.log(`✅ Endpoint is public, bypassing refresh token validation`);
            return true;
        }

        console.log(`🔒 Endpoint requires authentication, proceeding with refresh token validation`);
        return super.canActivate(context);
    }

    handleRequest(err: any, user: any, info: any, context: ExecutionContext) {
        console.log('🔍 ========== REFRESH TOKEN GUARD HANDLE REQUEST ==========');
        console.log('🔍 Error:', err);
        console.log('🔍 User:', user);
        console.log('🔍 Info:', info);
        console.log('🔍 Error message:', err?.message);
        console.log('🔍 Error name:', err?.name);

        if (err || !user) {
            console.error('❌ Refresh token guard failed:', err || 'No user');

            // Check if this is an access token error being propagated
            if (err?.message?.includes('Refresh token is invalid or expired')) {
                console.error('🚨 DETECTED ACCESS TOKEN ERROR IN REFRESH ENDPOINT!');
                console.error('🚨 Someone is likely sending an access token to refresh endpoint');

                // Provide a more specific error message for this common mistake
                throw new UnauthorizedException('Access token provided to refresh endpoint. Please use a valid refresh token obtained from the /auth/login endpoint.');
            }

            throw (
                err || new UnauthorizedException('Refresh token is invalid or expired')
            );
        }

        console.log('✅ Refresh token guard passed');
        return user;
    }
}