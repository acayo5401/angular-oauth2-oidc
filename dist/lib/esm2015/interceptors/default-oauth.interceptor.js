import { __decorate, __metadata, __param } from "tslib";
import { Injectable, Optional } from '@angular/core';
import { of, merge } from 'rxjs';
import { catchError, filter, map, take, mergeMap, timeout } from 'rxjs/operators';
import { OAuthResourceServerErrorHandler } from './resource-server-error-handler';
import { OAuthModuleConfig } from '../oauth-module.config';
import { OAuthStorage } from '../types';
import { OAuthService } from '../oauth-service';
let DefaultOAuthInterceptor = class DefaultOAuthInterceptor {
    constructor(authStorage, oAuthService, errorHandler, moduleConfig) {
        this.authStorage = authStorage;
        this.oAuthService = oAuthService;
        this.errorHandler = errorHandler;
        this.moduleConfig = moduleConfig;
    }
    checkUrl(url) {
        if (this.moduleConfig.resourceServer.customUrlValidation) {
            return this.moduleConfig.resourceServer.customUrlValidation(url);
        }
        if (this.moduleConfig.resourceServer.allowedUrls) {
            return !!this.moduleConfig.resourceServer.allowedUrls.find(u => url.startsWith(u));
        }
        return true;
    }
    intercept(req, next) {
        const url = req.url.toLowerCase();
        if (!this.moduleConfig ||
            !this.moduleConfig.resourceServer ||
            !this.checkUrl(url)) {
            return next.handle(req);
        }
        const sendAccessToken = this.moduleConfig.resourceServer.sendAccessToken;
        if (!sendAccessToken) {
            return next
                .handle(req)
                .pipe(catchError(err => this.errorHandler.handleError(err)));
        }
        return merge(of(this.oAuthService.getAccessToken()).pipe(filter(token => (token ? true : false))), this.oAuthService.events.pipe(filter(e => e.type === 'token_received'), timeout(this.oAuthService.waitForTokenInMsec || 0), catchError(_ => of(null)), // timeout is not an error
        map(_ => this.oAuthService.getAccessToken()))).pipe(take(1), mergeMap(token => {
            if (token) {
                const header = 'Bearer ' + token;
                const headers = req.headers.set('Authorization', header);
                req = req.clone({ headers });
            }
            return next
                .handle(req)
                .pipe(catchError(err => this.errorHandler.handleError(err)));
        }));
    }
};
DefaultOAuthInterceptor.ctorParameters = () => [
    { type: OAuthStorage },
    { type: OAuthService },
    { type: OAuthResourceServerErrorHandler },
    { type: OAuthModuleConfig, decorators: [{ type: Optional }] }
];
DefaultOAuthInterceptor = __decorate([
    Injectable(),
    __param(3, Optional()),
    __metadata("design:paramtypes", [OAuthStorage,
        OAuthService,
        OAuthResourceServerErrorHandler,
        OAuthModuleConfig])
], DefaultOAuthInterceptor);
export { DefaultOAuthInterceptor };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZGVmYXVsdC1vYXV0aC5pbnRlcmNlcHRvci5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItb2F1dGgyLW9pZGMvIiwic291cmNlcyI6WyJpbnRlcmNlcHRvcnMvZGVmYXVsdC1vYXV0aC5pbnRlcmNlcHRvci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiO0FBQUEsT0FBTyxFQUFFLFVBQVUsRUFBRSxRQUFRLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFRckQsT0FBTyxFQUFjLEVBQUUsRUFBRSxLQUFLLEVBQUUsTUFBTSxNQUFNLENBQUM7QUFDN0MsT0FBTyxFQUNMLFVBQVUsRUFDVixNQUFNLEVBQ04sR0FBRyxFQUNILElBQUksRUFDSixRQUFRLEVBQ1IsT0FBTyxFQUNSLE1BQU0sZ0JBQWdCLENBQUM7QUFDeEIsT0FBTyxFQUFFLCtCQUErQixFQUFFLE1BQU0saUNBQWlDLENBQUM7QUFDbEYsT0FBTyxFQUFFLGlCQUFpQixFQUFFLE1BQU0sd0JBQXdCLENBQUM7QUFDM0QsT0FBTyxFQUFFLFlBQVksRUFBRSxNQUFNLFVBQVUsQ0FBQztBQUN4QyxPQUFPLEVBQUUsWUFBWSxFQUFFLE1BQU0sa0JBQWtCLENBQUM7QUFHaEQsSUFBYSx1QkFBdUIsR0FBcEMsTUFBYSx1QkFBdUI7SUFDbEMsWUFDVSxXQUF5QixFQUN6QixZQUEwQixFQUMxQixZQUE2QyxFQUNqQyxZQUErQjtRQUgzQyxnQkFBVyxHQUFYLFdBQVcsQ0FBYztRQUN6QixpQkFBWSxHQUFaLFlBQVksQ0FBYztRQUMxQixpQkFBWSxHQUFaLFlBQVksQ0FBaUM7UUFDakMsaUJBQVksR0FBWixZQUFZLENBQW1CO0lBQ2xELENBQUM7SUFFSSxRQUFRLENBQUMsR0FBVztRQUMxQixJQUFJLElBQUksQ0FBQyxZQUFZLENBQUMsY0FBYyxDQUFDLG1CQUFtQixFQUFFO1lBQ3hELE9BQU8sSUFBSSxDQUFDLFlBQVksQ0FBQyxjQUFjLENBQUMsbUJBQW1CLENBQUMsR0FBRyxDQUFDLENBQUM7U0FDbEU7UUFF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LCtCQUErQjtRQUNuQixpQkFBaUI7R0FMMUMsdUJBQXVCLENBcUVuQztTQXJFWSx1QkFBdUIiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBJbmplY3RhYmxlLCBPcHRpb25hbCB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xyXG5cclxuaW1wb3J0IHtcclxuICBIdHRwRXZlbnQsXHJcbiAgSHR0cEhhbmRsZXIsXHJcbiAgSHR0cEludGVyY2VwdG9yLFxyXG4gIEh0dHBSZXF1ZXN0XHJcbn0gZnJvbSAnQGFuZ3VsYXIvY29tbW9uL2h0dHAnO1xyXG5pbXBvcnQgeyBPYnNlcnZhYmxlLCBvZiwgbWVyZ2UgfSBmcm9tICdyeGpzJztcclxuaW1wb3J0IHtcclxuICBjYXRjaEVycm9yLFxyXG4gIGZpbHRlcixcclxuICBtYXAsXHJcbiAgdGFrZSxcclxuICBtZXJnZU1hcCxcclxuICB0aW1lb3V0XHJcbn0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xyXG5pbXBvcnQgeyBPQXV0aFJlc291cmNlU2VydmVyRXJyb3JIYW5kbGVyIH0gZnJvbSAnLi9yZXNvdXJjZS1zZXJ2ZXItZXJyb3ItaGFuZGxlcic7XHJcbmltcG9ydCB7IE9BdXRoTW9kdWxlQ29uZmlnIH0gZnJvbSAnLi4vb2F1dGgtbW9kdWxlLmNvbmZpZyc7XHJcbmltcG9ydCB7IE9BdXRoU3RvcmFnZSB9IGZyb20gJy4uL3R5cGVzJztcclxuaW1wb3J0IHsgT0F1dGhTZXJ2aWNlIH0gZnJvbSAnLi4vb2F1dGgtc2VydmljZSc7XHJcblxyXG5ASW5qZWN0YWJsZSgpXHJcbmV4cG9ydCBjbGFzcyBEZWZhdWx0T0F1dGhJbnRlcmNlcHRvciBpbXBsZW1lbnRzIEh0dHBJbnRlcmNlcHRvciB7XHJcbiAgY29uc3RydWN0b3IoXHJcbiAgICBwcml2YXRlIGF1dGhTdG9yYWdlOiBPQXV0aFN0b3JhZ2UsXHJcbiAgICBwcml2YXRlIG9BdXRoU2VydmljZTogT0F1dGhTZXJ2aWNlLFxyXG4gICAgcHJpdmF0ZSBlcnJvckhhbmRsZXI6IE9BdXRoUmVzb3VyY2VTZXJ2ZXJFcnJvckhhbmRsZXIsXHJcbiAgICBAT3B0aW9uYWwoKSBwcml2YXRlIG1vZHVsZUNvbmZpZzogT0F1dGhNb2R1bGVDb25maWdcclxuICApIHt9XHJcblxyXG4gIHByaXZhdGUgY2hlY2tVcmwodXJsOiBzdHJpbmcpOiBib29sZWFuIHtcclxuICAgIGlmICh0aGlzLm1vZHVsZUNvbmZpZy5yZXNvdXJjZVNlcnZlci5jdXN0b21VcmxWYWxpZGF0aW9uKSB7XHJcbiAgICAgIHJldHVybiB0aGlzLm1vZHVsZUNvbmZpZy5yZXNvdXJjZVNlcnZlci5jdXN0b21VcmxWYWxpZGF0aW9uKHVybCk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHRoaXMubW9kdWxlQ29uZmlnLnJlc291cmNlU2VydmVyLmFsbG93ZWRVcmxzKSB7XHJcbiAgICAgIHJldHVybiAhIXRoaXMubW9kdWxlQ29uZmlnLnJlc291cmNlU2VydmVyLmFsbG93ZWRVcmxzLmZpbmQodSA9PlxyXG4gICAgICAgIHVybC5zdGFydHNXaXRoKHUpXHJcbiAgICAgICk7XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIHRydWU7XHJcbiAgfVxyXG5cclxuICBwdWJsaWMgaW50ZXJjZXB0KFxyXG4gICAgcmVxOiBIdHRwUmVxdWVzdDxhbnk+LFxyXG4gICAgbmV4dDogSHR0cEhhbmRsZXJcclxuICApOiBPYnNlcnZhYmxlPEh0dHBFdmVudDxhbnk+PiB7XHJcbiAgICBjb25zdCB1cmwgPSByZXEudXJsLnRvTG93ZXJDYXNlKCk7XHJcblxyXG4gICAgaWYgKFxyXG4gICAgICAhdGhpcy5tb2R1bGVDb25maWcgfHxcclxuICAgICAgIXRoaXMubW9kdWxlQ29uZmlnLnJlc291cmNlU2VydmVyIHx8XHJcbiAgICAgICF0aGlzLmNoZWNrVXJsKHVybClcclxuICAgICkge1xyXG4gICAgICByZXR1cm4gbmV4dC5oYW5kbGUocmVxKTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBzZW5kQWNjZXNzVG9rZW4gPSB0aGlzLm1vZHVsZUNvbmZpZy5yZXNvdXJjZVNlcnZlci5zZW5kQWNjZXNzVG9rZW47XHJcblxyXG4gICAgaWYgKCFzZW5kQWNjZXNzVG9rZW4pIHtcclxuICAgICAgcmV0dXJuIG5leHRcclxuICAgICAgICAuaGFuZGxlKHJlcSlcclxuICAgICAgICAucGlwZShjYXRjaEVycm9yKGVyciA9PiB0aGlzLmVycm9ySGFuZGxlci5oYW5kbGVFcnJvcihlcnIpKSk7XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIG1lcmdlKFxyXG4gICAgICBvZih0aGlzLm9BdXRoU2VydmljZS5nZXRBY2Nlc3NUb2tlbigpKS5waXBlKFxyXG4gICAgICAgIGZpbHRlcih0b2tlbiA9PiAodG9rZW4gPyB0cnVlIDogZmFsc2UpKVxyXG4gICAgICApLFxyXG4gICAgICB0aGlzLm9BdXRoU2VydmljZS5ldmVudHMucGlwZShcclxuICAgICAgICBmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICd0b2tlbl9yZWNlaXZlZCcpLFxyXG4gICAgICAgIHRpbWVvdXQodGhpcy5vQXV0aFNlcnZpY2Uud2FpdEZvclRva2VuSW5Nc2VjIHx8IDApLFxyXG4gICAgICAgIGNhdGNoRXJyb3IoXyA9PiBvZihudWxsKSksIC8vIHRpbWVvdXQgaXMgbm90IGFuIGVycm9yXHJcbiAgICAgICAgbWFwKF8gPT4gdGhpcy5vQXV0aFNlcnZpY2UuZ2V0QWNjZXNzVG9rZW4oKSlcclxuICAgICAgKVxyXG4gICAgKS5waXBlKFxyXG4gICAgICB0YWtlKDEpLFxyXG4gICAgICBtZXJnZU1hcCh0b2tlbiA9PiB7XHJcbiAgICAgICAgaWYgKHRva2VuKSB7XHJcbiAgICAgICAgICBjb25zdCBoZWFkZXIgPSAnQmVhcmVyICcgKyB0b2tlbjtcclxuICAgICAgICAgIGNvbnN0IGhlYWRlcnMgPSByZXEuaGVhZGVycy5zZXQoJ0F1dGhvcml6YXRpb24nLCBoZWFkZXIpO1xyXG4gICAgICAgICAgcmVxID0gcmVxLmNsb25lKHsgaGVhZGVycyB9KTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJldHVybiBuZXh0XHJcbiAgICAgICAgICAuaGFuZGxlKHJlcSlcclxuICAgICAgICAgIC5waXBlKGNhdGNoRXJyb3IoZXJyID0+IHRoaXMuZXJyb3JIYW5kbGVyLmhhbmRsZUVycm9yKGVycikpKTtcclxuICAgICAgfSlcclxuICAgICk7XHJcbiAgfVxyXG59XHJcbiJdfQ==