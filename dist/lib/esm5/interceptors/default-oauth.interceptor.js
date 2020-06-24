import { __decorate, __metadata, __param } from "tslib";
import { Injectable, Optional } from '@angular/core';
import { of, merge } from 'rxjs';
import { catchError, filter, map, take, mergeMap, timeout } from 'rxjs/operators';
import { OAuthResourceServerErrorHandler } from './resource-server-error-handler';
import { OAuthModuleConfig } from '../oauth-module.config';
import { OAuthStorage } from '../types';
import { OAuthService } from '../oauth-service';
var DefaultOAuthInterceptor = /** @class */ (function () {
    function DefaultOAuthInterceptor(authStorage, oAuthService, errorHandler, moduleConfig) {
        this.authStorage = authStorage;
        this.oAuthService = oAuthService;
        this.errorHandler = errorHandler;
        this.moduleConfig = moduleConfig;
    }
    DefaultOAuthInterceptor.prototype.checkUrl = function (url) {
        if (this.moduleConfig.resourceServer.customUrlValidation) {
            return this.moduleConfig.resourceServer.customUrlValidation(url);
        }
        if (this.moduleConfig.resourceServer.allowedUrls) {
            return !!this.moduleConfig.resourceServer.allowedUrls.find(function (u) {
                return url.startsWith(u);
            });
        }
        return true;
    };
    DefaultOAuthInterceptor.prototype.intercept = function (req, next) {
        var _this = this;
        var url = req.url.toLowerCase();
        if (!this.moduleConfig ||
            !this.moduleConfig.resourceServer ||
            !this.checkUrl(url)) {
            return next.handle(req);
        }
        var sendAccessToken = this.moduleConfig.resourceServer.sendAccessToken;
        if (!sendAccessToken) {
            return next
                .handle(req)
                .pipe(catchError(function (err) { return _this.errorHandler.handleError(err); }));
        }
        return merge(of(this.oAuthService.getAccessToken()).pipe(filter(function (token) { return (token ? true : false); })), this.oAuthService.events.pipe(filter(function (e) { return e.type === 'token_received'; }), timeout(this.oAuthService.waitForTokenInMsec || 0), catchError(function (_) { return of(null); }), // timeout is not an error
        map(function (_) { return _this.oAuthService.getAccessToken(); }))).pipe(take(1), mergeMap(function (token) {
            if (token) {
                var header = 'Bearer ' + token;
                var headers = req.headers.set('Authorization', header);
                req = req.clone({ headers: headers });
            }
            return next
                .handle(req)
                .pipe(catchError(function (err) { return _this.errorHandler.handleError(err); }));
        }));
    };
    DefaultOAuthInterceptor.ctorParameters = function () { return [
        { type: OAuthStorage },
        { type: OAuthService },
        { type: OAuthResourceServerErrorHandler },
        { type: OAuthModuleConfig, decorators: [{ type: Optional }] }
    ]; };
    DefaultOAuthInterceptor = __decorate([
        Injectable(),
        __param(3, Optional()),
        __metadata("design:paramtypes", [OAuthStorage,
            OAuthService,
            OAuthResourceServerErrorHandler,
            OAuthModuleConfig])
    ], DefaultOAuthInterceptor);
    return DefaultOAuthInterceptor;
}());
export { DefaultOAuthInterceptor };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZGVmYXVsdC1vYXV0aC5pbnRlcmNlcHRvci5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItb2F1dGgyLW9pZGMvIiwic291cmNlcyI6WyJpbnRlcmNlcHRvcnMvZGVmYXVsdC1vYXV0aC5pbnRlcmNlcHRvci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiO0FBQUEsT0FBTyxFQUFFLFVBQVUsRUFBRSxRQUFRLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFRckQsT0FBTyxFQUFjLEVBQUUsRUFBRSxLQUFLLEVBQUUsTUFBTSxNQUFNLENBQUM7QUFDN0MsT0FBTyxFQUNMLFVBQVUsRUFDVixNQUFNLEVBQ04sR0FBRyxFQUNILElBQUksRUFDSixRQUFRLEVBQ1IsT0FBTyxFQUNSLE1BQU0sZ0JBQWdCLENBQUM7QUFDeEIsT0FBTyxFQUFFLCtCQUErQixFQUFFLE1BQU0saUNBQWlDLENBQUM7QUFDbEYsT0FBTyxFQUFFLGlCQUFpQixFQUFFLE1BQU0sd0JBQXdCLENBQUM7QUFDM0QsT0FBTyxFQUFFLFlBQVksRUFBRSxNQUFNLFVBQVUsQ0FBQztBQUN4QyxPQUFPLEVBQUUsWUFBWSxFQUFFLE1BQU0sa0JBQWtCLENBQUM7QUFHaEQ7SUFDRSxpQ0FDVSxXQUF5QixFQUN6QixZQUEwQixFQUMxQixZQUE2QyxFQUNqQyxZQUErQjtRQUgzQyxnQkFBVyxHQUFYLFdBQVcsQ0FBYztRQUN6QixpQkFBWSxHQUFaLFlBQVksQ0FBYztRQUMxQixpQkFBWSxHQUFaLFlBQVksQ0FBaUM7UUFDakMsaUJBQVksR0FBWixZQUFZLENBQW1CO0lBQ2xELENBQUM7SUFFSSwwQ0FBUSxHQUFoQixVQUFpQixHQUFXO1FBQzFCLElBQUksSUFBSSxDQUFDLFlBQVksQ0FBQyxjQUFjLENBQUMsbUJBQW1CLEVBQUU7WUFDeEQsT0FBTyxJQUFJLENBQUMsWUFBWSxDQUFDLGNBQWMsQ0FBQyxtQkFBbUIsQ0FBQyxHQUFHLENBQUMsQ0FBQztTQUNsRTtRQUVELElBQUksSUFBSSxDQUFDLFlBQVks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QSx1QkFBdUI7UUFEbkMsVUFBVSxFQUFFO1FBTVIsV0FBQSxRQUFRLEVBQUUsQ0FBQTt5Q0FIVSxZQUFZO1lBQ1gsWUFBWTtZQUNaLCtCQUErQjtZQUNuQixpQkFBaUI7T0FMMUMsdUJBQXVCLENBcUVuQztJQUFELDhCQUFDO0NBQUEsQUFyRUQsSUFxRUM7U0FyRVksdUJBQXVCIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSW5qZWN0YWJsZSwgT3B0aW9uYWwgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcclxuXHJcbmltcG9ydCB7XHJcbiAgSHR0cEV2ZW50LFxyXG4gIEh0dHBIYW5kbGVyLFxyXG4gIEh0dHBJbnRlcmNlcHRvcixcclxuICBIdHRwUmVxdWVzdFxyXG59IGZyb20gJ0Bhbmd1bGFyL2NvbW1vbi9odHRwJztcclxuaW1wb3J0IHsgT2JzZXJ2YWJsZSwgb2YsIG1lcmdlIH0gZnJvbSAncnhqcyc7XHJcbmltcG9ydCB7XHJcbiAgY2F0Y2hFcnJvcixcclxuICBmaWx0ZXIsXHJcbiAgbWFwLFxyXG4gIHRha2UsXHJcbiAgbWVyZ2VNYXAsXHJcbiAgdGltZW91dFxyXG59IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcclxuaW1wb3J0IHsgT0F1dGhSZXNvdXJjZVNlcnZlckVycm9ySGFuZGxlciB9IGZyb20gJy4vcmVzb3VyY2Utc2VydmVyLWVycm9yLWhhbmRsZXInO1xyXG5pbXBvcnQgeyBPQXV0aE1vZHVsZUNvbmZpZyB9IGZyb20gJy4uL29hdXRoLW1vZHVsZS5jb25maWcnO1xyXG5pbXBvcnQgeyBPQXV0aFN0b3JhZ2UgfSBmcm9tICcuLi90eXBlcyc7XHJcbmltcG9ydCB7IE9BdXRoU2VydmljZSB9IGZyb20gJy4uL29hdXRoLXNlcnZpY2UnO1xyXG5cclxuQEluamVjdGFibGUoKVxyXG5leHBvcnQgY2xhc3MgRGVmYXVsdE9BdXRoSW50ZXJjZXB0b3IgaW1wbGVtZW50cyBIdHRwSW50ZXJjZXB0b3Ige1xyXG4gIGNvbnN0cnVjdG9yKFxyXG4gICAgcHJpdmF0ZSBhdXRoU3RvcmFnZTogT0F1dGhTdG9yYWdlLFxyXG4gICAgcHJpdmF0ZSBvQXV0aFNlcnZpY2U6IE9BdXRoU2VydmljZSxcclxuICAgIHByaXZhdGUgZXJyb3JIYW5kbGVyOiBPQXV0aFJlc291cmNlU2VydmVyRXJyb3JIYW5kbGVyLFxyXG4gICAgQE9wdGlvbmFsKCkgcHJpdmF0ZSBtb2R1bGVDb25maWc6IE9BdXRoTW9kdWxlQ29uZmlnXHJcbiAgKSB7fVxyXG5cclxuICBwcml2YXRlIGNoZWNrVXJsKHVybDogc3RyaW5nKTogYm9vbGVhbiB7XHJcbiAgICBpZiAodGhpcy5tb2R1bGVDb25maWcucmVzb3VyY2VTZXJ2ZXIuY3VzdG9tVXJsVmFsaWRhdGlvbikge1xyXG4gICAgICByZXR1cm4gdGhpcy5tb2R1bGVDb25maWcucmVzb3VyY2VTZXJ2ZXIuY3VzdG9tVXJsVmFsaWRhdGlvbih1cmwpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICh0aGlzLm1vZHVsZUNvbmZpZy5yZXNvdXJjZVNlcnZlci5hbGxvd2VkVXJscykge1xyXG4gICAgICByZXR1cm4gISF0aGlzLm1vZHVsZUNvbmZpZy5yZXNvdXJjZVNlcnZlci5hbGxvd2VkVXJscy5maW5kKHUgPT5cclxuICAgICAgICB1cmwuc3RhcnRzV2l0aCh1KVxyXG4gICAgICApO1xyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiB0cnVlO1xyXG4gIH1cclxuXHJcbiAgcHVibGljIGludGVyY2VwdChcclxuICAgIHJlcTogSHR0cFJlcXVlc3Q8YW55PixcclxuICAgIG5leHQ6IEh0dHBIYW5kbGVyXHJcbiAgKTogT2JzZXJ2YWJsZTxIdHRwRXZlbnQ8YW55Pj4ge1xyXG4gICAgY29uc3QgdXJsID0gcmVxLnVybC50b0xvd2VyQ2FzZSgpO1xyXG5cclxuICAgIGlmIChcclxuICAgICAgIXRoaXMubW9kdWxlQ29uZmlnIHx8XHJcbiAgICAgICF0aGlzLm1vZHVsZUNvbmZpZy5yZXNvdXJjZVNlcnZlciB8fFxyXG4gICAgICAhdGhpcy5jaGVja1VybCh1cmwpXHJcbiAgICApIHtcclxuICAgICAgcmV0dXJuIG5leHQuaGFuZGxlKHJlcSk7XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3Qgc2VuZEFjY2Vzc1Rva2VuID0gdGhpcy5tb2R1bGVDb25maWcucmVzb3VyY2VTZXJ2ZXIuc2VuZEFjY2Vzc1Rva2VuO1xyXG5cclxuICAgIGlmICghc2VuZEFjY2Vzc1Rva2VuKSB7XHJcbiAgICAgIHJldHVybiBuZXh0XHJcbiAgICAgICAgLmhhbmRsZShyZXEpXHJcbiAgICAgICAgLnBpcGUoY2F0Y2hFcnJvcihlcnIgPT4gdGhpcy5lcnJvckhhbmRsZXIuaGFuZGxlRXJyb3IoZXJyKSkpO1xyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiBtZXJnZShcclxuICAgICAgb2YodGhpcy5vQXV0aFNlcnZpY2UuZ2V0QWNjZXNzVG9rZW4oKSkucGlwZShcclxuICAgICAgICBmaWx0ZXIodG9rZW4gPT4gKHRva2VuID8gdHJ1ZSA6IGZhbHNlKSlcclxuICAgICAgKSxcclxuICAgICAgdGhpcy5vQXV0aFNlcnZpY2UuZXZlbnRzLnBpcGUoXHJcbiAgICAgICAgZmlsdGVyKGUgPT4gZS50eXBlID09PSAndG9rZW5fcmVjZWl2ZWQnKSxcclxuICAgICAgICB0aW1lb3V0KHRoaXMub0F1dGhTZXJ2aWNlLndhaXRGb3JUb2tlbkluTXNlYyB8fCAwKSxcclxuICAgICAgICBjYXRjaEVycm9yKF8gPT4gb2YobnVsbCkpLCAvLyB0aW1lb3V0IGlzIG5vdCBhbiBlcnJvclxyXG4gICAgICAgIG1hcChfID0+IHRoaXMub0F1dGhTZXJ2aWNlLmdldEFjY2Vzc1Rva2VuKCkpXHJcbiAgICAgIClcclxuICAgICkucGlwZShcclxuICAgICAgdGFrZSgxKSxcclxuICAgICAgbWVyZ2VNYXAodG9rZW4gPT4ge1xyXG4gICAgICAgIGlmICh0b2tlbikge1xyXG4gICAgICAgICAgY29uc3QgaGVhZGVyID0gJ0JlYXJlciAnICsgdG9rZW47XHJcbiAgICAgICAgICBjb25zdCBoZWFkZXJzID0gcmVxLmhlYWRlcnMuc2V0KCdBdXRob3JpemF0aW9uJywgaGVhZGVyKTtcclxuICAgICAgICAgIHJlcSA9IHJlcS5jbG9uZSh7IGhlYWRlcnMgfSk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gbmV4dFxyXG4gICAgICAgICAgLmhhbmRsZShyZXEpXHJcbiAgICAgICAgICAucGlwZShjYXRjaEVycm9yKGVyciA9PiB0aGlzLmVycm9ySGFuZGxlci5oYW5kbGVFcnJvcihlcnIpKSk7XHJcbiAgICAgIH0pXHJcbiAgICApO1xyXG4gIH1cclxufVxyXG4iXX0=