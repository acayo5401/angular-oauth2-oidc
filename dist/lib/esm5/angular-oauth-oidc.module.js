import { __decorate } from "tslib";
import { OAuthStorage, OAuthLogger } from './types';
import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HTTP_INTERCEPTORS } from '@angular/common/http';
import { OAuthService } from './oauth-service';
import { UrlHelperService } from './url-helper.service';
import { OAuthModuleConfig } from './oauth-module.config';
import { OAuthResourceServerErrorHandler, OAuthNoopResourceServerErrorHandler } from './interceptors/resource-server-error-handler';
import { DefaultOAuthInterceptor } from './interceptors/default-oauth.interceptor';
import { ValidationHandler } from './token-validation/validation-handler';
import { NullValidationHandler } from './token-validation/null-validation-handler';
import { createDefaultLogger, createDefaultStorage } from './factories';
import { HashHandler, DefaultHashHandler } from './token-validation/hash-handler';
var OAuthModule = /** @class */ (function () {
    function OAuthModule() {
    }
    OAuthModule_1 = OAuthModule;
    OAuthModule.forRoot = function (config, validationHandlerClass) {
        if (config === void 0) { config = null; }
        if (validationHandlerClass === void 0) { validationHandlerClass = NullValidationHandler; }
        return {
            ngModule: OAuthModule_1,
            providers: [
                OAuthService,
                UrlHelperService,
                { provide: OAuthLogger, useFactory: createDefaultLogger },
                { provide: OAuthStorage, useFactory: createDefaultStorage },
                { provide: ValidationHandler, useClass: validationHandlerClass },
                { provide: HashHandler, useClass: DefaultHashHandler },
                {
                    provide: OAuthResourceServerErrorHandler,
                    useClass: OAuthNoopResourceServerErrorHandler
                },
                { provide: OAuthModuleConfig, useValue: config },
                {
                    provide: HTTP_INTERCEPTORS,
                    useClass: DefaultOAuthInterceptor,
                    multi: true
                }
            ]
        };
    };
    var OAuthModule_1;
    OAuthModule = OAuthModule_1 = __decorate([
        NgModule({
            imports: [CommonModule],
            declarations: [],
            exports: []
        })
    ], OAuthModule);
    return OAuthModule;
}());
export { OAuthModule };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYW5ndWxhci1vYXV0aC1vaWRjLm1vZHVsZS5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItb2F1dGgyLW9pZGMvIiwic291cmNlcyI6WyJhbmd1bGFyLW9hdXRoLW9pZGMubW9kdWxlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQSxPQUFPLEVBQUUsWUFBWSxFQUFFLFdBQVcsRUFBRSxNQUFNLFNBQVMsQ0FBQztBQUNwRCxPQUFPLEVBQUUsUUFBUSxFQUF1QixNQUFNLGVBQWUsQ0FBQztBQUM5RCxPQUFPLEVBQUUsWUFBWSxFQUFFLE1BQU0saUJBQWlCLENBQUM7QUFDL0MsT0FBTyxFQUFFLGlCQUFpQixFQUFFLE1BQU0sc0JBQXNCLENBQUM7QUFFekQsT0FBTyxFQUFFLFlBQVksRUFBRSxNQUFNLGlCQUFpQixDQUFDO0FBQy9DLE9BQU8sRUFBRSxnQkFBZ0IsRUFBRSxNQUFNLHNCQUFzQixDQUFDO0FBRXhELE9BQU8sRUFBRSxpQkFBaUIsRUFBRSxNQUFNLHVCQUF1QixDQUFDO0FBQzFELE9BQU8sRUFDTCwrQkFBK0IsRUFDL0IsbUNBQW1DLEVBQ3BDLE1BQU0sOENBQThDLENBQUM7QUFDdEQsT0FBTyxFQUFFLHVCQUF1QixFQUFFLE1BQU0sMENBQTBDLENBQUM7QUFDbkYsT0FBTyxFQUFFLGlCQUFpQixFQUFFLE1BQU0sdUNBQXVDLENBQUM7QUFDMUUsT0FBTyxFQUFFLHFCQUFxQixFQUFFLE1BQU0sNENBQTRDLENBQUM7QUFDbkYsT0FBTyxFQUFFLG1CQUFtQixFQUFFLG9CQUFvQixFQUFFLE1BQU0sYUFBYSxDQUFDO0FBQ3hFLE9BQU8sRUFDTCxXQUFXLEVBQ1gsa0JBQWtCLEVBQ25CLE1BQU0saUNBQWlDLENBQUM7QUFPekM7SUFBQTtJQTJCQSxDQUFDO29CQTNCWSxXQUFXO0lBQ2YsbUJBQU8sR0FBZCxVQUNFLE1BQWdDLEVBQ2hDLHNCQUE4QztRQUQ5Qyx1QkFBQSxFQUFBLGFBQWdDO1FBQ2hDLHVDQUFBLEVBQUEsOENBQThDO1FBRTlDLE9BQU87WUFDTCxRQUFRLEVBQUUsYUFBVztZQUNyQixTQUFTLEVBQUU7Z0JBQ1QsWUFBWTtnQkFDWixnQkFBZ0I7Z0JBQ2hCLEVBQUUsT0FBTyxFQUFFLFdBQVcsRUFBRSxVQUFVLEVBQUUsbUJBQW1CLEVBQUU7Z0JBQ3pELEVBQUUsT0FBTyxFQUFFLFlBQVksRUFBRSxVQUFVLEVBQUUsb0JBQW9CLEVBQUU7Z0JBQzNELEVBQUUsT0FBTyxFQUFFLGlCQUFpQixFQUFFLFFBQVEsRUFBRSxzQkFBc0IsRUFBRTtnQkFDaEUsRUFBRSxPQUFPLEVBQUUsV0FBVyxFQUFFLFFBQVEsRUFBRSxrQkFBa0IsRUFBRTtnQkFDdEQ7b0JBQ0UsT0FBTyxFQUFFLCtCQUErQjtvQkFDeEMsUUFBUSxFQUFFLG1DQUFtQztpQkFDOUM7Z0JBQ0QsRUFBRSxPQUFPLEVBQUUsaUJBQWlCLEVBQUUsUUFBUSxFQUFFLE1BQU0sRUFBRTtnQkFDaEQ7b0JBQ0UsT0FBTyxFQUFFLGlCQUFpQjtvQkFDMUIsUUFBUSxFQUFFLHVCQUF1QjtvQkFDakMsS0FBSyxFQUFFLElBQUk7aUJBQ1o7YUFDRjtTQUNGLENBQUM7SUFDSixDQUFDOztJQTFCVSxXQUFXO1FBTHZCLFFBQVEsQ0FBQztZQUNSLE9BQU8sRUFBRSxDQUFDLFlBQVksQ0FBQztZQUN2QixZQUFZLEVBQUUsRUFBRTtZQUNoQixPQUFPLEVBQUUsRUFBRTtTQUNaLENBQUM7T0FDVyxXQUFXLENBMkJ2QjtJQUFELGtCQUFDO0NBQUEsQUEzQkQsSUEyQkM7U0EzQlksV0FBVyIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IE9BdXRoU3RvcmFnZSwgT0F1dGhMb2dnZXIgfSBmcm9tICcuL3R5cGVzJztcclxuaW1wb3J0IHsgTmdNb2R1bGUsIE1vZHVsZVdpdGhQcm92aWRlcnMgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcclxuaW1wb3J0IHsgQ29tbW9uTW9kdWxlIH0gZnJvbSAnQGFuZ3VsYXIvY29tbW9uJztcclxuaW1wb3J0IHsgSFRUUF9JTlRFUkNFUFRPUlMgfSBmcm9tICdAYW5ndWxhci9jb21tb24vaHR0cCc7XHJcblxyXG5pbXBvcnQgeyBPQXV0aFNlcnZpY2UgfSBmcm9tICcuL29hdXRoLXNlcnZpY2UnO1xyXG5pbXBvcnQgeyBVcmxIZWxwZXJTZXJ2aWNlIH0gZnJvbSAnLi91cmwtaGVscGVyLnNlcnZpY2UnO1xyXG5cclxuaW1wb3J0IHsgT0F1dGhNb2R1bGVDb25maWcgfSBmcm9tICcuL29hdXRoLW1vZHVsZS5jb25maWcnO1xyXG5pbXBvcnQge1xyXG4gIE9BdXRoUmVzb3VyY2VTZXJ2ZXJFcnJvckhhbmRsZXIsXHJcbiAgT0F1dGhOb29wUmVzb3VyY2VTZXJ2ZXJFcnJvckhhbmRsZXJcclxufSBmcm9tICcuL2ludGVyY2VwdG9ycy9yZXNvdXJjZS1zZXJ2ZXItZXJyb3ItaGFuZGxlcic7XHJcbmltcG9ydCB7IERlZmF1bHRPQXV0aEludGVyY2VwdG9yIH0gZnJvbSAnLi9pbnRlcmNlcHRvcnMvZGVmYXVsdC1vYXV0aC5pbnRlcmNlcHRvcic7XHJcbmltcG9ydCB7IFZhbGlkYXRpb25IYW5kbGVyIH0gZnJvbSAnLi90b2tlbi12YWxpZGF0aW9uL3ZhbGlkYXRpb24taGFuZGxlcic7XHJcbmltcG9ydCB7IE51bGxWYWxpZGF0aW9uSGFuZGxlciB9IGZyb20gJy4vdG9rZW4tdmFsaWRhdGlvbi9udWxsLXZhbGlkYXRpb24taGFuZGxlcic7XHJcbmltcG9ydCB7IGNyZWF0ZURlZmF1bHRMb2dnZXIsIGNyZWF0ZURlZmF1bHRTdG9yYWdlIH0gZnJvbSAnLi9mYWN0b3JpZXMnO1xyXG5pbXBvcnQge1xyXG4gIEhhc2hIYW5kbGVyLFxyXG4gIERlZmF1bHRIYXNoSGFuZGxlclxyXG59IGZyb20gJy4vdG9rZW4tdmFsaWRhdGlvbi9oYXNoLWhhbmRsZXInO1xyXG5cclxuQE5nTW9kdWxlKHtcclxuICBpbXBvcnRzOiBbQ29tbW9uTW9kdWxlXSxcclxuICBkZWNsYXJhdGlvbnM6IFtdLFxyXG4gIGV4cG9ydHM6IFtdXHJcbn0pXHJcbmV4cG9ydCBjbGFzcyBPQXV0aE1vZHVsZSB7XHJcbiAgc3RhdGljIGZvclJvb3QoXHJcbiAgICBjb25maWc6IE9BdXRoTW9kdWxlQ29uZmlnID0gbnVsbCxcclxuICAgIHZhbGlkYXRpb25IYW5kbGVyQ2xhc3MgPSBOdWxsVmFsaWRhdGlvbkhhbmRsZXJcclxuICApOiBNb2R1bGVXaXRoUHJvdmlkZXJzPE9BdXRoTW9kdWxlPiB7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBuZ01vZHVsZTogT0F1dGhNb2R1bGUsXHJcbiAgICAgIHByb3ZpZGVyczogW1xyXG4gICAgICAgIE9BdXRoU2VydmljZSxcclxuICAgICAgICBVcmxIZWxwZXJTZXJ2aWNlLFxyXG4gICAgICAgIHsgcHJvdmlkZTogT0F1dGhMb2dnZXIsIHVzZUZhY3Rvcnk6IGNyZWF0ZURlZmF1bHRMb2dnZXIgfSxcclxuICAgICAgICB7IHByb3ZpZGU6IE9BdXRoU3RvcmFnZSwgdXNlRmFjdG9yeTogY3JlYXRlRGVmYXVsdFN0b3JhZ2UgfSxcclxuICAgICAgICB7IHByb3ZpZGU6IFZhbGlkYXRpb25IYW5kbGVyLCB1c2VDbGFzczogdmFsaWRhdGlvbkhhbmRsZXJDbGFzcyB9LFxyXG4gICAgICAgIHsgcHJvdmlkZTogSGFzaEhhbmRsZXIsIHVzZUNsYXNzOiBEZWZhdWx0SGFzaEhhbmRsZXIgfSxcclxuICAgICAgICB7XHJcbiAgICAgICAgICBwcm92aWRlOiBPQXV0aFJlc291cmNlU2VydmVyRXJyb3JIYW5kbGVyLFxyXG4gICAgICAgICAgdXNlQ2xhc3M6IE9BdXRoTm9vcFJlc291cmNlU2VydmVyRXJyb3JIYW5kbGVyXHJcbiAgICAgICAgfSxcclxuICAgICAgICB7IHByb3ZpZGU6IE9BdXRoTW9kdWxlQ29uZmlnLCB1c2VWYWx1ZTogY29uZmlnIH0sXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgcHJvdmlkZTogSFRUUF9JTlRFUkNFUFRPUlMsXHJcbiAgICAgICAgICB1c2VDbGFzczogRGVmYXVsdE9BdXRoSW50ZXJjZXB0b3IsXHJcbiAgICAgICAgICBtdWx0aTogdHJ1ZVxyXG4gICAgICAgIH1cclxuICAgICAgXVxyXG4gICAgfTtcclxuICB9XHJcbn1cclxuIl19