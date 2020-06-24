var OAuthModule_1;
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
let OAuthModule = OAuthModule_1 = class OAuthModule {
    static forRoot(config = null, validationHandlerClass = NullValidationHandler) {
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
    }
};
OAuthModule = OAuthModule_1 = __decorate([
    NgModule({
        imports: [CommonModule],
        declarations: [],
        exports: []
    })
], OAuthModule);
export { OAuthModule };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYW5ndWxhci1vYXV0aC1vaWRjLm1vZHVsZS5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItb2F1dGgyLW9pZGMvIiwic291cmNlcyI6WyJhbmd1bGFyLW9hdXRoLW9pZGMubW9kdWxlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7O0FBQUEsT0FBTyxFQUFFLFlBQVksRUFBRSxXQUFXLEVBQUUsTUFBTSxTQUFTLENBQUM7QUFDcEQsT0FBTyxFQUFFLFFBQVEsRUFBdUIsTUFBTSxlQUFlLENBQUM7QUFDOUQsT0FBTyxFQUFFLFlBQVksRUFBRSxNQUFNLGlCQUFpQixDQUFDO0FBQy9DLE9BQU8sRUFBRSxpQkFBaUIsRUFBRSxNQUFNLHNCQUFzQixDQUFDO0FBRXpELE9BQU8sRUFBRSxZQUFZLEVBQUUsTUFBTSxpQkFBaUIsQ0FBQztBQUMvQyxPQUFPLEVBQUUsZ0JBQWdCLEVBQUUsTUFBTSxzQkFBc0IsQ0FBQztBQUV4RCxPQUFPLEVBQUUsaUJBQWlCLEVBQUUsTUFBTSx1QkFBdUIsQ0FBQztBQUMxRCxPQUFPLEVBQ0wsK0JBQStCLEVBQy9CLG1DQUFtQyxFQUNwQyxNQUFNLDhDQUE4QyxDQUFDO0FBQ3RELE9BQU8sRUFBRSx1QkFBdUIsRUFBRSxNQUFNLDBDQUEwQyxDQUFDO0FBQ25GLE9BQU8sRUFBRSxpQkFBaUIsRUFBRSxNQUFNLHVDQUF1QyxDQUFDO0FBQzFFLE9BQU8sRUFBRSxxQkFBcUIsRUFBRSxNQUFNLDRDQUE0QyxDQUFDO0FBQ25GLE9BQU8sRUFBRSxtQkFBbUIsRUFBRSxvQkFBb0IsRUFBRSxNQUFNLGFBQWEsQ0FBQztBQUN4RSxPQUFPLEVBQ0wsV0FBVyxFQUNYLGtCQUFrQixFQUNuQixNQUFNLGlDQUFpQyxDQUFDO0FBT3pDLElBQWEsV0FBVyxtQkFBeEIsTUFBYSxXQUFXO0lBQ3RCLE1BQU0sQ0FBQyxPQUFPLENBQ1osU0FBNEIsSUFBSSxFQUNoQyxzQkFBc0IsR0FBRyxxQkFBcUI7UUFFOUMsT0FBTztZQUNMLFFBQVEsRUFBRSxhQUFXO1lBQ3JCLFNBQVMsRUFBRTtnQkFDVCxZQUFZO2dCQUNaLGdCQUFnQjtnQkFDaEIsRUFBRSxPQUFPLEVBQUUsV0FBVyxFQUFFLFVBQVUsRUFBRSxtQkFBbUIsRUFBRTtnQkFDekQsRUFBRSxPQUFPLEVBQUUsWUFBWSxFQUFFLFVBQVUsRUFBRSxvQkFBb0IsRUFBRTtnQkFDM0QsRUFBRSxPQUFPLEVBQUUsaUJBQWlCLEVBQUUsUUFBUSxFQUFFLHNCQUFzQixFQUFFO2dCQUNoRSxFQUFFLE9BQU8sRUFBRSxXQUFXLEVBQUUsUUFBUSxFQUFFLGtCQUFrQixFQUFFO2dCQUN0RDtvQkFDRSxPQUFPLEVBQUUsK0JBQStCO29CQUN4QyxRQUFRLEVBQUUsbUNBQW1DO2lCQUM5QztnQkFDRCxFQUFFLE9BQU8sRUFBRSxpQkFBaUIsRUFBRSxRQUFRLEVBQUUsTUFBTSxFQUFFO2dCQUNoRDtvQkFDRSxPQUFPLEVBQUUsaUJBQWlCO29CQUMxQixRQUFRLEVBQUUsdUJBQXVCO29CQUNqQyxLQUFLLEVBQUUsSUFBSTtpQkFDWjthQUNGO1NBQ0YsQ0FBQztJQUNKLENBQUM7Q0FDRixDQUFBO0FBM0JZLFdBQVc7SUFMdkIsUUFBUSxDQUFDO1FBQ1IsT0FBTyxFQUFFLENBQUMsWUFBWSxDQUFDO1FBQ3ZCLFlBQVksRUFBRSxFQUFFO1FBQ2hCLE9BQU8sRUFBRSxFQUFFO0tBQ1osQ0FBQztHQUNXLFdBQVcsQ0EyQnZCO1NBM0JZLFdBQVciLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBPQXV0aFN0b3JhZ2UsIE9BdXRoTG9nZ2VyIH0gZnJvbSAnLi90eXBlcyc7XHJcbmltcG9ydCB7IE5nTW9kdWxlLCBNb2R1bGVXaXRoUHJvdmlkZXJzIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XHJcbmltcG9ydCB7IENvbW1vbk1vZHVsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvbW1vbic7XHJcbmltcG9ydCB7IEhUVFBfSU5URVJDRVBUT1JTIH0gZnJvbSAnQGFuZ3VsYXIvY29tbW9uL2h0dHAnO1xyXG5cclxuaW1wb3J0IHsgT0F1dGhTZXJ2aWNlIH0gZnJvbSAnLi9vYXV0aC1zZXJ2aWNlJztcclxuaW1wb3J0IHsgVXJsSGVscGVyU2VydmljZSB9IGZyb20gJy4vdXJsLWhlbHBlci5zZXJ2aWNlJztcclxuXHJcbmltcG9ydCB7IE9BdXRoTW9kdWxlQ29uZmlnIH0gZnJvbSAnLi9vYXV0aC1tb2R1bGUuY29uZmlnJztcclxuaW1wb3J0IHtcclxuICBPQXV0aFJlc291cmNlU2VydmVyRXJyb3JIYW5kbGVyLFxyXG4gIE9BdXRoTm9vcFJlc291cmNlU2VydmVyRXJyb3JIYW5kbGVyXHJcbn0gZnJvbSAnLi9pbnRlcmNlcHRvcnMvcmVzb3VyY2Utc2VydmVyLWVycm9yLWhhbmRsZXInO1xyXG5pbXBvcnQgeyBEZWZhdWx0T0F1dGhJbnRlcmNlcHRvciB9IGZyb20gJy4vaW50ZXJjZXB0b3JzL2RlZmF1bHQtb2F1dGguaW50ZXJjZXB0b3InO1xyXG5pbXBvcnQgeyBWYWxpZGF0aW9uSGFuZGxlciB9IGZyb20gJy4vdG9rZW4tdmFsaWRhdGlvbi92YWxpZGF0aW9uLWhhbmRsZXInO1xyXG5pbXBvcnQgeyBOdWxsVmFsaWRhdGlvbkhhbmRsZXIgfSBmcm9tICcuL3Rva2VuLXZhbGlkYXRpb24vbnVsbC12YWxpZGF0aW9uLWhhbmRsZXInO1xyXG5pbXBvcnQgeyBjcmVhdGVEZWZhdWx0TG9nZ2VyLCBjcmVhdGVEZWZhdWx0U3RvcmFnZSB9IGZyb20gJy4vZmFjdG9yaWVzJztcclxuaW1wb3J0IHtcclxuICBIYXNoSGFuZGxlcixcclxuICBEZWZhdWx0SGFzaEhhbmRsZXJcclxufSBmcm9tICcuL3Rva2VuLXZhbGlkYXRpb24vaGFzaC1oYW5kbGVyJztcclxuXHJcbkBOZ01vZHVsZSh7XHJcbiAgaW1wb3J0czogW0NvbW1vbk1vZHVsZV0sXHJcbiAgZGVjbGFyYXRpb25zOiBbXSxcclxuICBleHBvcnRzOiBbXVxyXG59KVxyXG5leHBvcnQgY2xhc3MgT0F1dGhNb2R1bGUge1xyXG4gIHN0YXRpYyBmb3JSb290KFxyXG4gICAgY29uZmlnOiBPQXV0aE1vZHVsZUNvbmZpZyA9IG51bGwsXHJcbiAgICB2YWxpZGF0aW9uSGFuZGxlckNsYXNzID0gTnVsbFZhbGlkYXRpb25IYW5kbGVyXHJcbiAgKTogTW9kdWxlV2l0aFByb3ZpZGVycyB7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBuZ01vZHVsZTogT0F1dGhNb2R1bGUsXHJcbiAgICAgIHByb3ZpZGVyczogW1xyXG4gICAgICAgIE9BdXRoU2VydmljZSxcclxuICAgICAgICBVcmxIZWxwZXJTZXJ2aWNlLFxyXG4gICAgICAgIHsgcHJvdmlkZTogT0F1dGhMb2dnZXIsIHVzZUZhY3Rvcnk6IGNyZWF0ZURlZmF1bHRMb2dnZXIgfSxcclxuICAgICAgICB7IHByb3ZpZGU6IE9BdXRoU3RvcmFnZSwgdXNlRmFjdG9yeTogY3JlYXRlRGVmYXVsdFN0b3JhZ2UgfSxcclxuICAgICAgICB7IHByb3ZpZGU6IFZhbGlkYXRpb25IYW5kbGVyLCB1c2VDbGFzczogdmFsaWRhdGlvbkhhbmRsZXJDbGFzcyB9LFxyXG4gICAgICAgIHsgcHJvdmlkZTogSGFzaEhhbmRsZXIsIHVzZUNsYXNzOiBEZWZhdWx0SGFzaEhhbmRsZXIgfSxcclxuICAgICAgICB7XHJcbiAgICAgICAgICBwcm92aWRlOiBPQXV0aFJlc291cmNlU2VydmVyRXJyb3JIYW5kbGVyLFxyXG4gICAgICAgICAgdXNlQ2xhc3M6IE9BdXRoTm9vcFJlc291cmNlU2VydmVyRXJyb3JIYW5kbGVyXHJcbiAgICAgICAgfSxcclxuICAgICAgICB7IHByb3ZpZGU6IE9BdXRoTW9kdWxlQ29uZmlnLCB1c2VWYWx1ZTogY29uZmlnIH0sXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgcHJvdmlkZTogSFRUUF9JTlRFUkNFUFRPUlMsXHJcbiAgICAgICAgICB1c2VDbGFzczogRGVmYXVsdE9BdXRoSW50ZXJjZXB0b3IsXHJcbiAgICAgICAgICBtdWx0aTogdHJ1ZVxyXG4gICAgICAgIH1cclxuICAgICAgXVxyXG4gICAgfTtcclxuICB9XHJcbn1cclxuIl19