var AuthConfig = /** @class */ (function () {
    function AuthConfig(json) {
        /**
         * The client's id as registered with the auth server
         */
        this.clientId = '';
        /**
         * The client's redirectUri as registered with the auth server
         */
        this.redirectUri = '';
        /**
         * An optional second redirectUri where the auth server
         * redirects the user to after logging out.
         */
        this.postLogoutRedirectUri = '';
        /**
         * The auth server's endpoint that allows to log
         * the user in when using implicit flow.
         */
        this.loginUrl = '';
        /**
         * The requested scopes
         */
        this.scope = 'openid profile';
        this.resource = '';
        this.rngUrl = '';
        /**
         * Defines whether to use OpenId Connect during
         * implicit flow.
         */
        this.oidc = true;
        /**
         * Defines whether to request an access token during
         * implicit flow.
         */
        this.requestAccessToken = true;
        this.options = null;
        /**
         * The issuer's uri.
         */
        this.issuer = '';
        /**
         * The logout url.
         */
        this.logoutUrl = '';
        /**
         * Defines whether to clear the hash fragment after logging in.
         */
        this.clearHashAfterLogin = true;
        /**
         * Url of the token endpoint as defined by OpenId Connect and OAuth 2.
         */
        this.tokenEndpoint = null;
        /**
         * Url of the revocation endpoint as defined by OpenId Connect and OAuth 2.
         */
        this.revocationEndpoint = null;
        /**
         * Names of known parameters sent out in the TokenResponse. https://tools.ietf.org/html/rfc6749#section-5.1
         */
        this.customTokenParameters = [];
        /**
         * Url of the userinfo endpoint as defined by OpenId Connect.
         */
        this.userinfoEndpoint = null;
        this.responseType = '';
        /**
         * Defines whether additional debug information should
         * be shown at the console. Note that in certain browsers
         * the verbosity of the console needs to be explicitly set
         * to include Debug level messages.
         */
        this.showDebugInformation = false;
        /**
         * The redirect uri used when doing silent refresh.
         */
        this.silentRefreshRedirectUri = '';
        this.silentRefreshMessagePrefix = '';
        /**
         * Set this to true to display the iframe used for
         * silent refresh for debugging.
         */
        this.silentRefreshShowIFrame = false;
        /**
         * Timeout for silent refresh.
         * @internal
         * depreacted b/c of typo, see silentRefreshTimeout
         */
        this.siletRefreshTimeout = 1000 * 20;
        /**
         * Timeout for silent refresh.
         */
        this.silentRefreshTimeout = 1000 * 20;
        /**
         * Some auth servers don't allow using password flow
         * w/o a client secret while the standards do not
         * demand for it. In this case, you can set a password
         * here. As this password is exposed to the public
         * it does not bring additional security and is therefore
         * as good as using no password.
         */
        this.dummyClientSecret = null;
        /**
         * Defines whether https is required.
         * The default value is remoteOnly which only allows
         * http for localhost, while every other domains need
         * to be used with https.
         */
        this.requireHttps = 'remoteOnly';
        /**
         * Defines whether every url provided by the discovery
         * document has to start with the issuer's url.
         */
        this.strictDiscoveryDocumentValidation = true;
        /**
         * JSON Web Key Set (https://tools.ietf.org/html/rfc7517)
         * with keys used to validate received id_tokens.
         * This is taken out of the disovery document. Can be set manually too.
         */
        this.jwks = null;
        /**
         * Map with additional query parameter that are appended to
         * the request when initializing implicit flow.
         */
        this.customQueryParams = null;
        this.silentRefreshIFrameName = 'angular-oauth-oidc-silent-refresh-iframe';
        /**
         * Defines when the token_timeout event should be raised.
         * If you set this to the default value 0.75, the event
         * is triggered after 75% of the token's life time.
         */
        this.timeoutFactor = 0.75;
        /**
         * If true, the lib will try to check whether the user
         * is still logged in on a regular basis as described
         * in http://openid.net/specs/openid-connect-session-1_0.html#ChangeNotification
         */
        this.sessionChecksEnabled = false;
        /**
         * Interval in msec for checking the session
         * according to http://openid.net/specs/openid-connect-session-1_0.html#ChangeNotification
         */
        this.sessionCheckIntervall = 3 * 1000;
        /**
         * Url for the iframe used for session checks
         */
        this.sessionCheckIFrameUrl = null;
        /**
         * Name of the iframe to use for session checks
         */
        this.sessionCheckIFrameName = 'angular-oauth-oidc-check-session-iframe';
        /**
         * This property has been introduced to disable at_hash checks
         * and is indented for Identity Provider that does not deliver
         * an at_hash EVEN THOUGH its recommended by the OIDC specs.
         * Of course, when disabling these checks the we are bypassing
         * a security check which means we are more vulnerable.
         */
        this.disableAtHashCheck = false;
        /**
         * Defines wether to check the subject of a refreshed token after silent refresh.
         * Normally, it should be the same as before.
         */
        this.skipSubjectCheck = false;
        this.useIdTokenHintForSilentRefresh = false;
        /**
         * Defined whether to skip the validation of the issuer in the discovery document.
         * Normally, the discovey document's url starts with the url of the issuer.
         */
        this.skipIssuerCheck = false;
        /**
         * final state sent to issuer is built as follows:
         * state = nonce + nonceStateSeparator + additional state
         * Default separator is ';' (encoded %3B).
         * In rare cases, this character might be forbidden or inconvenient to use by the issuer so it can be customized.
         */
        this.nonceStateSeparator = ';';
        /**
         * Set this to true to use HTTP BASIC auth for AJAX calls
         */
        this.useHttpBasicAuth = false;
        /**
         * The interceptors waits this time span if there is no token
         */
        this.waitForTokenInMsec = 0;
        /**
         * Code Flow is by defauld used together with PKCI which is also higly recommented.
         * You can disbale it here by setting this flag to true.
         * https://tools.ietf.org/html/rfc7636#section-1.1
         */
        this.disablePKCE = false;
        /**
         * This property allows you to override the method that is used to open the login url,
         * allowing a way for implementations to specify their own method of routing to new
         * urls.
         */
        this.openUri = function (uri) {
            location.href = uri;
        };
        if (json) {
            Object.assign(this, json);
        }
    }
    return AuthConfig;
}());
export { AuthConfig };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYXV0aC5jb25maWcuanMiLCJzb3VyY2VSb290Ijoibmc6Ly9hbmd1bGFyLW9hdXRoMi1vaWRjLyIsInNvdXJjZXMiOlsiYXV0aC5jb25maWcudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUE7SUE2UEUsb0JBQVksSUFBMEI7UUE1UHRDOztXQUVHO1FBQ0ksYUFBUSxHQUFJLEVBQUUsQ0FBQztRQUV0Qjs7V0FFRztRQUNJLGdCQUFXLEdBQUksRUFBRSxDQUFDO1FBRXpCOzs7V0FHRztRQUNJLDBCQUFxQixHQUFJLEVBQUUsQ0FBQztRQUVuQzs7O1dBR0c7UUFDSSxhQUFRLEdBQUksRUFBRSxDQUFDO1FBRXRCOztXQUVHO1FBQ0ksVUFBSyxHQUFJLGdCQUFnQixDQUFDO1FBRTFCLGFBQVEsR0FBSSxFQUFFLENBQUM7UUFFZixXQUFNLEdBQUksRUFBRSxDQUFDO1FBRXBCOzs7V0FHRztRQUNJLFNBQUksR0FBSSxJQUFJLENBQUM7UUFFcEI7OztXQUdHO1FBQ0ksdUJBQWtCLEdBQUksSUFBSSxDQUFDO1FBRTNCLFlBQU8sR0FBUyxJQUFJLENBQUM7UUFFNUI7O1dBRUc7UUFDSSxXQUFNLEdBQUksRUFBRSxDQUFDO1FBRXBCOztXQUVHO1FBQ0ksY0FBUyxHQUFJLEVBQUUsQ0FBQztRQUV2Qjs7V0FFRztRQUNJLHdCQUFtQixHQUFJLElBQUksQ0FBQztRQUVuQzs7V0FFRztRQUNJLGtCQUFhLEdBQVksSUFBSSxDQUFDO1FBRXJDOztXQUVHO1FBQ0ksdUJBQWtCLEdBQVksSUFBSSxDQUFDO1FBRTFDOztXQUVHO1FBQ0ksMEJBQXFCLEdBQWMsRUFBRSxDQUFDO1FBRTdDOztXQUVHO1FBQ0kscUJBQWdCLEdBQVksSUFBSSxDQUFDO1FBRWpDLGlCQUFZLEdBQUksRUFBRSxDQUFDO1FBRTFCOzs7OztXQUtHO1FBQ0kseUJBQW9CLEdBQUksS0FBSyxDQUFDO1FBRXJDOztXQUVHO1FBQ0ksNkJBQXdCLEdBQUksRUFBRSxDQUFDO1FBRS9CLCtCQUEwQixHQUFJLEVBQUUsQ0FBQztRQUV4Qzs7O1dBR0c7UUFDSSw0QkFBdUIsR0FBSSxLQUFLLENBQUM7UUFFeEM7Ozs7V0FJRztRQUNJLHdCQUFtQixHQUFZLElBQUksR0FBRyxFQUFFLENBQUM7UUFFaEQ7O1dBRUc7UUFDSSx5QkFBb0IsR0FBWSxJQUFJLEdBQUcsRUFBRSxDQUFDO1FBRWpEOzs7Ozs7O1dBT0c7UUFDSSxzQkFBaUIsR0FBWSxJQUFJLENBQUM7UUFFekM7Ozs7O1dBS0c7UUFDSSxpQkFBWSxHQUE0QixZQUFZLENBQUM7UUFFNUQ7OztXQUdHO1FBQ0ksc0NBQWlDLEdBQUksSUFBSSxDQUFDO1FBRWpEOzs7O1dBSUc7UUFDSSxTQUFJLEdBQVksSUFBSSxDQUFDO1FBRTVCOzs7V0FHRztRQUNJLHNCQUFpQixHQUFZLElBQUksQ0FBQztRQUVsQyw0QkFBdUIsR0FBSSwwQ0FBMEMsQ0FBQztRQUU3RTs7OztXQUlHO1FBQ0ksa0JBQWEsR0FBSSxJQUFJLENBQUM7UUFFN0I7Ozs7V0FJRztRQUNJLHlCQUFvQixHQUFJLEtBQUssQ0FBQztRQUVyQzs7O1dBR0c7UUFDSSwwQkFBcUIsR0FBSSxDQUFDLEdBQUcsSUFBSSxDQUFDO1FBRXpDOztXQUVHO1FBQ0ksMEJBQXFCLEdBQVksSUFBSSxDQUFDO1FBRTdDOztXQUVHO1FBQ0ksMkJBQXNCLEdBQUkseUNBQXlDLENBQUM7UUFFM0U7Ozs7OztXQU1HO1FBQ0ksdUJBQWtCLEdBQUksS0FBSyxDQUFDO1FBRW5DOzs7V0FHRztRQUNJLHFCQUFnQixHQUFJLEtBQUssQ0FBQztRQUUxQixtQ0FBOEIsR0FBSSxLQUFLLENBQUM7UUFFL0M7OztXQUdHO1FBQ0ksb0JBQWUsR0FBSSxLQUFLLENBQUM7UUFTaEM7Ozs7O1dBS0c7UUFDSSx3QkFBbUIsR0FBSSxHQUFHLENBQUM7UUFFbEM7O1dBRUc7UUFDSSxxQkFBZ0IsR0FBSSxLQUFLLENBQUM7UUFPakM7O1dBRUc7UUFDSSx1QkFBa0IsR0FBSSxDQUFDLENBQUM7UUFVL0I7Ozs7V0FJRztRQUNJLGdCQUFXLEdBQUksS0FBSyxDQUFDO1FBUTVCOzs7O1dBSUc7UUFDSSxZQUFPLEdBQTJCLFVBQUEsR0FBRztZQUMxQyxRQUFRLENBQUMsSUFBSSxHQUFHLEdBQUcsQ0FBQztRQUN0QixDQUFDLENBQUM7UUFaQSxJQUFJLElBQUksRUFBRTtZQUNSLE1BQU0sQ0FBQyxNQUFNLENBQUMsSUFBSSxFQUFFLElBQUksQ0FBQyxDQUFDO1NBQzNCO0lBQ0gsQ0FBQztJQVVILGlCQUFDO0FBQUQsQ0FBQyxBQTNRRCxJQTJRQyIsInNvdXJjZXNDb250ZW50IjpbImV4cG9ydCBjbGFzcyBBdXRoQ29uZmlnIHtcclxuICAvKipcclxuICAgKiBUaGUgY2xpZW50J3MgaWQgYXMgcmVnaXN0ZXJlZCB3aXRoIHRoZSBhdXRoIHNlcnZlclxyXG4gICAqL1xyXG4gIHB1YmxpYyBjbGllbnRJZD8gPSAnJztcclxuXHJcbiAgLyoqXHJcbiAgICogVGhlIGNsaWVudCdzIHJlZGlyZWN0VXJpIGFzIHJlZ2lzdGVyZWQgd2l0aCB0aGUgYXV0aCBzZXJ2ZXJcclxuICAgKi9cclxuICBwdWJsaWMgcmVkaXJlY3RVcmk/ID0gJyc7XHJcblxyXG4gIC8qKlxyXG4gICAqIEFuIG9wdGlvbmFsIHNlY29uZCByZWRpcmVjdFVyaSB3aGVyZSB0aGUgYXV0aCBzZXJ2ZXJcclxuICAgKiByZWRpcmVjdHMgdGhlIHVzZXIgdG8gYWZ0ZXIgbG9nZ2luZyBvdXQuXHJcbiAgICovXHJcbiAgcHVibGljIHBvc3RMb2dvdXRSZWRpcmVjdFVyaT8gPSAnJztcclxuXHJcbiAgLyoqXHJcbiAgICogVGhlIGF1dGggc2VydmVyJ3MgZW5kcG9pbnQgdGhhdCBhbGxvd3MgdG8gbG9nXHJcbiAgICogdGhlIHVzZXIgaW4gd2hlbiB1c2luZyBpbXBsaWNpdCBmbG93LlxyXG4gICAqL1xyXG4gIHB1YmxpYyBsb2dpblVybD8gPSAnJztcclxuXHJcbiAgLyoqXHJcbiAgICogVGhlIHJlcXVlc3RlZCBzY29wZXNcclxuICAgKi9cclxuICBwdWJsaWMgc2NvcGU/ID0gJ29wZW5pZCBwcm9maWxlJztcclxuXHJcbiAgcHVibGljIHJlc291cmNlPyA9ICcnO1xyXG5cclxuICBwdWJsaWMgcm5nVXJsPyA9ICcnO1xyXG5cclxuICAvKipcclxuICAgKiBEZWZpbmVzIHdoZXRoZXIgdG8gdXNlIE9wZW5JZCBDb25uZWN0IGR1cmluZ1xyXG4gICAqIGltcGxpY2l0IGZsb3cuXHJcbiAgICovXHJcbiAgcHVibGljIG9pZGM/ID0gdHJ1ZTtcclxuXHJcbiAgLyoqXHJcbiAgICogRGVmaW5lcyB3aGV0aGVyIHRvIHJlcXVlc3QgYW4gYWNjZXNzIHRva2VuIGR1cmluZ1xyXG4gICAqIGltcGxpY2l0IGZsb3cuXHJcbiAgICovXHJcbiAgcHVibGljIHJlcXVlc3RBY2Nlc3NUb2tlbj8gPSB0cnVlO1xyXG5cclxuICBwdWJsaWMgb3B0aW9ucz86IGFueSA9IG51bGw7XHJcblxyXG4gIC8qKlxyXG4gICAqIFRoZSBpc3N1ZXIncyB1cmkuXHJcbiAgICovXHJcbiAgcHVibGljIGlzc3Vlcj8gPSAnJztcclxuXHJcbiAgLyoqXHJcbiAgICogVGhlIGxvZ291dCB1cmwuXHJcbiAgICovXHJcbiAgcHVibGljIGxvZ291dFVybD8gPSAnJztcclxuXHJcbiAgLyoqXHJcbiAgICogRGVmaW5lcyB3aGV0aGVyIHRvIGNsZWFyIHRoZSBoYXNoIGZyYWdtZW50IGFmdGVyIGxvZ2dpbmcgaW4uXHJcbiAgICovXHJcbiAgcHVibGljIGNsZWFySGFzaEFmdGVyTG9naW4/ID0gdHJ1ZTtcclxuXHJcbiAgLyoqXHJcbiAgICogVXJsIG9mIHRoZSB0b2tlbiBlbmRwb2ludCBhcyBkZWZpbmVkIGJ5IE9wZW5JZCBDb25uZWN0IGFuZCBPQXV0aCAyLlxyXG4gICAqL1xyXG4gIHB1YmxpYyB0b2tlbkVuZHBvaW50Pzogc3RyaW5nID0gbnVsbDtcclxuXHJcbiAgLyoqXHJcbiAgICogVXJsIG9mIHRoZSByZXZvY2F0aW9uIGVuZHBvaW50IGFzIGRlZmluZWQgYnkgT3BlbklkIENvbm5lY3QgYW5kIE9BdXRoIDIuXHJcbiAgICovXHJcbiAgcHVibGljIHJldm9jYXRpb25FbmRwb2ludD86IHN0cmluZyA9IG51bGw7XHJcblxyXG4gIC8qKlxyXG4gICAqIE5hbWVzIG9mIGtub3duIHBhcmFtZXRlcnMgc2VudCBvdXQgaW4gdGhlIFRva2VuUmVzcG9uc2UuIGh0dHBzOi8vdG9vbHMuaWV0Zi5vcmcvaHRtbC9yZmM2NzQ5I3NlY3Rpb24tNS4xXHJcbiAgICovXHJcbiAgcHVibGljIGN1c3RvbVRva2VuUGFyYW1ldGVycz86IHN0cmluZ1tdID0gW107XHJcblxyXG4gIC8qKlxyXG4gICAqIFVybCBvZiB0aGUgdXNlcmluZm8gZW5kcG9pbnQgYXMgZGVmaW5lZCBieSBPcGVuSWQgQ29ubmVjdC5cclxuICAgKi9cclxuICBwdWJsaWMgdXNlcmluZm9FbmRwb2ludD86IHN0cmluZyA9IG51bGw7XHJcblxyXG4gIHB1YmxpYyByZXNwb25zZVR5cGU/ID0gJyc7XHJcblxyXG4gIC8qKlxyXG4gICAqIERlZmluZXMgd2hldGhlciBhZGRpdGlvbmFsIGRlYnVnIGluZm9ybWF0aW9uIHNob3VsZFxyXG4gICAqIGJlIHNob3duIGF0IHRoZSBjb25zb2xlLiBOb3RlIHRoYXQgaW4gY2VydGFpbiBicm93c2Vyc1xyXG4gICAqIHRoZSB2ZXJib3NpdHkgb2YgdGhlIGNvbnNvbGUgbmVlZHMgdG8gYmUgZXhwbGljaXRseSBzZXRcclxuICAgKiB0byBpbmNsdWRlIERlYnVnIGxldmVsIG1lc3NhZ2VzLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBzaG93RGVidWdJbmZvcm1hdGlvbj8gPSBmYWxzZTtcclxuXHJcbiAgLyoqXHJcbiAgICogVGhlIHJlZGlyZWN0IHVyaSB1c2VkIHdoZW4gZG9pbmcgc2lsZW50IHJlZnJlc2guXHJcbiAgICovXHJcbiAgcHVibGljIHNpbGVudFJlZnJlc2hSZWRpcmVjdFVyaT8gPSAnJztcclxuXHJcbiAgcHVibGljIHNpbGVudFJlZnJlc2hNZXNzYWdlUHJlZml4PyA9ICcnO1xyXG5cclxuICAvKipcclxuICAgKiBTZXQgdGhpcyB0byB0cnVlIHRvIGRpc3BsYXkgdGhlIGlmcmFtZSB1c2VkIGZvclxyXG4gICAqIHNpbGVudCByZWZyZXNoIGZvciBkZWJ1Z2dpbmcuXHJcbiAgICovXHJcbiAgcHVibGljIHNpbGVudFJlZnJlc2hTaG93SUZyYW1lPyA9IGZhbHNlO1xyXG5cclxuICAvKipcclxuICAgKiBUaW1lb3V0IGZvciBzaWxlbnQgcmVmcmVzaC5cclxuICAgKiBAaW50ZXJuYWxcclxuICAgKiBkZXByZWFjdGVkIGIvYyBvZiB0eXBvLCBzZWUgc2lsZW50UmVmcmVzaFRpbWVvdXRcclxuICAgKi9cclxuICBwdWJsaWMgc2lsZXRSZWZyZXNoVGltZW91dD86IG51bWJlciA9IDEwMDAgKiAyMDtcclxuXHJcbiAgLyoqXHJcbiAgICogVGltZW91dCBmb3Igc2lsZW50IHJlZnJlc2guXHJcbiAgICovXHJcbiAgcHVibGljIHNpbGVudFJlZnJlc2hUaW1lb3V0PzogbnVtYmVyID0gMTAwMCAqIDIwO1xyXG5cclxuICAvKipcclxuICAgKiBTb21lIGF1dGggc2VydmVycyBkb24ndCBhbGxvdyB1c2luZyBwYXNzd29yZCBmbG93XHJcbiAgICogdy9vIGEgY2xpZW50IHNlY3JldCB3aGlsZSB0aGUgc3RhbmRhcmRzIGRvIG5vdFxyXG4gICAqIGRlbWFuZCBmb3IgaXQuIEluIHRoaXMgY2FzZSwgeW91IGNhbiBzZXQgYSBwYXNzd29yZFxyXG4gICAqIGhlcmUuIEFzIHRoaXMgcGFzc3dvcmQgaXMgZXhwb3NlZCB0byB0aGUgcHVibGljXHJcbiAgICogaXQgZG9lcyBub3QgYnJpbmcgYWRkaXRpb25hbCBzZWN1cml0eSBhbmQgaXMgdGhlcmVmb3JlXHJcbiAgICogYXMgZ29vZCBhcyB1c2luZyBubyBwYXNzd29yZC5cclxuICAgKi9cclxuICBwdWJsaWMgZHVtbXlDbGllbnRTZWNyZXQ/OiBzdHJpbmcgPSBudWxsO1xyXG5cclxuICAvKipcclxuICAgKiBEZWZpbmVzIHdoZXRoZXIgaHR0cHMgaXMgcmVxdWlyZWQuXHJcbiAgICogVGhlIGRlZmF1bHQgdmFsdWUgaXMgcmVtb3RlT25seSB3aGljaCBvbmx5IGFsbG93c1xyXG4gICAqIGh0dHAgZm9yIGxvY2FsaG9zdCwgd2hpbGUgZXZlcnkgb3RoZXIgZG9tYWlucyBuZWVkXHJcbiAgICogdG8gYmUgdXNlZCB3aXRoIGh0dHBzLlxyXG4gICAqL1xyXG4gIHB1YmxpYyByZXF1aXJlSHR0cHM/OiBib29sZWFuIHwgJ3JlbW90ZU9ubHknID0gJ3JlbW90ZU9ubHknO1xyXG5cclxuICAvKipcclxuICAgKiBEZWZpbmVzIHdoZXRoZXIgZXZlcnkgdXJsIHByb3ZpZGVkIGJ5IHRoZSBkaXNjb3ZlcnlcclxuICAgKiBkb2N1bWVudCBoYXMgdG8gc3RhcnQgd2l0aCB0aGUgaXNzdWVyJ3MgdXJsLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBzdHJpY3REaXNjb3ZlcnlEb2N1bWVudFZhbGlkYXRpb24/ID0gdHJ1ZTtcclxuXHJcbiAgLyoqXHJcbiAgICogSlNPTiBXZWIgS2V5IFNldCAoaHR0cHM6Ly90b29scy5pZXRmLm9yZy9odG1sL3JmYzc1MTcpXHJcbiAgICogd2l0aCBrZXlzIHVzZWQgdG8gdmFsaWRhdGUgcmVjZWl2ZWQgaWRfdG9rZW5zLlxyXG4gICAqIFRoaXMgaXMgdGFrZW4gb3V0IG9mIHRoZSBkaXNvdmVyeSBkb2N1bWVudC4gQ2FuIGJlIHNldCBtYW51YWxseSB0b28uXHJcbiAgICovXHJcbiAgcHVibGljIGp3a3M/OiBvYmplY3QgPSBudWxsO1xyXG5cclxuICAvKipcclxuICAgKiBNYXAgd2l0aCBhZGRpdGlvbmFsIHF1ZXJ5IHBhcmFtZXRlciB0aGF0IGFyZSBhcHBlbmRlZCB0b1xyXG4gICAqIHRoZSByZXF1ZXN0IHdoZW4gaW5pdGlhbGl6aW5nIGltcGxpY2l0IGZsb3cuXHJcbiAgICovXHJcbiAgcHVibGljIGN1c3RvbVF1ZXJ5UGFyYW1zPzogb2JqZWN0ID0gbnVsbDtcclxuXHJcbiAgcHVibGljIHNpbGVudFJlZnJlc2hJRnJhbWVOYW1lPyA9ICdhbmd1bGFyLW9hdXRoLW9pZGMtc2lsZW50LXJlZnJlc2gtaWZyYW1lJztcclxuXHJcbiAgLyoqXHJcbiAgICogRGVmaW5lcyB3aGVuIHRoZSB0b2tlbl90aW1lb3V0IGV2ZW50IHNob3VsZCBiZSByYWlzZWQuXHJcbiAgICogSWYgeW91IHNldCB0aGlzIHRvIHRoZSBkZWZhdWx0IHZhbHVlIDAuNzUsIHRoZSBldmVudFxyXG4gICAqIGlzIHRyaWdnZXJlZCBhZnRlciA3NSUgb2YgdGhlIHRva2VuJ3MgbGlmZSB0aW1lLlxyXG4gICAqL1xyXG4gIHB1YmxpYyB0aW1lb3V0RmFjdG9yPyA9IDAuNzU7XHJcblxyXG4gIC8qKlxyXG4gICAqIElmIHRydWUsIHRoZSBsaWIgd2lsbCB0cnkgdG8gY2hlY2sgd2hldGhlciB0aGUgdXNlclxyXG4gICAqIGlzIHN0aWxsIGxvZ2dlZCBpbiBvbiBhIHJlZ3VsYXIgYmFzaXMgYXMgZGVzY3JpYmVkXHJcbiAgICogaW4gaHR0cDovL29wZW5pZC5uZXQvc3BlY3Mvb3BlbmlkLWNvbm5lY3Qtc2Vzc2lvbi0xXzAuaHRtbCNDaGFuZ2VOb3RpZmljYXRpb25cclxuICAgKi9cclxuICBwdWJsaWMgc2Vzc2lvbkNoZWNrc0VuYWJsZWQ/ID0gZmFsc2U7XHJcblxyXG4gIC8qKlxyXG4gICAqIEludGVydmFsIGluIG1zZWMgZm9yIGNoZWNraW5nIHRoZSBzZXNzaW9uXHJcbiAgICogYWNjb3JkaW5nIHRvIGh0dHA6Ly9vcGVuaWQubmV0L3NwZWNzL29wZW5pZC1jb25uZWN0LXNlc3Npb24tMV8wLmh0bWwjQ2hhbmdlTm90aWZpY2F0aW9uXHJcbiAgICovXHJcbiAgcHVibGljIHNlc3Npb25DaGVja0ludGVydmFsbD8gPSAzICogMTAwMDtcclxuXHJcbiAgLyoqXHJcbiAgICogVXJsIGZvciB0aGUgaWZyYW1lIHVzZWQgZm9yIHNlc3Npb24gY2hlY2tzXHJcbiAgICovXHJcbiAgcHVibGljIHNlc3Npb25DaGVja0lGcmFtZVVybD86IHN0cmluZyA9IG51bGw7XHJcblxyXG4gIC8qKlxyXG4gICAqIE5hbWUgb2YgdGhlIGlmcmFtZSB0byB1c2UgZm9yIHNlc3Npb24gY2hlY2tzXHJcbiAgICovXHJcbiAgcHVibGljIHNlc3Npb25DaGVja0lGcmFtZU5hbWU/ID0gJ2FuZ3VsYXItb2F1dGgtb2lkYy1jaGVjay1zZXNzaW9uLWlmcmFtZSc7XHJcblxyXG4gIC8qKlxyXG4gICAqIFRoaXMgcHJvcGVydHkgaGFzIGJlZW4gaW50cm9kdWNlZCB0byBkaXNhYmxlIGF0X2hhc2ggY2hlY2tzXHJcbiAgICogYW5kIGlzIGluZGVudGVkIGZvciBJZGVudGl0eSBQcm92aWRlciB0aGF0IGRvZXMgbm90IGRlbGl2ZXJcclxuICAgKiBhbiBhdF9oYXNoIEVWRU4gVEhPVUdIIGl0cyByZWNvbW1lbmRlZCBieSB0aGUgT0lEQyBzcGVjcy5cclxuICAgKiBPZiBjb3Vyc2UsIHdoZW4gZGlzYWJsaW5nIHRoZXNlIGNoZWNrcyB0aGUgd2UgYXJlIGJ5cGFzc2luZ1xyXG4gICAqIGEgc2VjdXJpdHkgY2hlY2sgd2hpY2ggbWVhbnMgd2UgYXJlIG1vcmUgdnVsbmVyYWJsZS5cclxuICAgKi9cclxuICBwdWJsaWMgZGlzYWJsZUF0SGFzaENoZWNrPyA9IGZhbHNlO1xyXG5cclxuICAvKipcclxuICAgKiBEZWZpbmVzIHdldGhlciB0byBjaGVjayB0aGUgc3ViamVjdCBvZiBhIHJlZnJlc2hlZCB0b2tlbiBhZnRlciBzaWxlbnQgcmVmcmVzaC5cclxuICAgKiBOb3JtYWxseSwgaXQgc2hvdWxkIGJlIHRoZSBzYW1lIGFzIGJlZm9yZS5cclxuICAgKi9cclxuICBwdWJsaWMgc2tpcFN1YmplY3RDaGVjaz8gPSBmYWxzZTtcclxuXHJcbiAgcHVibGljIHVzZUlkVG9rZW5IaW50Rm9yU2lsZW50UmVmcmVzaD8gPSBmYWxzZTtcclxuXHJcbiAgLyoqXHJcbiAgICogRGVmaW5lZCB3aGV0aGVyIHRvIHNraXAgdGhlIHZhbGlkYXRpb24gb2YgdGhlIGlzc3VlciBpbiB0aGUgZGlzY292ZXJ5IGRvY3VtZW50LlxyXG4gICAqIE5vcm1hbGx5LCB0aGUgZGlzY292ZXkgZG9jdW1lbnQncyB1cmwgc3RhcnRzIHdpdGggdGhlIHVybCBvZiB0aGUgaXNzdWVyLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBza2lwSXNzdWVyQ2hlY2s/ID0gZmFsc2U7XHJcblxyXG4gIC8qKlxyXG4gICAqIEFjY29yZGluZyB0byByZmM2NzQ5IGl0IGlzIHJlY29tbWVuZGVkIChidXQgbm90IHJlcXVpcmVkKSB0aGF0IHRoZSBhdXRoXHJcbiAgICogc2VydmVyIGV4cG9zZXMgdGhlIGFjY2Vzc190b2tlbidzIGxpZmUgdGltZSBpbiBzZWNvbmRzLlxyXG4gICAqIFRoaXMgaXMgYSBmYWxsYmFjayB2YWx1ZSBmb3IgdGhlIGNhc2UgdGhpcyB2YWx1ZSBpcyBub3QgZXhwb3NlZC5cclxuICAgKi9cclxuICBwdWJsaWMgZmFsbGJhY2tBY2Nlc3NUb2tlbkV4cGlyYXRpb25UaW1lSW5TZWM/OiBudW1iZXI7XHJcblxyXG4gIC8qKlxyXG4gICAqIGZpbmFsIHN0YXRlIHNlbnQgdG8gaXNzdWVyIGlzIGJ1aWx0IGFzIGZvbGxvd3M6XHJcbiAgICogc3RhdGUgPSBub25jZSArIG5vbmNlU3RhdGVTZXBhcmF0b3IgKyBhZGRpdGlvbmFsIHN0YXRlXHJcbiAgICogRGVmYXVsdCBzZXBhcmF0b3IgaXMgJzsnIChlbmNvZGVkICUzQikuXHJcbiAgICogSW4gcmFyZSBjYXNlcywgdGhpcyBjaGFyYWN0ZXIgbWlnaHQgYmUgZm9yYmlkZGVuIG9yIGluY29udmVuaWVudCB0byB1c2UgYnkgdGhlIGlzc3VlciBzbyBpdCBjYW4gYmUgY3VzdG9taXplZC5cclxuICAgKi9cclxuICBwdWJsaWMgbm9uY2VTdGF0ZVNlcGFyYXRvcj8gPSAnOyc7XHJcblxyXG4gIC8qKlxyXG4gICAqIFNldCB0aGlzIHRvIHRydWUgdG8gdXNlIEhUVFAgQkFTSUMgYXV0aCBmb3IgQUpBWCBjYWxsc1xyXG4gICAqL1xyXG4gIHB1YmxpYyB1c2VIdHRwQmFzaWNBdXRoPyA9IGZhbHNlO1xyXG5cclxuICAvKipcclxuICAgKiBUaGUgd2luZG93IG9mIHRpbWUgKGluIHNlY29uZHMpIHRvIGFsbG93IHRoZSBjdXJyZW50IHRpbWUgdG8gZGV2aWF0ZSB3aGVuIHZhbGlkYXRpbmcgaWRfdG9rZW4ncyBpYXQgYW5kIGV4cCB2YWx1ZXMuXHJcbiAgICovXHJcbiAgcHVibGljIGNsb2NrU2tld0luU2VjPzogbnVtYmVyO1xyXG5cclxuICAvKipcclxuICAgKiBUaGUgaW50ZXJjZXB0b3JzIHdhaXRzIHRoaXMgdGltZSBzcGFuIGlmIHRoZXJlIGlzIG5vIHRva2VuXHJcbiAgICovXHJcbiAgcHVibGljIHdhaXRGb3JUb2tlbkluTXNlYz8gPSAwO1xyXG5cclxuICAvKipcclxuICAgKiBTZXQgdGhpcyB0byB0cnVlIGlmIHlvdSB3YW50IHRvIHVzZSBzaWxlbnQgcmVmcmVzaCB0b2dldGhlciB3aXRoXHJcbiAgICogY29kZSBmbG93LiBBcyBzaWxlbnQgcmVmcmVzaCBpcyB0aGUgb25seSBvcHRpb24gZm9yIHJlZnJlc2hpbmdcclxuICAgKiB3aXRoIGltcGxpY2l0IGZsb3csIHlvdSBkb24ndCBuZWVkIHRvIGV4cGxpY2l0bHkgdHVybiBpdCBvbiBpblxyXG4gICAqIHRoaXMgY2FzZS5cclxuICAgKi9cclxuICBwdWJsaWMgdXNlU2lsZW50UmVmcmVzaD87XHJcblxyXG4gIC8qKlxyXG4gICAqIENvZGUgRmxvdyBpcyBieSBkZWZhdWxkIHVzZWQgdG9nZXRoZXIgd2l0aCBQS0NJIHdoaWNoIGlzIGFsc28gaGlnbHkgcmVjb21tZW50ZWQuXHJcbiAgICogWW91IGNhbiBkaXNiYWxlIGl0IGhlcmUgYnkgc2V0dGluZyB0aGlzIGZsYWcgdG8gdHJ1ZS5cclxuICAgKiBodHRwczovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjNzYzNiNzZWN0aW9uLTEuMVxyXG4gICAqL1xyXG4gIHB1YmxpYyBkaXNhYmxlUEtDRT8gPSBmYWxzZTtcclxuXHJcbiAgY29uc3RydWN0b3IoanNvbj86IFBhcnRpYWw8QXV0aENvbmZpZz4pIHtcclxuICAgIGlmIChqc29uKSB7XHJcbiAgICAgIE9iamVjdC5hc3NpZ24odGhpcywganNvbik7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBUaGlzIHByb3BlcnR5IGFsbG93cyB5b3UgdG8gb3ZlcnJpZGUgdGhlIG1ldGhvZCB0aGF0IGlzIHVzZWQgdG8gb3BlbiB0aGUgbG9naW4gdXJsLFxyXG4gICAqIGFsbG93aW5nIGEgd2F5IGZvciBpbXBsZW1lbnRhdGlvbnMgdG8gc3BlY2lmeSB0aGVpciBvd24gbWV0aG9kIG9mIHJvdXRpbmcgdG8gbmV3XHJcbiAgICogdXJscy5cclxuICAgKi9cclxuICBwdWJsaWMgb3BlblVyaT86ICh1cmk6IHN0cmluZykgPT4gdm9pZCA9IHVyaSA9PiB7XHJcbiAgICBsb2NhdGlvbi5ocmVmID0gdXJpO1xyXG4gIH07XHJcbn1cclxuIl19