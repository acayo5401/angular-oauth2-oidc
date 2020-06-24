import { __awaiter, __decorate, __extends, __generator, __metadata, __param, __read, __values } from "tslib";
import { Injectable, NgZone, Optional, OnDestroy, Inject } from '@angular/core';
import { HttpClient, HttpHeaders, HttpParams } from '@angular/common/http';
import { Subject, of, race, from, combineLatest } from 'rxjs';
import { filter, delay, first, tap, map, switchMap, debounceTime } from 'rxjs/operators';
import { DOCUMENT } from '@angular/common';
import { ValidationHandler, ValidationParams } from './token-validation/validation-handler';
import { UrlHelperService } from './url-helper.service';
import { OAuthInfoEvent, OAuthErrorEvent, OAuthSuccessEvent } from './events';
import { OAuthLogger, OAuthStorage, LoginOptions, ParsedIdToken, OidcDiscoveryDoc, TokenResponse, UserInfo } from './types';
import { b64DecodeUnicode, base64UrlEncode } from './base64-helper';
import { AuthConfig } from './auth.config';
import { WebHttpUrlEncodingCodec } from './encoder';
import { HashHandler } from './token-validation/hash-handler';
/**
 * Service for logging in and logging out with
 * OIDC and OAuth2. Supports implicit flow and
 * password flow.
 */
var OAuthService = /** @class */ (function (_super) {
    __extends(OAuthService, _super);
    function OAuthService(ngZone, http, storage, tokenValidationHandler, config, urlHelper, logger, crypto, document) {
        var _a, _b, _c, _d;
        var _this = _super.call(this) || this;
        _this.ngZone = ngZone;
        _this.http = http;
        _this.config = config;
        _this.urlHelper = urlHelper;
        _this.logger = logger;
        _this.crypto = crypto;
        _this.document = document;
        /**
         * @internal
         * Deprecated:  use property events instead
         */
        _this.discoveryDocumentLoaded = false;
        /**
         * The received (passed around) state, when logging
         * in with implicit flow.
         */
        _this.state = '';
        _this.eventsSubject = new Subject();
        _this.discoveryDocumentLoadedSubject = new Subject();
        _this.grantTypesSupported = [];
        _this.inImplicitFlow = false;
        _this.saveNoncesInLocalStorage = false;
        _this.debug('angular-oauth2-oidc v8-beta');
        _this.discoveryDocumentLoaded$ = _this.discoveryDocumentLoadedSubject.asObservable();
        _this.events = _this.eventsSubject.asObservable();
        if (tokenValidationHandler) {
            _this.tokenValidationHandler = tokenValidationHandler;
        }
        if (config) {
            _this.configure(config);
        }
        try {
            if (storage) {
                _this.setStorage(storage);
            }
            else if (typeof sessionStorage !== 'undefined') {
                _this.setStorage(sessionStorage);
            }
        }
        catch (e) {
            console.error('No OAuthStorage provided and cannot access default (sessionStorage).' +
                'Consider providing a custom OAuthStorage implementation in your module.', e);
        }
        // in IE, sessionStorage does not always survive a redirect
        if (typeof window !== 'undefined' &&
            typeof window['localStorage'] !== 'undefined') {
            var ua = (_b = (_a = window) === null || _a === void 0 ? void 0 : _a.navigator) === null || _b === void 0 ? void 0 : _b.userAgent;
            var msie = ((_c = ua) === null || _c === void 0 ? void 0 : _c.includes('MSIE ')) || ((_d = ua) === null || _d === void 0 ? void 0 : _d.includes('Trident'));
            if (msie) {
                _this.saveNoncesInLocalStorage = true;
            }
        }
        _this.setupRefreshTimer();
        return _this;
    }
    /**
     * Use this method to configure the service
     * @param config the configuration
     */
    OAuthService.prototype.configure = function (config) {
        // For the sake of downward compatibility with
        // original configuration API
        Object.assign(this, new AuthConfig(), config);
        this.config = Object.assign({}, new AuthConfig(), config);
        if (this.sessionChecksEnabled) {
            this.setupSessionCheck();
        }
        this.configChanged();
    };
    OAuthService.prototype.configChanged = function () {
        this.setupRefreshTimer();
    };
    OAuthService.prototype.restartSessionChecksIfStillLoggedIn = function () {
        if (this.hasValidIdToken()) {
            this.initSessionCheck();
        }
    };
    OAuthService.prototype.restartRefreshTimerIfStillLoggedIn = function () {
        this.setupExpirationTimers();
    };
    OAuthService.prototype.setupSessionCheck = function () {
        var _this = this;
        this.events.pipe(filter(function (e) { return e.type === 'token_received'; })).subscribe(function (e) {
            _this.initSessionCheck();
        });
    };
    /**
     * Will setup up silent refreshing for when the token is
     * about to expire. When the user is logged out via this.logOut method, the
     * silent refreshing will pause and not refresh the tokens until the user is
     * logged back in via receiving a new token.
     * @param params Additional parameter to pass
     * @param listenTo Setup automatic refresh of a specific token type
     */
    OAuthService.prototype.setupAutomaticSilentRefresh = function (params, listenTo, noPrompt) {
        var _this = this;
        if (params === void 0) { params = {}; }
        if (noPrompt === void 0) { noPrompt = true; }
        var shouldRunSilentRefresh = true;
        this.events
            .pipe(tap(function (e) {
            if (e.type === 'token_received') {
                shouldRunSilentRefresh = true;
            }
            else if (e.type === 'logout') {
                shouldRunSilentRefresh = false;
            }
        }), filter(function (e) { return e.type === 'token_expires'; }), debounceTime(1000))
            .subscribe(function (e) {
            var event = e;
            if ((listenTo == null || listenTo === 'any' || event.info === listenTo) &&
                shouldRunSilentRefresh) {
                // this.silentRefresh(params, noPrompt).catch(_ => {
                _this.refreshInternal(params, noPrompt).catch(function (_) {
                    _this.debug('Automatic silent refresh did not work');
                });
            }
        });
        this.restartRefreshTimerIfStillLoggedIn();
    };
    OAuthService.prototype.refreshInternal = function (params, noPrompt) {
        if (!this.useSilentRefresh && this.responseType === 'code') {
            return this.refreshToken();
        }
        else {
            return this.silentRefresh(params, noPrompt);
        }
    };
    /**
     * Convenience method that first calls `loadDiscoveryDocument(...)` and
     * directly chains using the `then(...)` part of the promise to call
     * the `tryLogin(...)` method.
     *
     * @param options LoginOptions to pass through to `tryLogin(...)`
     */
    OAuthService.prototype.loadDiscoveryDocumentAndTryLogin = function (options) {
        var _this = this;
        if (options === void 0) { options = null; }
        return this.loadDiscoveryDocument().then(function (doc) {
            return _this.tryLogin(options);
        });
    };
    /**
     * Convenience method that first calls `loadDiscoveryDocumentAndTryLogin(...)`
     * and if then chains to `initLoginFlow()`, but only if there is no valid
     * IdToken or no valid AccessToken.
     *
     * @param options LoginOptions to pass through to `tryLogin(...)`
     */
    OAuthService.prototype.loadDiscoveryDocumentAndLogin = function (options) {
        var _this = this;
        if (options === void 0) { options = null; }
        if (!options) {
            options = { state: '' };
        }
        return this.loadDiscoveryDocumentAndTryLogin(options).then(function (_) {
            if (!_this.hasValidIdToken() || !_this.hasValidAccessToken()) {
                if (_this.responseType === 'code') {
                    _this.initCodeFlow(options.state);
                }
                else {
                    _this.initImplicitFlow(options.state);
                }
                return false;
            }
            else {
                return true;
            }
        });
    };
    OAuthService.prototype.debug = function () {
        var args = [];
        for (var _i = 0; _i < arguments.length; _i++) {
            args[_i] = arguments[_i];
        }
        if (this.showDebugInformation) {
            this.logger.debug.apply(this.logger, args);
        }
    };
    OAuthService.prototype.validateUrlFromDiscoveryDocument = function (url) {
        var errors = [];
        var httpsCheck = this.validateUrlForHttps(url);
        var issuerCheck = this.validateUrlAgainstIssuer(url);
        if (!httpsCheck) {
            errors.push('https for all urls required. Also for urls received by discovery.');
        }
        if (!issuerCheck) {
            errors.push('Every url in discovery document has to start with the issuer url.' +
                'Also see property strictDiscoveryDocumentValidation.');
        }
        return errors;
    };
    OAuthService.prototype.validateUrlForHttps = function (url) {
        if (!url) {
            return true;
        }
        var lcUrl = url.toLowerCase();
        if (this.requireHttps === false) {
            return true;
        }
        if ((lcUrl.match(/^http:\/\/localhost($|[:\/])/) ||
            lcUrl.match(/^http:\/\/localhost($|[:\/])/)) &&
            this.requireHttps === 'remoteOnly') {
            return true;
        }
        return lcUrl.startsWith('https://');
    };
    OAuthService.prototype.assertUrlNotNullAndCorrectProtocol = function (url, description) {
        if (!url) {
            throw new Error("'" + description + "' should not be null");
        }
        if (!this.validateUrlForHttps(url)) {
            throw new Error("'" + description + "' must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
        }
    };
    OAuthService.prototype.validateUrlAgainstIssuer = function (url) {
        if (!this.strictDiscoveryDocumentValidation) {
            return true;
        }
        if (!url) {
            return true;
        }
        return url.toLowerCase().startsWith(this.issuer.toLowerCase());
    };
    OAuthService.prototype.setupRefreshTimer = function () {
        var _this = this;
        if (typeof window === 'undefined') {
            this.debug('timer not supported on this plattform');
            return;
        }
        if (this.hasValidIdToken() || this.hasValidAccessToken()) {
            this.clearAccessTokenTimer();
            this.clearIdTokenTimer();
            this.setupExpirationTimers();
        }
        if (this.tokenReceivedSubscription)
            this.tokenReceivedSubscription.unsubscribe();
        this.tokenReceivedSubscription = this.events
            .pipe(filter(function (e) { return e.type === 'token_received'; }))
            .subscribe(function (_) {
            _this.clearAccessTokenTimer();
            _this.clearIdTokenTimer();
            _this.setupExpirationTimers();
        });
    };
    OAuthService.prototype.setupExpirationTimers = function () {
        if (this.hasValidAccessToken()) {
            //this.setupAccessTokenTimer();
        }
        if (this.hasValidIdToken()) {
            //this.setupIdTokenTimer();
        }
    };
    OAuthService.prototype.setupAccessTokenTimer = function () {
        var _this = this;
        var expiration = this.getAccessTokenExpiration();
        var storedAt = this.getAccessTokenStoredAt();
        var timeout = this.calcTimeout(storedAt, expiration);
        this.ngZone.runOutsideAngular(function () {
            _this.accessTokenTimeoutSubscription = of(new OAuthInfoEvent('token_expires', 'access_token'))
                .pipe(delay(timeout))
                .subscribe(function (e) {
                _this.ngZone.run(function () {
                    _this.eventsSubject.next(e);
                });
            });
        });
    };
    OAuthService.prototype.setupIdTokenTimer = function () {
        var _this = this;
        var expiration = this.getIdTokenExpiration();
        var storedAt = this.getIdTokenStoredAt();
        var timeout = this.calcTimeout(storedAt, expiration);
        this.ngZone.runOutsideAngular(function () {
            _this.idTokenTimeoutSubscription = of(new OAuthInfoEvent('token_expires', 'id_token'))
                .pipe(delay(timeout))
                .subscribe(function (e) {
                _this.ngZone.run(function () {
                    _this.eventsSubject.next(e);
                });
            });
        });
    };
    /**
     * Stops timers for automatic refresh.
     * To restart it, call setupAutomaticSilentRefresh again.
     */
    OAuthService.prototype.stopAutomaticRefresh = function () {
        this.clearAccessTokenTimer();
        this.clearIdTokenTimer();
    };
    OAuthService.prototype.clearAccessTokenTimer = function () {
        if (this.accessTokenTimeoutSubscription) {
            this.accessTokenTimeoutSubscription.unsubscribe();
        }
    };
    OAuthService.prototype.clearIdTokenTimer = function () {
        if (this.idTokenTimeoutSubscription) {
            this.idTokenTimeoutSubscription.unsubscribe();
        }
    };
    OAuthService.prototype.calcTimeout = function (storedAt, expiration) {
        var now = Date.now();
        var delta = (expiration - storedAt) * this.timeoutFactor - (now - storedAt);
        return Math.max(0, delta);
    };
    /**
     * DEPRECATED. Use a provider for OAuthStorage instead:
     *
     * { provide: OAuthStorage, useFactory: oAuthStorageFactory }
     * export function oAuthStorageFactory(): OAuthStorage { return localStorage; }
     * Sets a custom storage used to store the received
     * tokens on client side. By default, the browser's
     * sessionStorage is used.
     * @ignore
     *
     * @param storage
     */
    OAuthService.prototype.setStorage = function (storage) {
        this._storage = storage;
        this.configChanged();
    };
    /**
     * Loads the discovery document to configure most
     * properties of this service. The url of the discovery
     * document is infered from the issuer's url according
     * to the OpenId Connect spec. To use another url you
     * can pass it to to optional parameter fullUrl.
     *
     * @param fullUrl
     */
    OAuthService.prototype.loadDiscoveryDocument = function (fullUrl) {
        var _this = this;
        if (fullUrl === void 0) { fullUrl = null; }
        return new Promise(function (resolve, reject) {
            if (!fullUrl) {
                fullUrl = _this.issuer || '';
                if (!fullUrl.endsWith('/')) {
                    fullUrl += '/';
                }
                fullUrl += '.well-known/openid-configuration';
            }
            if (!_this.validateUrlForHttps(fullUrl)) {
                reject("issuer  must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
                return;
            }
            _this.http.get(fullUrl).subscribe(function (doc) {
                if (!_this.validateDiscoveryDocument(doc)) {
                    _this.eventsSubject.next(new OAuthErrorEvent('discovery_document_validation_error', null));
                    reject('discovery_document_validation_error');
                    return;
                }
                _this.loginUrl = doc.authorization_endpoint;
                _this.logoutUrl = doc.end_session_endpoint || _this.logoutUrl;
                _this.grantTypesSupported = doc.grant_types_supported;
                _this.issuer = doc.issuer;
                _this.tokenEndpoint = doc.token_endpoint;
                _this.userinfoEndpoint =
                    doc.userinfo_endpoint || _this.userinfoEndpoint;
                _this.jwksUri = doc.jwks_uri;
                _this.sessionCheckIFrameUrl =
                    doc.check_session_iframe || _this.sessionCheckIFrameUrl;
                _this.discoveryDocumentLoaded = true;
                _this.discoveryDocumentLoadedSubject.next(doc);
                _this.revocationEndpoint = doc.revocation_endpoint;
                if (_this.sessionChecksEnabled) {
                    _this.restartSessionChecksIfStillLoggedIn();
                }
                _this.loadJwks()
                    .then(function (jwks) {
                    var result = {
                        discoveryDocument: doc,
                        jwks: jwks
                    };
                    var event = new OAuthSuccessEvent('discovery_document_loaded', result);
                    _this.eventsSubject.next(event);
                    resolve(event);
                    return;
                })
                    .catch(function (err) {
                    _this.eventsSubject.next(new OAuthErrorEvent('discovery_document_load_error', err));
                    reject(err);
                    return;
                });
            }, function (err) {
                _this.logger.error('error loading discovery document', err);
                _this.eventsSubject.next(new OAuthErrorEvent('discovery_document_load_error', err));
                reject(err);
            });
        });
    };
    OAuthService.prototype.loadJwks = function () {
        var _this = this;
        return new Promise(function (resolve, reject) {
            if (_this.jwksUri) {
                _this.http.get(_this.jwksUri).subscribe(function (jwks) {
                    _this.jwks = jwks;
                    _this.eventsSubject.next(new OAuthSuccessEvent('discovery_document_loaded'));
                    resolve(jwks);
                }, function (err) {
                    _this.logger.error('error loading jwks', err);
                    _this.eventsSubject.next(new OAuthErrorEvent('jwks_load_error', err));
                    reject(err);
                });
            }
            else {
                resolve(null);
            }
        });
    };
    OAuthService.prototype.validateDiscoveryDocument = function (doc) {
        var errors;
        if (!this.skipIssuerCheck && doc.issuer !== this.issuer) {
            this.logger.error('invalid issuer in discovery document', 'expected: ' + this.issuer, 'current: ' + doc.issuer);
            return false;
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.authorization_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating authorization_endpoint in discovery document', errors);
            return false;
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.end_session_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating end_session_endpoint in discovery document', errors);
            return false;
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.token_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating token_endpoint in discovery document', errors);
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.revocation_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating revocation_endpoint in discovery document', errors);
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.userinfo_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating userinfo_endpoint in discovery document', errors);
            return false;
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.jwks_uri);
        if (errors.length > 0) {
            this.logger.error('error validating jwks_uri in discovery document', errors);
            return false;
        }
        if (this.sessionChecksEnabled && !doc.check_session_iframe) {
            this.logger.warn('sessionChecksEnabled is activated but discovery document' +
                ' does not contain a check_session_iframe field');
        }
        return true;
    };
    /**
     * Uses password flow to exchange userName and password for an
     * access_token. After receiving the access_token, this method
     * uses it to query the userinfo endpoint in order to get information
     * about the user in question.
     *
     * When using this, make sure that the property oidc is set to false.
     * Otherwise stricter validations take place that make this operation
     * fail.
     *
     * @param userName
     * @param password
     * @param headers Optional additional http-headers.
     */
    OAuthService.prototype.fetchTokenUsingPasswordFlowAndLoadUserProfile = function (userName, password, headers) {
        var _this = this;
        if (headers === void 0) { headers = new HttpHeaders(); }
        return this.fetchTokenUsingPasswordFlow(userName, password, headers).then(function () { return _this.loadUserProfile(); });
    };
    /**
     * Loads the user profile by accessing the user info endpoint defined by OpenId Connect.
     *
     * When using this with OAuth2 password flow, make sure that the property oidc is set to false.
     * Otherwise stricter validations take place that make this operation fail.
     */
    OAuthService.prototype.loadUserProfile = function () {
        var _this = this;
        if (!this.hasValidAccessToken()) {
            throw new Error('Can not load User Profile without access_token');
        }
        if (!this.validateUrlForHttps(this.userinfoEndpoint)) {
            throw new Error("userinfoEndpoint must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
        }
        return new Promise(function (resolve, reject) {
            var headers = new HttpHeaders().set('Authorization', 'Bearer ' + _this.getAccessToken());
            _this.http
                .get(_this.userinfoEndpoint, { headers: headers })
                .subscribe(function (info) {
                _this.debug('userinfo received', info);
                var existingClaims = _this.getIdentityClaims() || {};
                if (!_this.skipSubjectCheck) {
                    if (_this.oidc &&
                        (!existingClaims['sub'] || info.sub !== existingClaims['sub'])) {
                        var err = 'if property oidc is true, the received user-id (sub) has to be the user-id ' +
                            'of the user that has logged in with oidc.\n' +
                            'if you are not using oidc but just oauth2 password flow set oidc to false';
                        reject(err);
                        return;
                    }
                }
                info = Object.assign({}, existingClaims, info);
                _this._storage.setItem('id_token_claims_obj', JSON.stringify(info));
                _this.eventsSubject.next(new OAuthSuccessEvent('user_profile_loaded'));
                resolve(info);
            }, function (err) {
                _this.logger.error('error loading user info', err);
                _this.eventsSubject.next(new OAuthErrorEvent('user_profile_load_error', err));
                reject(err);
            });
        });
    };
    /**
     * Uses password flow to exchange userName and password for an access_token.
     * @param userName
     * @param password
     * @param headers Optional additional http-headers.
     */
    OAuthService.prototype.fetchTokenUsingPasswordFlow = function (userName, password, headers) {
        var _this = this;
        if (headers === void 0) { headers = new HttpHeaders(); }
        this.assertUrlNotNullAndCorrectProtocol(this.tokenEndpoint, 'tokenEndpoint');
        return new Promise(function (resolve, reject) {
            var e_1, _a;
            /**
             * A `HttpParameterCodec` that uses `encodeURIComponent` and `decodeURIComponent` to
             * serialize and parse URL parameter keys and values.
             *
             * @stable
             */
            var params = new HttpParams({ encoder: new WebHttpUrlEncodingCodec() })
                .set('grant_type', 'password')
                .set('scope', _this.scope)
                .set('username', userName)
                .set('password', password);
            if (_this.useHttpBasicAuth) {
                var header = btoa(_this.clientId + ":" + _this.dummyClientSecret);
                headers = headers.set('Authorization', 'Basic ' + header);
            }
            if (!_this.useHttpBasicAuth) {
                params = params.set('client_id', _this.clientId);
            }
            if (!_this.useHttpBasicAuth && _this.dummyClientSecret) {
                params = params.set('client_secret', _this.dummyClientSecret);
            }
            if (_this.customQueryParams) {
                try {
                    for (var _b = __values(Object.getOwnPropertyNames(_this.customQueryParams)), _c = _b.next(); !_c.done; _c = _b.next()) {
                        var key = _c.value;
                        params = params.set(key, _this.customQueryParams[key]);
                    }
                }
                catch (e_1_1) { e_1 = { error: e_1_1 }; }
                finally {
                    try {
                        if (_c && !_c.done && (_a = _b.return)) _a.call(_b);
                    }
                    finally { if (e_1) throw e_1.error; }
                }
            }
            headers = headers.set('Content-Type', 'application/x-www-form-urlencoded');
            _this.http
                .post(_this.tokenEndpoint, params, { headers: headers })
                .subscribe(function (tokenResponse) {
                _this.debug('tokenResponse', tokenResponse);
                _this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in ||
                    _this.fallbackAccessTokenExpirationTimeInSec, tokenResponse.scope, _this.extractRecognizedCustomParameters(tokenResponse));
                _this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                resolve(tokenResponse);
            }, function (err) {
                _this.logger.error('Error performing password flow', err);
                _this.eventsSubject.next(new OAuthErrorEvent('token_error', err));
                reject(err);
            });
        });
    };
    /**
     * Refreshes the token using a refresh_token.
     * This does not work for implicit flow, b/c
     * there is no refresh_token in this flow.
     * A solution for this is provided by the
     * method silentRefresh.
     */
    OAuthService.prototype.refreshToken = function () {
        var _this = this;
        this.assertUrlNotNullAndCorrectProtocol(this.tokenEndpoint, 'tokenEndpoint');
        return new Promise(function (resolve, reject) {
            var e_2, _a;
            var params = new HttpParams()
                .set('grant_type', 'refresh_token')
                .set('scope', _this.scope)
                .set('refresh_token', _this._storage.getItem('refresh_token'));
            var headers = new HttpHeaders().set('Content-Type', 'application/x-www-form-urlencoded');
            if (_this.useHttpBasicAuth) {
                var header = btoa(_this.clientId + ":" + _this.dummyClientSecret);
                headers = headers.set('Authorization', 'Basic ' + header);
            }
            if (!_this.useHttpBasicAuth) {
                params = params.set('client_id', _this.clientId);
            }
            if (!_this.useHttpBasicAuth && _this.dummyClientSecret) {
                params = params.set('client_secret', _this.dummyClientSecret);
            }
            if (_this.customQueryParams) {
                try {
                    for (var _b = __values(Object.getOwnPropertyNames(_this.customQueryParams)), _c = _b.next(); !_c.done; _c = _b.next()) {
                        var key = _c.value;
                        params = params.set(key, _this.customQueryParams[key]);
                    }
                }
                catch (e_2_1) { e_2 = { error: e_2_1 }; }
                finally {
                    try {
                        if (_c && !_c.done && (_a = _b.return)) _a.call(_b);
                    }
                    finally { if (e_2) throw e_2.error; }
                }
            }
            _this.http
                .post(_this.tokenEndpoint, params, { headers: headers })
                .pipe(switchMap(function (tokenResponse) {
                if (tokenResponse.id_token) {
                    return from(_this.processIdToken(tokenResponse.id_token, tokenResponse.access_token, true)).pipe(tap(function (result) { return _this.storeIdToken(result); }), map(function (_) { return tokenResponse; }));
                }
                else {
                    return of(tokenResponse);
                }
            }))
                .subscribe(function (tokenResponse) {
                _this.debug('refresh tokenResponse', tokenResponse);
                _this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in ||
                    _this.fallbackAccessTokenExpirationTimeInSec, tokenResponse.scope, _this.extractRecognizedCustomParameters(tokenResponse));
                _this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                _this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                resolve(tokenResponse);
            }, function (err) {
                _this.logger.error('Error refreshing token', err);
                _this.eventsSubject.next(new OAuthErrorEvent('token_refresh_error', err));
                reject(err);
            });
        });
    };
    OAuthService.prototype.removeSilentRefreshEventListener = function () {
        if (this.silentRefreshPostMessageEventListener) {
            window.removeEventListener('message', this.silentRefreshPostMessageEventListener);
            this.silentRefreshPostMessageEventListener = null;
        }
    };
    OAuthService.prototype.setupSilentRefreshEventListener = function () {
        var _this = this;
        this.removeSilentRefreshEventListener();
        this.silentRefreshPostMessageEventListener = function (e) {
            var message = _this.processMessageEventMessage(e);
            _this.tryLogin({
                customHashFragment: message,
                preventClearHashAfterLogin: true,
                customRedirectUri: _this.silentRefreshRedirectUri || _this.redirectUri
            }).catch(function (err) { return _this.debug('tryLogin during silent refresh failed', err); });
        };
        window.addEventListener('message', this.silentRefreshPostMessageEventListener);
    };
    /**
     * Performs a silent refresh for implicit flow.
     * Use this method to get new tokens when/before
     * the existing tokens expire.
     */
    OAuthService.prototype.silentRefresh = function (params, noPrompt) {
        var _this = this;
        if (params === void 0) { params = {}; }
        if (noPrompt === void 0) { noPrompt = true; }
        var claims = this.getIdentityClaims() || {};
        if (this.useIdTokenHintForSilentRefresh && this.hasValidIdToken()) {
            params['id_token_hint'] = this.getIdToken();
        }
        if (!this.validateUrlForHttps(this.loginUrl)) {
            throw new Error("loginUrl  must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
        }
        if (typeof document === 'undefined') {
            throw new Error('silent refresh is not supported on this platform');
        }
        var existingIframe = document.getElementById(this.silentRefreshIFrameName);
        if (existingIframe) {
            document.body.removeChild(existingIframe);
        }
        this.silentRefreshSubject = claims['sub'];
        var iframe = document.createElement('iframe');
        iframe.id = this.silentRefreshIFrameName;
        this.setupSilentRefreshEventListener();
        var redirectUri = this.silentRefreshRedirectUri || this.redirectUri;
        this.createLoginUrl(null, null, redirectUri, noPrompt, params).then(function (url) {
            iframe.setAttribute('src', url);
            if (!_this.silentRefreshShowIFrame) {
                iframe.style['display'] = 'none';
            }
            document.body.appendChild(iframe);
        });
        var errors = this.events.pipe(filter(function (e) { return e instanceof OAuthErrorEvent; }), first());
        var success = this.events.pipe(filter(function (e) { return e.type === 'token_received'; }), first());
        var timeout = of(new OAuthErrorEvent('silent_refresh_timeout', null)).pipe(delay(this.silentRefreshTimeout));
        return race([errors, success, timeout])
            .pipe(map(function (e) {
            if (e instanceof OAuthErrorEvent) {
                if (e.type === 'silent_refresh_timeout') {
                    _this.eventsSubject.next(e);
                }
                else {
                    e = new OAuthErrorEvent('silent_refresh_error', e);
                    _this.eventsSubject.next(e);
                }
                throw e;
            }
            else if (e.type === 'token_received') {
                e = new OAuthSuccessEvent('silently_refreshed');
                _this.eventsSubject.next(e);
            }
            return e;
        }))
            .toPromise();
    };
    /**
     * This method exists for backwards compatibility.
     * {@link OAuthService#initLoginFlowInPopup} handles both code
     * and implicit flows.
     */
    OAuthService.prototype.initImplicitFlowInPopup = function (options) {
        return this.initLoginFlowInPopup(options);
    };
    OAuthService.prototype.initLoginFlowInPopup = function (options) {
        var _this = this;
        options = options || {};
        return this.createLoginUrl(null, null, this.silentRefreshRedirectUri, false, {
            display: 'popup'
        }).then(function (url) {
            return new Promise(function (resolve, reject) {
                /**
                 * Error handling section
                 */
                var checkForPopupClosedInterval = 500;
                var windowRef = window.open(url, '_blank', _this.calculatePopupFeatures(options));
                var checkForPopupClosedTimer;
                var checkForPopupClosed = function () {
                    if (!windowRef || windowRef.closed) {
                        cleanup();
                        reject(new OAuthErrorEvent('popup_closed', {}));
                    }
                };
                if (!windowRef) {
                    reject(new OAuthErrorEvent('popup_blocked', {}));
                }
                else {
                    checkForPopupClosedTimer = window.setInterval(checkForPopupClosed, checkForPopupClosedInterval);
                }
                var cleanup = function () {
                    window.clearInterval(checkForPopupClosedTimer);
                    window.removeEventListener('message', listener);
                    if (windowRef !== null) {
                        windowRef.close();
                    }
                    windowRef = null;
                };
                var listener = function (e) {
                    var message = _this.processMessageEventMessage(e);
                    if (message && message !== null) {
                        _this.tryLogin({
                            customHashFragment: message,
                            preventClearHashAfterLogin: true,
                            customRedirectUri: _this.silentRefreshRedirectUri
                        }).then(function () {
                            cleanup();
                            resolve();
                        }, function (err) {
                            cleanup();
                            reject(err);
                        });
                    }
                    else {
                        console.log('false event firing');
                    }
                };
                window.addEventListener('message', listener);
            });
        });
    };
    OAuthService.prototype.calculatePopupFeatures = function (options) {
        // Specify an static height and width and calculate centered position
        var height = options.height || 470;
        var width = options.width || 500;
        var left = window.screenLeft + (window.outerWidth - width) / 2;
        var top = window.screenTop + (window.outerHeight - height) / 2;
        return "location=no,toolbar=no,width=" + width + ",height=" + height + ",top=" + top + ",left=" + left;
    };
    OAuthService.prototype.processMessageEventMessage = function (e) {
        var expectedPrefix = '#';
        if (this.silentRefreshMessagePrefix) {
            expectedPrefix += this.silentRefreshMessagePrefix;
        }
        if (!e || !e.data || typeof e.data !== 'string') {
            return;
        }
        var prefixedMessage = e.data;
        if (!prefixedMessage.startsWith(expectedPrefix)) {
            return;
        }
        return '#' + prefixedMessage.substr(expectedPrefix.length);
    };
    OAuthService.prototype.canPerformSessionCheck = function () {
        if (!this.sessionChecksEnabled) {
            return false;
        }
        if (!this.sessionCheckIFrameUrl) {
            console.warn('sessionChecksEnabled is activated but there is no sessionCheckIFrameUrl');
            return false;
        }
        var sessionState = this.getSessionState();
        if (!sessionState) {
            console.warn('sessionChecksEnabled is activated but there is no session_state');
            return false;
        }
        if (typeof document === 'undefined') {
            return false;
        }
        return true;
    };
    OAuthService.prototype.setupSessionCheckEventListener = function () {
        var _this = this;
        this.removeSessionCheckEventListener();
        this.sessionCheckEventListener = function (e) {
            var origin = e.origin.toLowerCase();
            var issuer = _this.issuer.toLowerCase();
            _this.debug('sessionCheckEventListener');
            if (!issuer.startsWith(origin)) {
                _this.debug('sessionCheckEventListener', 'wrong origin', origin, 'expected', issuer, 'event', e);
                return;
            }
            // only run in Angular zone if it is 'changed' or 'error'
            switch (e.data) {
                case 'unchanged':
                    _this.handleSessionUnchanged();
                    break;
                case 'changed':
                    _this.ngZone.run(function () {
                        _this.handleSessionChange();
                    });
                    break;
                case 'error':
                    _this.ngZone.run(function () {
                        _this.handleSessionError();
                    });
                    break;
            }
            _this.debug('got info from session check inframe', e);
        };
        // prevent Angular from refreshing the view on every message (runs in intervals)
        this.ngZone.runOutsideAngular(function () {
            window.addEventListener('message', _this.sessionCheckEventListener);
        });
    };
    OAuthService.prototype.handleSessionUnchanged = function () {
        this.debug('session check', 'session unchanged');
    };
    OAuthService.prototype.handleSessionChange = function () {
        var _this = this;
        this.eventsSubject.next(new OAuthInfoEvent('session_changed'));
        this.stopSessionCheckTimer();
        if (!this.useSilentRefresh && this.responseType === 'code') {
            this.refreshToken()
                .then(function (_) {
                _this.debug('token refresh after session change worked');
            })
                .catch(function (_) {
                _this.debug('token refresh did not work after session changed');
                _this.eventsSubject.next(new OAuthInfoEvent('session_terminated'));
                _this.logOut(true);
            });
        }
        else if (this.silentRefreshRedirectUri) {
            this.silentRefresh().catch(function (_) {
                return _this.debug('silent refresh failed after session changed');
            });
            this.waitForSilentRefreshAfterSessionChange();
        }
        else {
            this.eventsSubject.next(new OAuthInfoEvent('session_terminated'));
            this.logOut(true);
        }
    };
    OAuthService.prototype.waitForSilentRefreshAfterSessionChange = function () {
        var _this = this;
        this.events
            .pipe(filter(function (e) {
            return e.type === 'silently_refreshed' ||
                e.type === 'silent_refresh_timeout' ||
                e.type === 'silent_refresh_error';
        }), first())
            .subscribe(function (e) {
            if (e.type !== 'silently_refreshed') {
                _this.debug('silent refresh did not work after session changed');
                _this.eventsSubject.next(new OAuthInfoEvent('session_terminated'));
                _this.logOut(true);
            }
        });
    };
    OAuthService.prototype.handleSessionError = function () {
        this.stopSessionCheckTimer();
        this.eventsSubject.next(new OAuthInfoEvent('session_error'));
    };
    OAuthService.prototype.removeSessionCheckEventListener = function () {
        if (this.sessionCheckEventListener) {
            window.removeEventListener('message', this.sessionCheckEventListener);
            this.sessionCheckEventListener = null;
        }
    };
    OAuthService.prototype.initSessionCheck = function () {
        if (!this.canPerformSessionCheck()) {
            return;
        }
        var existingIframe = document.getElementById(this.sessionCheckIFrameName);
        if (existingIframe) {
            document.body.removeChild(existingIframe);
        }
        var iframe = document.createElement('iframe');
        iframe.id = this.sessionCheckIFrameName;
        this.setupSessionCheckEventListener();
        var url = this.sessionCheckIFrameUrl;
        iframe.setAttribute('src', url);
        iframe.style.display = 'none';
        document.body.appendChild(iframe);
        this.startSessionCheckTimer();
    };
    OAuthService.prototype.startSessionCheckTimer = function () {
        var _this = this;
        this.stopSessionCheckTimer();
        this.ngZone.runOutsideAngular(function () {
            _this.sessionCheckTimer = setInterval(_this.checkSession.bind(_this), _this.sessionCheckIntervall);
        });
    };
    OAuthService.prototype.stopSessionCheckTimer = function () {
        if (this.sessionCheckTimer) {
            clearInterval(this.sessionCheckTimer);
            this.sessionCheckTimer = null;
        }
    };
    OAuthService.prototype.checkSession = function () {
        var iframe = document.getElementById(this.sessionCheckIFrameName);
        if (!iframe) {
            this.logger.warn('checkSession did not find iframe', this.sessionCheckIFrameName);
        }
        var sessionState = this.getSessionState();
        if (!sessionState) {
            this.stopSessionCheckTimer();
        }
        var message = this.clientId + ' ' + sessionState;
        iframe.contentWindow.postMessage(message, this.issuer);
    };
    OAuthService.prototype.createLoginUrl = function (state, loginHint, customRedirectUri, noPrompt, params) {
        if (state === void 0) { state = ''; }
        if (loginHint === void 0) { loginHint = ''; }
        if (customRedirectUri === void 0) { customRedirectUri = ''; }
        if (noPrompt === void 0) { noPrompt = false; }
        if (params === void 0) { params = {}; }
        return __awaiter(this, void 0, void 0, function () {
            var that, redirectUri, nonce, seperationChar, scope, url, _a, challenge, verifier, _b, _c, key, _d, _e, key;
            var e_3, _f, e_4, _g;
            return __generator(this, function (_h) {
                switch (_h.label) {
                    case 0:
                        that = this;
                        if (customRedirectUri) {
                            redirectUri = customRedirectUri;
                        }
                        else {
                            redirectUri = this.redirectUri;
                        }
                        return [4 /*yield*/, this.createAndSaveNonce()];
                    case 1:
                        nonce = _h.sent();
                        if (state) {
                            state =
                                nonce + this.config.nonceStateSeparator + encodeURIComponent(state);
                        }
                        else {
                            state = nonce;
                        }
                        if (!this.requestAccessToken && !this.oidc) {
                            throw new Error('Either requestAccessToken or oidc or both must be true');
                        }
                        if (this.config.responseType) {
                            this.responseType = this.config.responseType;
                        }
                        else {
                            if (this.oidc && this.requestAccessToken) {
                                this.responseType = 'id_token token';
                            }
                            else if (this.oidc && !this.requestAccessToken) {
                                this.responseType = 'id_token';
                            }
                            else {
                                this.responseType = 'token';
                            }
                        }
                        seperationChar = that.loginUrl.indexOf('?') > -1 ? '&' : '?';
                        scope = that.scope;
                        if (this.oidc && !scope.match(/(^|\s)openid($|\s)/)) {
                            scope = 'openid ' + scope;
                        }
                        url = that.loginUrl +
                            seperationChar +
                            'response_type=' +
                            encodeURIComponent(that.responseType) +
                            '&client_id=' +
                            encodeURIComponent(that.clientId) +
                            '&state=' +
                            encodeURIComponent(state) +
                            '&redirect_uri=' +
                            encodeURIComponent(redirectUri) +
                            '&scope=' +
                            encodeURIComponent(scope);
                        if (!(this.responseType === 'code' && !this.disablePKCE)) return [3 /*break*/, 3];
                        return [4 /*yield*/, this.createChallangeVerifierPairForPKCE()];
                    case 2:
                        _a = __read.apply(void 0, [_h.sent(), 2]), challenge = _a[0], verifier = _a[1];
                        if (this.saveNoncesInLocalStorage &&
                            typeof window['localStorage'] !== 'undefined') {
                            localStorage.setItem('PKCI_verifier', verifier);
                        }
                        else {
                            this._storage.setItem('PKCI_verifier', verifier);
                        }
                        url += '&code_challenge=' + challenge;
                        url += '&code_challenge_method=S256';
                        _h.label = 3;
                    case 3:
                        if (loginHint) {
                            url += '&login_hint=' + encodeURIComponent(loginHint);
                        }
                        if (that.resource) {
                            url += '&resource=' + encodeURIComponent(that.resource);
                        }
                        if (that.oidc) {
                            url += '&nonce=' + encodeURIComponent(nonce);
                        }
                        if (noPrompt) {
                            url += '&prompt=none';
                        }
                        try {
                            for (_b = __values(Object.keys(params)), _c = _b.next(); !_c.done; _c = _b.next()) {
                                key = _c.value;
                                url +=
                                    '&' + encodeURIComponent(key) + '=' + encodeURIComponent(params[key]);
                            }
                        }
                        catch (e_3_1) { e_3 = { error: e_3_1 }; }
                        finally {
                            try {
                                if (_c && !_c.done && (_f = _b.return)) _f.call(_b);
                            }
                            finally { if (e_3) throw e_3.error; }
                        }
                        if (this.customQueryParams) {
                            try {
                                for (_d = __values(Object.getOwnPropertyNames(this.customQueryParams)), _e = _d.next(); !_e.done; _e = _d.next()) {
                                    key = _e.value;
                                    url +=
                                        '&' + key + '=' + encodeURIComponent(this.customQueryParams[key]);
                                }
                            }
                            catch (e_4_1) { e_4 = { error: e_4_1 }; }
                            finally {
                                try {
                                    if (_e && !_e.done && (_g = _d.return)) _g.call(_d);
                                }
                                finally { if (e_4) throw e_4.error; }
                            }
                        }
                        return [2 /*return*/, url];
                }
            });
        });
    };
    OAuthService.prototype.initImplicitFlowInternal = function (additionalState, params) {
        var _this = this;
        if (additionalState === void 0) { additionalState = ''; }
        if (params === void 0) { params = ''; }
        if (this.inImplicitFlow) {
            return;
        }
        this.inImplicitFlow = true;
        if (!this.validateUrlForHttps(this.loginUrl)) {
            throw new Error("loginUrl  must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
        }
        var addParams = {};
        var loginHint = null;
        if (typeof params === 'string') {
            loginHint = params;
        }
        else if (typeof params === 'object') {
            addParams = params;
        }
        this.createLoginUrl(additionalState, loginHint, null, false, addParams)
            .then(this.config.openUri)
            .catch(function (error) {
            console.error('Error in initImplicitFlow', error);
            _this.inImplicitFlow = false;
        });
    };
    /**
     * Starts the implicit flow and redirects to user to
     * the auth servers' login url.
     *
     * @param additionalState Optional state that is passed around.
     *  You'll find this state in the property `state` after `tryLogin` logged in the user.
     * @param params Hash with additional parameter. If it is a string, it is used for the
     *               parameter loginHint (for the sake of compatibility with former versions)
     */
    OAuthService.prototype.initImplicitFlow = function (additionalState, params) {
        var _this = this;
        if (additionalState === void 0) { additionalState = ''; }
        if (params === void 0) { params = ''; }
        if (this.loginUrl !== '') {
            this.initImplicitFlowInternal(additionalState, params);
        }
        else {
            this.events
                .pipe(filter(function (e) { return e.type === 'discovery_document_loaded'; }))
                .subscribe(function (_) { return _this.initImplicitFlowInternal(additionalState, params); });
        }
    };
    /**
     * Reset current implicit flow
     *
     * @description This method allows resetting the current implict flow in order to be initialized again.
     */
    OAuthService.prototype.resetImplicitFlow = function () {
        this.inImplicitFlow = false;
    };
    OAuthService.prototype.callOnTokenReceivedIfExists = function (options) {
        var that = this;
        if (options.onTokenReceived) {
            var tokenParams = {
                idClaims: that.getIdentityClaims(),
                idToken: that.getIdToken(),
                accessToken: that.getAccessToken(),
                state: that.state
            };
            options.onTokenReceived(tokenParams);
        }
    };
    OAuthService.prototype.storeAccessTokenResponse = function (accessToken, refreshToken, expiresIn, grantedScopes, customParameters) {
        var _this = this;
        this._storage.setItem('access_token', accessToken);
        if (grantedScopes && !Array.isArray(grantedScopes)) {
            this._storage.setItem('granted_scopes', JSON.stringify(grantedScopes.split('+')));
        }
        else if (grantedScopes && Array.isArray(grantedScopes)) {
            this._storage.setItem('granted_scopes', JSON.stringify(grantedScopes));
        }
        this._storage.setItem('access_token_stored_at', '' + Date.now());
        if (expiresIn) {
            var expiresInMilliSeconds = expiresIn * 1000;
            var now = new Date();
            var expiresAt = now.getTime() + expiresInMilliSeconds;
            this._storage.setItem('expires_at', '' + expiresAt);
        }
        if (refreshToken) {
            this._storage.setItem('refresh_token', refreshToken);
        }
        if (customParameters) {
            customParameters.forEach(function (value, key) {
                _this._storage.setItem(key, value);
            });
        }
    };
    /**
     * Delegates to tryLoginImplicitFlow for the sake of competability
     * @param options Optional options.
     */
    OAuthService.prototype.tryLogin = function (options) {
        if (options === void 0) { options = null; }
        if (this.config.responseType === 'code') {
            return this.tryLoginCodeFlow(options).then(function (_) { return true; });
        }
        else {
            return this.tryLoginImplicitFlow(options);
        }
    };
    OAuthService.prototype.parseQueryString = function (queryString) {
        if (!queryString || queryString.length === 0) {
            return {};
        }
        if (queryString.charAt(0) === '?') {
            queryString = queryString.substr(1);
        }
        return this.urlHelper.parseQueryString(queryString);
    };
    OAuthService.prototype.tryLoginCodeFlow = function (options) {
        if (options === void 0) { options = null; }
        options = options || {};
        var querySource = options.customHashFragment
            ? options.customHashFragment.substring(1)
            : window.location.search;
        var parts = this.getCodePartsFromUrl(querySource);
        var code = parts['code'];
        var state = parts['state'];
        var sessionState = parts['session_state'];
        if (!options.preventClearHashAfterLogin) {
            var href = location.href
                .replace(/[&\?]code=[^&\$]*/, '')
                .replace(/[&\?]scope=[^&\$]*/, '')
                .replace(/[&\?]state=[^&\$]*/, '')
                .replace(/[&\?]session_state=[^&\$]*/, '');
            history.replaceState(null, window.name, href);
        }
        var _a = __read(this.parseState(state), 2), nonceInState = _a[0], userState = _a[1];
        this.state = userState;
        if (parts['error']) {
            this.debug('error trying to login');
            this.handleLoginError({}, parts);
            var err = new OAuthErrorEvent('code_error', {}, parts);
            this.eventsSubject.next(err);
            return Promise.reject(err);
        }
        nonceInState = sessionStorage.getItem('nonce');
        if (!nonceInState) {
            return Promise.resolve();
        }
        var success = this.validateNonce(nonceInState);
        if (!success) {
            var event_1 = new OAuthErrorEvent('invalid_nonce_in_state', null);
            this.eventsSubject.next(event_1);
            return Promise.reject(event_1);
        }
        this.storeSessionState(sessionState);
        if (code) {
            return this.getTokenFromCode(code, options).then(function (_) { return null; });
        }
        else {
            return Promise.resolve();
        }
    };
    /**
     * Retrieve the returned auth code from the redirect uri that has been called.
     * If required also check hash, as we could use hash location strategy.
     */
    OAuthService.prototype.getCodePartsFromUrl = function (queryString) {
        if (!queryString || queryString.length === 0) {
            return this.urlHelper.getHashFragmentParams();
        }
        // normalize query string
        if (queryString.charAt(0) === '?') {
            queryString = queryString.substr(1);
        }
        return this.urlHelper.parseQueryString(queryString);
    };
    /**
     * Get token using an intermediate code. Works for the Authorization Code flow.
     */
    OAuthService.prototype.getTokenFromCode = function (code, options) {
        var params = new HttpParams()
            .set('grant_type', 'authorization_code')
            .set('code', code)
            .set('redirect_uri', options.customRedirectUri || this.redirectUri);
        if (!this.disablePKCE) {
            var pkciVerifier = void 0;
            if (this.saveNoncesInLocalStorage &&
                typeof window['localStorage'] !== 'undefined') {
                pkciVerifier = localStorage.getItem('PKCI_verifier');
            }
            else {
                pkciVerifier = this._storage.getItem('PKCI_verifier');
            }
            if (!pkciVerifier) {
                console.warn('No PKCI verifier found in oauth storage!');
            }
            else {
                params = params.set('code_verifier', pkciVerifier);
            }
        }
        return this.fetchAndProcessToken(params);
    };
    OAuthService.prototype.fetchAndProcessToken = function (params) {
        var _this = this;
        this.assertUrlNotNullAndCorrectProtocol(this.tokenEndpoint, 'tokenEndpoint');
        var headers = new HttpHeaders().set('Content-Type', 'application/x-www-form-urlencoded');
        if (this.useHttpBasicAuth) {
            var header = btoa(this.clientId + ":" + this.dummyClientSecret);
            headers = headers.set('Authorization', 'Basic ' + header);
        }
        if (!this.useHttpBasicAuth) {
            params = params.set('client_id', this.clientId);
        }
        if (!this.useHttpBasicAuth && this.dummyClientSecret) {
            params = params.set('client_secret', this.dummyClientSecret);
        }
        return new Promise(function (resolve, reject) {
            var e_5, _a;
            if (_this.customQueryParams) {
                try {
                    for (var _b = __values(Object.getOwnPropertyNames(_this.customQueryParams)), _c = _b.next(); !_c.done; _c = _b.next()) {
                        var key = _c.value;
                        params = params.set(key, _this.customQueryParams[key]);
                    }
                }
                catch (e_5_1) { e_5 = { error: e_5_1 }; }
                finally {
                    try {
                        if (_c && !_c.done && (_a = _b.return)) _a.call(_b);
                    }
                    finally { if (e_5) throw e_5.error; }
                }
            }
            _this.http
                .post(_this.tokenEndpoint, params, { headers: headers })
                .subscribe(function (tokenResponse) {
                _this.debug('refresh tokenResponse', tokenResponse);
                _this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in ||
                    _this.fallbackAccessTokenExpirationTimeInSec, tokenResponse.scope, _this.extractRecognizedCustomParameters(tokenResponse));
                if (_this.oidc && tokenResponse.id_token) {
                    _this.processIdToken(tokenResponse.id_token, tokenResponse.access_token)
                        .then(function (result) {
                        _this.storeIdToken(result);
                        _this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                        _this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                        resolve(tokenResponse);
                    })
                        .catch(function (reason) {
                        _this.eventsSubject.next(new OAuthErrorEvent('token_validation_error', reason));
                        console.error('Error validating tokens');
                        console.error(reason);
                        reject(reason);
                    });
                }
                else {
                    _this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                    _this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                    resolve(tokenResponse);
                }
            }, function (err) {
                console.error('Error getting token', err);
                _this.eventsSubject.next(new OAuthErrorEvent('token_refresh_error', err));
                reject(err);
            });
        });
    };
    /**
     * Checks whether there are tokens in the hash fragment
     * as a result of the implicit flow. These tokens are
     * parsed, validated and used to sign the user in to the
     * current client.
     *
     * @param options Optional options.
     */
    OAuthService.prototype.tryLoginImplicitFlow = function (options) {
        var _this = this;
        if (options === void 0) { options = null; }
        options = options || {};
        var parts;
        if (options.customHashFragment) {
            parts = this.urlHelper.getHashFragmentParams(options.customHashFragment);
        }
        else {
            parts = this.urlHelper.getHashFragmentParams();
        }
        this.debug('parsed url', parts);
        var state = parts['state'];
        var _a = __read(this.parseState(state), 2), nonceInState = _a[0], userState = _a[1];
        this.state = userState;
        if (parts['error']) {
            this.debug('error trying to login');
            this.handleLoginError(options, parts);
            var err = new OAuthErrorEvent('token_error', {}, parts);
            this.eventsSubject.next(err);
            return Promise.reject(err);
        }
        var accessToken = parts['access_token'];
        var idToken = parts['id_token'];
        var sessionState = parts['session_state'];
        var grantedScopes = parts['scope'];
        if (!this.requestAccessToken && !this.oidc) {
            return Promise.reject('Either requestAccessToken or oidc (or both) must be true.');
        }
        if (this.requestAccessToken && !accessToken) {
            return Promise.resolve(false);
        }
        if (this.requestAccessToken && !options.disableOAuth2StateCheck && !state) {
            return Promise.resolve(false);
        }
        if (this.oidc && !idToken) {
            return Promise.resolve(false);
        }
        if (this.sessionChecksEnabled && !sessionState) {
            this.logger.warn('session checks (Session Status Change Notification) ' +
                'were activated in the configuration but the id_token ' +
                'does not contain a session_state claim');
        }
        if (this.requestAccessToken && !options.disableOAuth2StateCheck) {
            var success = this.validateNonce(nonceInState);
            if (!success) {
                var event_2 = new OAuthErrorEvent('invalid_nonce_in_state', null);
                this.eventsSubject.next(event_2);
                return Promise.reject(event_2);
            }
        }
        if (this.requestAccessToken) {
            this.storeAccessTokenResponse(accessToken, null, parts['expires_in'] || this.fallbackAccessTokenExpirationTimeInSec, grantedScopes);
        }
        if (!this.oidc) {
            this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
            if (this.clearHashAfterLogin && !options.preventClearHashAfterLogin) {
                location.hash = '';
            }
            this.callOnTokenReceivedIfExists(options);
            return Promise.resolve(true);
        }
        return this.processIdToken(idToken, accessToken)
            .then(function (result) {
            if (options.validationHandler) {
                return options
                    .validationHandler({
                    accessToken: accessToken,
                    idClaims: result.idTokenClaims,
                    idToken: result.idToken,
                    state: state
                })
                    .then(function (_) { return result; });
            }
            return result;
        })
            .then(function (result) {
            _this.storeIdToken(result);
            _this.storeSessionState(sessionState);
            if (_this.clearHashAfterLogin && !options.preventClearHashAfterLogin) {
                location.hash = '';
            }
            _this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
            _this.callOnTokenReceivedIfExists(options);
            _this.inImplicitFlow = false;
            return true;
        })
            .catch(function (reason) {
            _this.eventsSubject.next(new OAuthErrorEvent('token_validation_error', reason));
            _this.logger.error('Error validating tokens');
            _this.logger.error(reason);
            return Promise.reject(reason);
        });
    };
    OAuthService.prototype.parseState = function (state) {
        var nonce = state;
        var userState = '';
        if (state) {
            var idx = state.indexOf(this.config.nonceStateSeparator);
            if (idx > -1) {
                nonce = state.substr(0, idx);
                userState = state.substr(idx + this.config.nonceStateSeparator.length);
            }
        }
        return [nonce, userState];
    };
    OAuthService.prototype.validateNonce = function (nonceInState) {
        var savedNonce;
        if (this.saveNoncesInLocalStorage &&
            typeof window['localStorage'] !== 'undefined') {
            savedNonce = localStorage.getItem('nonce');
        }
        else {
            savedNonce = this._storage.getItem('nonce');
        }
        if (savedNonce !== nonceInState) {
            var err = 'Validating access_token failed, wrong state/nonce.';
            console.error(err, savedNonce, nonceInState);
            return false;
        }
        return true;
    };
    OAuthService.prototype.storeIdToken = function (idToken) {
        this._storage.setItem('id_token', idToken.idToken);
        this._storage.setItem('id_token_claims_obj', idToken.idTokenClaimsJson);
        this._storage.setItem('id_token_expires_at', '' + idToken.idTokenExpiresAt);
        this._storage.setItem('id_token_stored_at', '' + Date.now());
    };
    OAuthService.prototype.storeSessionState = function (sessionState) {
        this._storage.setItem('session_state', sessionState);
    };
    OAuthService.prototype.getSessionState = function () {
        return this._storage.getItem('session_state');
    };
    OAuthService.prototype.handleLoginError = function (options, parts) {
        if (options.onLoginError) {
            options.onLoginError(parts);
        }
        if (this.clearHashAfterLogin && !options.preventClearHashAfterLogin) {
            location.hash = '';
        }
    };
    /**
     * @ignore
     */
    OAuthService.prototype.processIdToken = function (idToken, accessToken, skipNonceCheck) {
        var _this = this;
        if (skipNonceCheck === void 0) { skipNonceCheck = false; }
        var tokenParts = idToken.split('.');
        var headerBase64 = this.padBase64(tokenParts[0]);
        var headerJson = b64DecodeUnicode(headerBase64);
        var header = JSON.parse(headerJson);
        var claimsBase64 = this.padBase64(tokenParts[1]);
        var claimsJson = b64DecodeUnicode(claimsBase64);
        var claims = JSON.parse(claimsJson);
        var savedNonce;
        if (this.saveNoncesInLocalStorage &&
            typeof window['localStorage'] !== 'undefined') {
            savedNonce = localStorage.getItem('nonce');
            localStorage.setItem('nonce', claims.jti);
        }
        else {
            savedNonce = this._storage.getItem('nonce');
            this._storage.setItem('nonce', claims.jti);
        }
        if (Array.isArray(claims.aud)) {
            if (claims.aud.every(function (v) { return v !== _this.clientId; })) {
                var err = 'Wrong audience: ' + claims.aud.join(',');
                this.logger.warn(err);
                return Promise.reject(err);
            }
        }
        else {
            if (claims.aud !== this.clientId) {
                var err = 'Wrong audience: ' + claims.aud;
                this.logger.warn(err);
                return Promise.reject(err);
            }
        }
        if (!claims.sub) {
            var err = 'No sub claim in id_token';
            this.logger.warn(err);
            return Promise.reject(err);
        }
        /* For now, we only check whether the sub against
         * silentRefreshSubject when sessionChecksEnabled is on
         * We will reconsider in a later version to do this
         * in every other case too.
         */
        if (this.sessionChecksEnabled &&
            this.silentRefreshSubject &&
            this.silentRefreshSubject !== claims['sub']) {
            var err = 'After refreshing, we got an id_token for another user (sub). ' +
                ("Expected sub: " + this.silentRefreshSubject + ", received sub: " + claims['sub']);
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!claims.iat) {
            var err = 'No iat claim in id_token';
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!this.skipIssuerCheck && claims.iss !== this.issuer) {
            var err = 'Wrong issuer: ' + claims.iss;
            this.logger.warn(err);
            return Promise.reject(err);
        }
        // at_hash is not applicable to authorization code flow
        // addressing https://github.com/manfredsteyer/angular-oauth2-oidc/issues/661
        // i.e. Based on spec the at_hash check is only true for implicit code flow on Ping Federate
        // https://www.pingidentity.com/developer/en/resources/openid-connect-developers-guide.html
        if (this.hasOwnProperty('responseType') && this.responseType === 'code') {
            this.disableAtHashCheck = true;
        }
        if (!this.disableAtHashCheck &&
            this.requestAccessToken &&
            !claims['at_hash']) {
            var err = 'An at_hash is needed!';
            this.logger.warn(err);
            return Promise.reject(err);
        }
        var now = Date.now();
        var issuedAtMSec = claims.iat * 1000;
        var expiresAtMSec = claims.exp * 1000;
        var clockSkewInMSec = (this.clockSkewInSec || 600) * 1000;
        if (issuedAtMSec - clockSkewInMSec >= now ||
            expiresAtMSec + clockSkewInMSec <= now) {
            var err = 'Token has expired';
            console.error(err);
            console.error({
                now: now,
                issuedAtMSec: issuedAtMSec,
                expiresAtMSec: expiresAtMSec
            });
            return Promise.reject(err);
        }
        var validationParams = {
            accessToken: accessToken,
            idToken: idToken,
            jwks: this.jwks,
            idTokenClaims: claims,
            idTokenHeader: header,
            loadKeys: function () { return _this.loadJwks(); }
        };
        if (this.disableAtHashCheck) {
            return this.checkSignature(validationParams).then(function (_) {
                var result = {
                    idToken: idToken,
                    idTokenClaims: claims,
                    idTokenClaimsJson: claimsJson,
                    idTokenHeader: header,
                    idTokenHeaderJson: headerJson,
                    idTokenExpiresAt: expiresAtMSec
                };
                return result;
            });
        }
        return this.checkAtHash(validationParams).then(function (atHashValid) {
            if (!_this.disableAtHashCheck && _this.requestAccessToken && !atHashValid) {
                var err = 'Wrong at_hash';
                _this.logger.warn(err);
                return Promise.reject(err);
            }
            return _this.checkSignature(validationParams).then(function (_) {
                var atHashCheckEnabled = !_this.disableAtHashCheck;
                var result = {
                    idToken: idToken,
                    idTokenClaims: claims,
                    idTokenClaimsJson: claimsJson,
                    idTokenHeader: header,
                    idTokenHeaderJson: headerJson,
                    idTokenExpiresAt: expiresAtMSec
                };
                if (atHashCheckEnabled) {
                    return _this.checkAtHash(validationParams).then(function (atHashValid) {
                        if (_this.requestAccessToken && !atHashValid) {
                            var err = 'Wrong at_hash';
                            _this.logger.warn(err);
                            return Promise.reject(err);
                        }
                        else {
                            return result;
                        }
                    });
                }
                else {
                    return result;
                }
            });
        });
    };
    /**
     * Returns the received claims about the user.
     */
    OAuthService.prototype.getIdentityClaims = function () {
        var claims = this._storage.getItem('id_token_claims_obj');
        if (!claims) {
            return null;
        }
        return JSON.parse(claims);
    };
    /**
     * Returns the granted scopes from the server.
     */
    OAuthService.prototype.getGrantedScopes = function () {
        var scopes = this._storage.getItem('granted_scopes');
        if (!scopes) {
            return null;
        }
        return JSON.parse(scopes);
    };
    /**
     * Returns the current id_token.
     */
    OAuthService.prototype.getIdToken = function () {
        return this._storage ? this._storage.getItem('id_token') : null;
    };
    OAuthService.prototype.padBase64 = function (base64data) {
        while (base64data.length % 4 !== 0) {
            base64data += '=';
        }
        return base64data;
    };
    /**
     * Returns the current access_token.
     */
    OAuthService.prototype.getAccessToken = function () {
        return this._storage ? this._storage.getItem('access_token') : null;
    };
    OAuthService.prototype.getRefreshToken = function () {
        return this._storage ? this._storage.getItem('refresh_token') : null;
    };
    /**
     * Returns the expiration date of the access_token
     * as milliseconds since 1970.
     */
    OAuthService.prototype.getAccessTokenExpiration = function () {
        if (!this._storage.getItem('expires_at')) {
            return null;
        }
        return parseInt(this._storage.getItem('expires_at'), 10);
    };
    OAuthService.prototype.getAccessTokenStoredAt = function () {
        return parseInt(this._storage.getItem('access_token_stored_at'), 10);
    };
    OAuthService.prototype.getIdTokenStoredAt = function () {
        return parseInt(this._storage.getItem('id_token_stored_at'), 10);
    };
    /**
     * Returns the expiration date of the id_token
     * as milliseconds since 1970.
     */
    OAuthService.prototype.getIdTokenExpiration = function () {
        if (!this._storage.getItem('id_token_expires_at')) {
            return null;
        }
        return parseInt(this._storage.getItem('id_token_expires_at'), 10);
    };
    /**
     * Checkes, whether there is a valid access_token.
     */
    OAuthService.prototype.hasValidAccessToken = function () {
        if (this.getAccessToken()) {
            var expiresAt = this._storage.getItem('expires_at');
            var now = new Date();
            if (expiresAt && parseInt(expiresAt, 10) < now.getTime()) {
                return false;
            }
            return true;
        }
        return false;
    };
    /**
     * Checks whether there is a valid id_token.
     */
    OAuthService.prototype.hasValidIdToken = function () {
        if (this.getIdToken()) {
            var expiresAt = this._storage.getItem('id_token_expires_at');
            var now = new Date();
            if (expiresAt && parseInt(expiresAt, 10) < now.getTime()) {
                return false;
            }
            return true;
        }
        return false;
    };
    /**
     * Retrieve a saved custom property of the TokenReponse object. Only if predefined in authconfig.
     */
    OAuthService.prototype.getCustomTokenResponseProperty = function (requestedProperty) {
        return this._storage &&
            this.config.customTokenParameters &&
            this.config.customTokenParameters.indexOf(requestedProperty) >= 0 &&
            this._storage.getItem(requestedProperty) !== null
            ? JSON.parse(this._storage.getItem(requestedProperty))
            : null;
    };
    /**
     * Returns the auth-header that can be used
     * to transmit the access_token to a service
     */
    OAuthService.prototype.authorizationHeader = function () {
        return 'Bearer ' + this.getAccessToken();
    };
    /**
     * Removes all tokens and logs the user out.
     * If a logout url is configured, the user is
     * redirected to it with optional state parameter.
     * @param noRedirectToLogoutUrl
     * @param state
     */
    OAuthService.prototype.logOut = function (noRedirectToLogoutUrl, state) {
        var _this = this;
        if (noRedirectToLogoutUrl === void 0) { noRedirectToLogoutUrl = false; }
        if (state === void 0) { state = ''; }
        var id_token = this.getIdToken();
        this._storage.removeItem('access_token');
        this._storage.removeItem('id_token');
        this._storage.removeItem('refresh_token');
        if (this.saveNoncesInLocalStorage) {
            localStorage.removeItem('nonce');
            localStorage.removeItem('PKCI_verifier');
        }
        else {
            this._storage.removeItem('nonce');
            this._storage.removeItem('PKCI_verifier');
        }
        this._storage.removeItem('expires_at');
        this._storage.removeItem('id_token_claims_obj');
        this._storage.removeItem('id_token_expires_at');
        this._storage.removeItem('id_token_stored_at');
        this._storage.removeItem('access_token_stored_at');
        this._storage.removeItem('granted_scopes');
        this._storage.removeItem('session_state');
        if (this.config.customTokenParameters) {
            this.config.customTokenParameters.forEach(function (customParam) {
                return _this._storage.removeItem(customParam);
            });
        }
        this.silentRefreshSubject = null;
        this.eventsSubject.next(new OAuthInfoEvent('logout'));
        if (!this.logoutUrl) {
            return;
        }
        if (noRedirectToLogoutUrl) {
            return;
        }
        if (!id_token && !this.postLogoutRedirectUri) {
            return;
        }
        var logoutUrl;
        if (!this.validateUrlForHttps(this.logoutUrl)) {
            throw new Error("logoutUrl  must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
        }
        // For backward compatibility
        if (this.logoutUrl.indexOf('{{') > -1) {
            logoutUrl = this.logoutUrl
                .replace(/\{\{id_token\}\}/, id_token)
                .replace(/\{\{client_id\}\}/, this.clientId);
        }
        else {
            var params = new HttpParams();
            if (id_token) {
                params = params.set('id_token_hint', id_token);
            }
            var postLogoutUrl = this.postLogoutRedirectUri || this.redirectUri;
            if (postLogoutUrl) {
                params = params.set('post_logout_redirect_uri', postLogoutUrl);
                if (state) {
                    params = params.set('state', state);
                }
            }
            logoutUrl =
                this.logoutUrl +
                    (this.logoutUrl.indexOf('?') > -1 ? '&' : '?') +
                    params.toString();
        }
        this.config.openUri(logoutUrl);
    };
    /**
     * @ignore
     */
    OAuthService.prototype.createAndSaveNonce = function () {
        var that = this;
        return this.createNonce().then(function (nonce) {
            // Use localStorage for nonce if possible
            // localStorage is the only storage who survives a
            // redirect in ALL browsers (also IE)
            // Otherwiese we'd force teams who have to support
            // IE into using localStorage for everything
            if (that.saveNoncesInLocalStorage &&
                typeof window['localStorage'] !== 'undefined') {
                localStorage.setItem('nonce', nonce);
            }
            else {
                that._storage.setItem('nonce', nonce);
            }
            return nonce;
        });
    };
    /**
     * @ignore
     */
    OAuthService.prototype.ngOnDestroy = function () {
        this.clearAccessTokenTimer();
        this.clearIdTokenTimer();
        this.removeSilentRefreshEventListener();
        var silentRefreshFrame = this.document.getElementById(this.silentRefreshIFrameName);
        if (silentRefreshFrame) {
            silentRefreshFrame.remove();
        }
        this.stopSessionCheckTimer();
        this.removeSessionCheckEventListener();
        var sessionCheckFrame = this.document.getElementById(this.sessionCheckIFrameName);
        if (sessionCheckFrame) {
            sessionCheckFrame.remove();
        }
    };
    OAuthService.prototype.createNonce = function () {
        var _this = this;
        return new Promise(function (resolve) {
            if (_this.rngUrl) {
                throw new Error('createNonce with rng-web-api has not been implemented so far');
            }
            /*
             * This alphabet is from:
             * https://tools.ietf.org/html/rfc7636#section-4.1
             *
             * [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
             */
            var unreserved = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
            var size = 45;
            var id = '';
            var crypto = typeof self === 'undefined' ? null : self.crypto || self['msCrypto'];
            if (crypto) {
                var bytes = new Uint8Array(size);
                crypto.getRandomValues(bytes);
                // Needed for IE
                if (!bytes.map) {
                    bytes.map = Array.prototype.map;
                }
                bytes = bytes.map(function (x) { return unreserved.charCodeAt(x % unreserved.length); });
                id = String.fromCharCode.apply(null, bytes);
            }
            else {
                while (0 < size--) {
                    id += unreserved[(Math.random() * unreserved.length) | 0];
                }
            }
            resolve(base64UrlEncode(id));
        });
    };
    OAuthService.prototype.checkAtHash = function (params) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                if (!this.tokenValidationHandler) {
                    this.logger.warn('No tokenValidationHandler configured. Cannot check at_hash.');
                    return [2 /*return*/, true];
                }
                return [2 /*return*/, this.tokenValidationHandler.validateAtHash(params)];
            });
        });
    };
    OAuthService.prototype.checkSignature = function (params) {
        if (!this.tokenValidationHandler) {
            this.logger.warn('No tokenValidationHandler configured. Cannot check signature.');
            return Promise.resolve(null);
        }
        return this.tokenValidationHandler.validateSignature(params);
    };
    /**
     * Start the implicit flow or the code flow,
     * depending on your configuration.
     */
    OAuthService.prototype.initLoginFlow = function (additionalState, params) {
        if (additionalState === void 0) { additionalState = ''; }
        if (params === void 0) { params = {}; }
        if (this.responseType === 'code') {
            return this.initCodeFlow(additionalState, params);
        }
        else {
            return this.initImplicitFlow(additionalState, params);
        }
    };
    /**
     * Starts the authorization code flow and redirects to user to
     * the auth servers login url.
     */
    OAuthService.prototype.initCodeFlow = function (additionalState, params) {
        var _this = this;
        if (additionalState === void 0) { additionalState = ''; }
        if (params === void 0) { params = {}; }
        if (this.loginUrl !== '') {
            this.initCodeFlowInternal(additionalState, params);
        }
        else {
            this.events
                .pipe(filter(function (e) { return e.type === 'discovery_document_loaded'; }))
                .subscribe(function (_) { return _this.initCodeFlowInternal(additionalState, params); });
        }
    };
    OAuthService.prototype.initCodeFlowInternal = function (additionalState, params) {
        if (additionalState === void 0) { additionalState = ''; }
        if (params === void 0) { params = {}; }
        if (!this.validateUrlForHttps(this.loginUrl)) {
            throw new Error("loginUrl  must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
        }
        this.createLoginUrl(additionalState, '', null, false, params)
            .then(this.config.openUri)
            .catch(function (error) {
            console.error('Error in initAuthorizationCodeFlow');
            console.error(error);
        });
    };
    OAuthService.prototype.createChallangeVerifierPairForPKCE = function () {
        return __awaiter(this, void 0, void 0, function () {
            var verifier, challengeRaw, challenge;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        if (!this.crypto) {
                            throw new Error('PKCE support for code flow needs a CryptoHander. Did you import the OAuthModule using forRoot() ?');
                        }
                        return [4 /*yield*/, this.createNonce()];
                    case 1:
                        verifier = _a.sent();
                        return [4 /*yield*/, this.crypto.calcHash(verifier, 'sha-256')];
                    case 2:
                        challengeRaw = _a.sent();
                        challenge = base64UrlEncode(challengeRaw);
                        return [2 /*return*/, [challenge, verifier]];
                }
            });
        });
    };
    OAuthService.prototype.extractRecognizedCustomParameters = function (tokenResponse) {
        var foundParameters = new Map();
        if (!this.config.customTokenParameters) {
            return foundParameters;
        }
        this.config.customTokenParameters.forEach(function (recognizedParameter) {
            if (tokenResponse[recognizedParameter]) {
                foundParameters.set(recognizedParameter, JSON.stringify(tokenResponse[recognizedParameter]));
            }
        });
        return foundParameters;
    };
    /**
     * Revokes the auth token to secure the vulnarability
     * of the token issued allowing the authorization server to clean
     * up any security credentials associated with the authorization
     */
    OAuthService.prototype.revokeTokenAndLogout = function () {
        var e_6, _a;
        var _this = this;
        var revokeEndpoint = this.revocationEndpoint;
        var accessToken = this.getAccessToken();
        var refreshToken = this.getRefreshToken();
        if (!accessToken) {
            return;
        }
        var params = new HttpParams();
        var headers = new HttpHeaders().set('Content-Type', 'application/x-www-form-urlencoded');
        if (this.useHttpBasicAuth) {
            var header = btoa(this.clientId + ":" + this.dummyClientSecret);
            headers = headers.set('Authorization', 'Basic ' + header);
        }
        if (!this.useHttpBasicAuth) {
            params = params.set('client_id', this.clientId);
        }
        if (!this.useHttpBasicAuth && this.dummyClientSecret) {
            params = params.set('client_secret', this.dummyClientSecret);
        }
        if (this.customQueryParams) {
            try {
                for (var _b = __values(Object.getOwnPropertyNames(this.customQueryParams)), _c = _b.next(); !_c.done; _c = _b.next()) {
                    var key = _c.value;
                    params = params.set(key, this.customQueryParams[key]);
                }
            }
            catch (e_6_1) { e_6 = { error: e_6_1 }; }
            finally {
                try {
                    if (_c && !_c.done && (_a = _b.return)) _a.call(_b);
                }
                finally { if (e_6) throw e_6.error; }
            }
        }
        return new Promise(function (resolve, reject) {
            var revokeAccessToken;
            var revokeRefreshToken;
            if (accessToken) {
                var revokationParams = params
                    .set('token', accessToken)
                    .set('token_type_hint', 'access_token');
                revokeAccessToken = _this.http.post(revokeEndpoint, revokationParams, { headers: headers });
            }
            else {
                revokeAccessToken = of(null);
            }
            if (refreshToken) {
                var revokationParams = params
                    .set('token', refreshToken)
                    .set('token_type_hint', 'refresh_token');
                revokeRefreshToken = _this.http.post(revokeEndpoint, revokationParams, { headers: headers });
            }
            else {
                revokeRefreshToken = of(null);
            }
            combineLatest([revokeAccessToken, revokeRefreshToken]).subscribe(function (res) {
                _this.logOut();
                resolve(res);
                _this.logger.info('Token successfully revoked');
            }, function (err) {
                _this.logger.error('Error revoking token', err);
                _this.eventsSubject.next(new OAuthErrorEvent('token_revoke_error', err));
                reject(err);
            });
        });
    };
    OAuthService.ctorParameters = function () { return [
        { type: NgZone },
        { type: HttpClient },
        { type: OAuthStorage, decorators: [{ type: Optional }] },
        { type: ValidationHandler, decorators: [{ type: Optional }] },
        { type: AuthConfig, decorators: [{ type: Optional }] },
        { type: UrlHelperService },
        { type: OAuthLogger },
        { type: HashHandler, decorators: [{ type: Optional }] },
        { type: Document, decorators: [{ type: Inject, args: [DOCUMENT,] }] }
    ]; };
    OAuthService = __decorate([
        Injectable(),
        __param(2, Optional()),
        __param(3, Optional()),
        __param(4, Optional()),
        __param(7, Optional()),
        __param(8, Inject(DOCUMENT)),
        __metadata("design:paramtypes", [NgZone,
            HttpClient,
            OAuthStorage,
            ValidationHandler,
            AuthConfig,
            UrlHelperService,
            OAuthLogger,
            HashHandler,
            Document])
    ], OAuthService);
    return OAuthService;
}(AuthConfig));
export { OAuthService };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2F1dGgtc2VydmljZS5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItb2F1dGgyLW9pZGMvIiwic291cmNlcyI6WyJvYXV0aC1zZXJ2aWNlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQSxPQUFPLEVBQUUsVUFBVSxFQUFFLE1BQU0sRUFBRSxRQUFRLEVBQUUsU0FBUyxFQUFFLE1BQU0sRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUNoRixPQUFPLEVBQUUsVUFBVSxFQUFFLFdBQVcsRUFBRSxVQUFVLEVBQUUsTUFBTSxzQkFBc0IsQ0FBQztBQUMzRSxPQUFPLEVBRUwsT0FBTyxFQUVQLEVBQUUsRUFDRixJQUFJLEVBQ0osSUFBSSxFQUNKLGFBQWEsRUFDZCxNQUFNLE1BQU0sQ0FBQztBQUNkLE9BQU8sRUFDTCxNQUFNLEVBQ04sS0FBSyxFQUNMLEtBQUssRUFDTCxHQUFHLEVBQ0gsR0FBRyxFQUNILFNBQVMsRUFDVCxZQUFZLEVBQ2IsTUFBTSxnQkFBZ0IsQ0FBQztBQUN4QixPQUFPLEVBQUUsUUFBUSxFQUFFLE1BQU0saUJBQWlCLENBQUM7QUFFM0MsT0FBTyxFQUNMLGlCQUFpQixFQUNqQixnQkFBZ0IsRUFDakIsTUFBTSx1Q0FBdUMsQ0FBQztBQUMvQyxPQUFPLEVBQUUsZ0JBQWdCLEVBQUUsTUFBTSxzQkFBc0IsQ0FBQztBQUN4RCxPQUFPLEVBRUwsY0FBYyxFQUNkLGVBQWUsRUFDZixpQkFBaUIsRUFDbEIsTUFBTSxVQUFVLENBQUM7QUFDbEIsT0FBTyxFQUNMLFdBQVcsRUFDWCxZQUFZLEVBQ1osWUFBWSxFQUNaLGFBQWEsRUFDYixnQkFBZ0IsRUFDaEIsYUFBYSxFQUNiLFFBQVEsRUFDVCxNQUFNLFNBQVMsQ0FBQztBQUNqQixPQUFPLEVBQUUsZ0JBQWdCLEVBQUUsZUFBZSxFQUFFLE1BQU0saUJBQWlCLENBQUM7QUFDcEUsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUMzQyxPQUFPLEVBQUUsdUJBQXVCLEVBQUUs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QUFVLEVBQUU7UUF3RFIsV0FBQSxRQUFRLEVBQUUsQ0FBQTtRQUNWLFdBQUEsUUFBUSxFQUFFLENBQUE7UUFDVixXQUFBLFFBQVEsRUFBRSxDQUFBO1FBR1YsV0FBQSxRQUFRLEVBQUUsQ0FBQTtRQUNWLFdBQUEsTUFBTSxDQUFDLFFBQVEsQ0FBQyxDQUFBO3lDQVJDLE1BQU07WUFDUixVQUFVO1lBQ0wsWUFBWTtZQUNHLGlCQUFpQjtZQUN2QixVQUFVO1lBQ25CLGdCQUFnQjtZQUNuQixXQUFXO1lBQ0MsV0FBVztZQUNMLFFBQVE7T0E3RG5DLFlBQVksQ0E4aEZ4QjtJQUFELG1CQUFDO0NBQUEsQUE5aEZELENBQWtDLFVBQVUsR0E4aEYzQztTQTloRlksWUFBWSIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IEluamVjdGFibGUsIE5nWm9uZSwgT3B0aW9uYWwsIE9uRGVzdHJveSwgSW5qZWN0IH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XHJcbmltcG9ydCB7IEh0dHBDbGllbnQsIEh0dHBIZWFkZXJzLCBIdHRwUGFyYW1zIH0gZnJvbSAnQGFuZ3VsYXIvY29tbW9uL2h0dHAnO1xyXG5pbXBvcnQge1xyXG4gIE9ic2VydmFibGUsXHJcbiAgU3ViamVjdCxcclxuICBTdWJzY3JpcHRpb24sXHJcbiAgb2YsXHJcbiAgcmFjZSxcclxuICBmcm9tLFxyXG4gIGNvbWJpbmVMYXRlc3RcclxufSBmcm9tICdyeGpzJztcclxuaW1wb3J0IHtcclxuICBmaWx0ZXIsXHJcbiAgZGVsYXksXHJcbiAgZmlyc3QsXHJcbiAgdGFwLFxyXG4gIG1hcCxcclxuICBzd2l0Y2hNYXAsXHJcbiAgZGVib3VuY2VUaW1lXHJcbn0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xyXG5pbXBvcnQgeyBET0NVTUVOVCB9IGZyb20gJ0Bhbmd1bGFyL2NvbW1vbic7XHJcblxyXG5pbXBvcnQge1xyXG4gIFZhbGlkYXRpb25IYW5kbGVyLFxyXG4gIFZhbGlkYXRpb25QYXJhbXNcclxufSBmcm9tICcuL3Rva2VuLXZhbGlkYXRpb24vdmFsaWRhdGlvbi1oYW5kbGVyJztcclxuaW1wb3J0IHsgVXJsSGVscGVyU2VydmljZSB9IGZyb20gJy4vdXJsLWhlbHBlci5zZXJ2aWNlJztcclxuaW1wb3J0IHtcclxuICBPQXV0aEV2ZW50LFxyXG4gIE9BdXRoSW5mb0V2ZW50LFxyXG4gIE9BdXRoRXJyb3JFdmVudCxcclxuICBPQXV0aFN1Y2Nlc3NFdmVudFxyXG59IGZyb20gJy4vZXZlbnRzJztcclxuaW1wb3J0IHtcclxuICBPQXV0aExvZ2dlcixcclxuICBPQXV0aFN0b3JhZ2UsXHJcbiAgTG9naW5PcHRpb25zLFxyXG4gIFBhcnNlZElkVG9rZW4sXHJcbiAgT2lkY0Rpc2NvdmVyeURvYyxcclxuICBUb2tlblJlc3BvbnNlLFxyXG4gIFVzZXJJbmZvXHJcbn0gZnJvbSAnLi90eXBlcyc7XHJcbmltcG9ydCB7IGI2NERlY29kZVVuaWNvZGUsIGJhc2U2NFVybEVuY29kZSB9IGZyb20gJy4vYmFzZTY0LWhlbHBlcic7XHJcbmltcG9ydCB7IEF1dGhDb25maWcgfSBmcm9tICcuL2F1dGguY29uZmlnJztcclxuaW1wb3J0IHsgV2ViSHR0cFVybEVuY29kaW5nQ29kZWMgfSBmcm9tICcuL2VuY29kZXInO1xyXG5pbXBvcnQgeyBIYXNoSGFuZGxlciB9IGZyb20gJy4vdG9rZW4tdmFsaWRhdGlvbi9oYXNoLWhhbmRsZXInO1xyXG5cclxuLyoqXHJcbiAqIFNlcnZpY2UgZm9yIGxvZ2dpbmcgaW4gYW5kIGxvZ2dpbmcgb3V0IHdpdGhcclxuICogT0lEQyBhbmQgT0F1dGgyLiBTdXBwb3J0cyBpbXBsaWNpdCBmbG93IGFuZFxyXG4gKiBwYXNzd29yZCBmbG93LlxyXG4gKi9cclxuQEluamVjdGFibGUoKVxyXG5leHBvcnQgY2xhc3MgT0F1dGhTZXJ2aWNlIGV4dGVuZHMgQXV0aENvbmZpZyBpbXBsZW1lbnRzIE9uRGVzdHJveSB7XHJcbiAgLy8gRXh0ZW5kaW5nIEF1dGhDb25maWcgaXN0IGp1c3QgZm9yIExFR0FDWSByZWFzb25zXHJcbiAgLy8gdG8gbm90IGJyZWFrIGV4aXN0aW5nIGNvZGUuXHJcblxyXG4gIC8qKlxyXG4gICAqIFRoZSBWYWxpZGF0aW9uSGFuZGxlciB1c2VkIHRvIHZhbGlkYXRlIHJlY2VpdmVkXHJcbiAgICogaWRfdG9rZW5zLlxyXG4gICAqL1xyXG4gIHB1YmxpYyB0b2tlblZhbGlkYXRpb25IYW5kbGVyOiBWYWxpZGF0aW9uSGFuZGxlcjtcclxuXHJcbiAgLyoqXHJcbiAgICogQGludGVybmFsXHJcbiAgICogRGVwcmVjYXRlZDogIHVzZSBwcm9wZXJ0eSBldmVudHMgaW5zdGVhZFxyXG4gICAqL1xyXG4gIHB1YmxpYyBkaXNjb3ZlcnlEb2N1bWVudExvYWRlZCA9IGZhbHNlO1xyXG5cclxuICAvKipcclxuICAgKiBAaW50ZXJuYWxcclxuICAgKiBEZXByZWNhdGVkOiAgdXNlIHByb3BlcnR5IGV2ZW50cyBpbnN0ZWFkXHJcbiAgICovXHJcbiAgcHVibGljIGRpc2NvdmVyeURvY3VtZW50TG9hZGVkJDogT2JzZXJ2YWJsZTxPaWRjRGlzY292ZXJ5RG9jPjtcclxuXHJcbiAgLyoqXHJcbiAgICogSW5mb3JtcyBhYm91dCBldmVudHMsIGxpa2UgdG9rZW5fcmVjZWl2ZWQgb3IgdG9rZW5fZXhwaXJlcy5cclxuICAgKiBTZWUgdGhlIHN0cmluZyBlbnVtIEV2ZW50VHlwZSBmb3IgYSBmdWxsIGxpc3Qgb2YgZXZlbnQgdHlwZXMuXHJcbiAgICovXHJcbiAgcHVibGljIGV2ZW50czogT2JzZXJ2YWJsZTxPQXV0aEV2ZW50PjtcclxuXHJcbiAgLyoqXHJcbiAgICogVGhlIHJlY2VpdmVkIChwYXNzZWQgYXJvdW5kKSBzdGF0ZSwgd2hlbiBsb2dnaW5nXHJcbiAgICogaW4gd2l0aCBpbXBsaWNpdCBmbG93LlxyXG4gICAqL1xyXG4gIHB1YmxpYyBzdGF0ZT8gPSAnJztcclxuXHJcbiAgcHJvdGVjdGVkIGV2ZW50c1N1YmplY3Q6IFN1YmplY3Q8T0F1dGhFdmVudD4gPSBuZXcgU3ViamVjdDxPQXV0aEV2ZW50PigpO1xyXG4gIHByb3RlY3RlZCBkaXNjb3ZlcnlEb2N1bWVudExvYWRlZFN1YmplY3Q6IFN1YmplY3Q8XHJcbiAgICBPaWRjRGlzY292ZXJ5RG9jXHJcbiAgPiA9IG5ldyBTdWJqZWN0PE9pZGNEaXNjb3ZlcnlEb2M+KCk7XHJcbiAgcHJvdGVjdGVkIHNpbGVudFJlZnJlc2hQb3N0TWVzc2FnZUV2ZW50TGlzdGVuZXI6IEV2ZW50TGlzdGVuZXI7XHJcbiAgcHJvdGVjdGVkIGdyYW50VHlwZXNTdXBwb3J0ZWQ6IEFycmF5PHN0cmluZz4gPSBbXTtcclxuICBwcm90ZWN0ZWQgX3N0b3JhZ2U6IE9BdXRoU3RvcmFnZTtcclxuICBwcm90ZWN0ZWQgYWNjZXNzVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uOiBTdWJzY3JpcHRpb247XHJcbiAgcHJvdGVjdGVkIGlkVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uOiBTdWJzY3JpcHRpb247XHJcbiAgcHJvdGVjdGVkIHRva2VuUmVjZWl2ZWRTdWJzY3JpcHRpb246IFN1YnNjcmlwdGlvbjtcclxuICBwcm90ZWN0ZWQgc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcjogRXZlbnRMaXN0ZW5lcjtcclxuICBwcm90ZWN0ZWQgandrc1VyaTogc3RyaW5nO1xyXG4gIHByb3RlY3RlZCBzZXNzaW9uQ2hlY2tUaW1lcjogYW55O1xyXG4gIHByb3RlY3RlZCBzaWxlbnRSZWZyZXNoU3ViamVjdDogc3RyaW5nO1xyXG4gIHByb3RlY3RlZCBpbkltcGxpY2l0RmxvdyA9IGZhbHNlO1xyXG5cclxuICBwcm90ZWN0ZWQgc2F2ZU5vbmNlc0luTG9jYWxTdG9yYWdlID0gZmFsc2U7XHJcblxyXG4gIGNvbnN0cnVjdG9yKFxyXG4gICAgcHJvdGVjdGVkIG5nWm9uZTogTmdab25lLFxyXG4gICAgcHJvdGVjdGVkIGh0dHA6IEh0dHBDbGllbnQsXHJcbiAgICBAT3B0aW9uYWwoKSBzdG9yYWdlOiBPQXV0aFN0b3JhZ2UsXHJcbiAgICBAT3B0aW9uYWwoKSB0b2tlblZhbGlkYXRpb25IYW5kbGVyOiBWYWxpZGF0aW9uSGFuZGxlcixcclxuICAgIEBPcHRpb25hbCgpIHByb3RlY3RlZCBjb25maWc6IEF1dGhDb25maWcsXHJcbiAgICBwcm90ZWN0ZWQgdXJsSGVscGVyOiBVcmxIZWxwZXJTZXJ2aWNlLFxyXG4gICAgcHJvdGVjdGVkIGxvZ2dlcjogT0F1dGhMb2dnZXIsXHJcbiAgICBAT3B0aW9uYWwoKSBwcm90ZWN0ZWQgY3J5cHRvOiBIYXNoSGFuZGxlcixcclxuICAgIEBJbmplY3QoRE9DVU1FTlQpIHByaXZhdGUgZG9jdW1lbnQ6IERvY3VtZW50XHJcbiAgKSB7XHJcbiAgICBzdXBlcigpO1xyXG5cclxuICAgIHRoaXMuZGVidWcoJ2FuZ3VsYXItb2F1dGgyLW9pZGMgdjgtYmV0YScpO1xyXG5cclxuICAgIHRoaXMuZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWQkID0gdGhpcy5kaXNjb3ZlcnlEb2N1bWVudExvYWRlZFN1YmplY3QuYXNPYnNlcnZhYmxlKCk7XHJcbiAgICB0aGlzLmV2ZW50cyA9IHRoaXMuZXZlbnRzU3ViamVjdC5hc09ic2VydmFibGUoKTtcclxuXHJcbiAgICBpZiAodG9rZW5WYWxpZGF0aW9uSGFuZGxlcikge1xyXG4gICAgICB0aGlzLnRva2VuVmFsaWRhdGlvbkhhbmRsZXIgPSB0b2tlblZhbGlkYXRpb25IYW5kbGVyO1xyXG4gICAgfVxyXG5cclxuICAgIGlmIChjb25maWcpIHtcclxuICAgICAgdGhpcy5jb25maWd1cmUoY29uZmlnKTtcclxuICAgIH1cclxuXHJcbiAgICB0cnkge1xyXG4gICAgICBpZiAoc3RvcmFnZSkge1xyXG4gICAgICAgIHRoaXMuc2V0U3RvcmFnZShzdG9yYWdlKTtcclxuICAgICAgfSBlbHNlIGlmICh0eXBlb2Ygc2Vzc2lvblN0b3JhZ2UgIT09ICd1bmRlZmluZWQnKSB7XHJcbiAgICAgICAgdGhpcy5zZXRTdG9yYWdlKHNlc3Npb25TdG9yYWdlKTtcclxuICAgICAgfVxyXG4gICAgfSBjYXRjaCAoZSkge1xyXG4gICAgICBjb25zb2xlLmVycm9yKFxyXG4gICAgICAgICdObyBPQXV0aFN0b3JhZ2UgcHJvdmlkZWQgYW5kIGNhbm5vdCBhY2Nlc3MgZGVmYXVsdCAoc2Vzc2lvblN0b3JhZ2UpLicgK1xyXG4gICAgICAgICAgJ0NvbnNpZGVyIHByb3ZpZGluZyBhIGN1c3RvbSBPQXV0aFN0b3JhZ2UgaW1wbGVtZW50YXRpb24gaW4geW91ciBtb2R1bGUuJyxcclxuICAgICAgICBlXHJcbiAgICAgICk7XHJcbiAgICB9XHJcblxyXG4gICAgLy8gaW4gSUUsIHNlc3Npb25TdG9yYWdlIGRvZXMgbm90IGFsd2F5cyBzdXJ2aXZlIGEgcmVkaXJlY3RcclxuICAgIGlmIChcclxuICAgICAgdHlwZW9mIHdpbmRvdyAhPT0gJ3VuZGVmaW5lZCcgJiZcclxuICAgICAgdHlwZW9mIHdpbmRvd1snbG9jYWxTdG9yYWdlJ10gIT09ICd1bmRlZmluZWQnXHJcbiAgICApIHtcclxuICAgICAgY29uc3QgdWEgPSB3aW5kb3c/Lm5hdmlnYXRvcj8udXNlckFnZW50O1xyXG4gICAgICBjb25zdCBtc2llID0gdWE/LmluY2x1ZGVzKCdNU0lFICcpIHx8IHVhPy5pbmNsdWRlcygnVHJpZGVudCcpO1xyXG5cclxuICAgICAgaWYgKG1zaWUpIHtcclxuICAgICAgICB0aGlzLnNhdmVOb25jZXNJbkxvY2FsU3RvcmFnZSA9IHRydWU7XHJcbiAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICB0aGlzLnNldHVwUmVmcmVzaFRpbWVyKCk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBVc2UgdGhpcyBtZXRob2QgdG8gY29uZmlndXJlIHRoZSBzZXJ2aWNlXHJcbiAgICogQHBhcmFtIGNvbmZpZyB0aGUgY29uZmlndXJhdGlvblxyXG4gICAqL1xyXG4gIHB1YmxpYyBjb25maWd1cmUoY29uZmlnOiBBdXRoQ29uZmlnKTogdm9pZCB7XHJcbiAgICAvLyBGb3IgdGhlIHNha2Ugb2YgZG93bndhcmQgY29tcGF0aWJpbGl0eSB3aXRoXHJcbiAgICAvLyBvcmlnaW5hbCBjb25maWd1cmF0aW9uIEFQSVxyXG4gICAgT2JqZWN0LmFzc2lnbih0aGlzLCBuZXcgQXV0aENvbmZpZygpLCBjb25maWcpO1xyXG5cclxuICAgIHRoaXMuY29uZmlnID0gT2JqZWN0LmFzc2lnbih7fSBhcyBBdXRoQ29uZmlnLCBuZXcgQXV0aENvbmZpZygpLCBjb25maWcpO1xyXG5cclxuICAgIGlmICh0aGlzLnNlc3Npb25DaGVja3NFbmFibGVkKSB7XHJcbiAgICAgIHRoaXMuc2V0dXBTZXNzaW9uQ2hlY2soKTtcclxuICAgIH1cclxuXHJcbiAgICB0aGlzLmNvbmZpZ0NoYW5nZWQoKTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBjb25maWdDaGFuZ2VkKCk6IHZvaWQge1xyXG4gICAgdGhpcy5zZXR1cFJlZnJlc2hUaW1lcigpO1xyXG4gIH1cclxuXHJcbiAgcHVibGljIHJlc3RhcnRTZXNzaW9uQ2hlY2tzSWZTdGlsbExvZ2dlZEluKCk6IHZvaWQge1xyXG4gICAgaWYgKHRoaXMuaGFzVmFsaWRJZFRva2VuKCkpIHtcclxuICAgICAgdGhpcy5pbml0U2Vzc2lvbkNoZWNrKCk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgcmVzdGFydFJlZnJlc2hUaW1lcklmU3RpbGxMb2dnZWRJbigpOiB2b2lkIHtcclxuICAgIHRoaXMuc2V0dXBFeHBpcmF0aW9uVGltZXJzKCk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgc2V0dXBTZXNzaW9uQ2hlY2soKTogdm9pZCB7XHJcbiAgICB0aGlzLmV2ZW50cy5waXBlKGZpbHRlcihlID0+IGUudHlwZSA9PT0gJ3Rva2VuX3JlY2VpdmVkJykpLnN1YnNjcmliZShlID0+IHtcclxuICAgICAgdGhpcy5pbml0U2Vzc2lvbkNoZWNrKCk7XHJcbiAgICB9KTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFdpbGwgc2V0dXAgdXAgc2lsZW50IHJlZnJlc2hpbmcgZm9yIHdoZW4gdGhlIHRva2VuIGlzXHJcbiAgICogYWJvdXQgdG8gZXhwaXJlLiBXaGVuIHRoZSB1c2VyIGlzIGxvZ2dlZCBvdXQgdmlhIHRoaXMubG9nT3V0IG1ldGhvZCwgdGhlXHJcbiAgICogc2lsZW50IHJlZnJlc2hpbmcgd2lsbCBwYXVzZSBhbmQgbm90IHJlZnJlc2ggdGhlIHRva2VucyB1bnRpbCB0aGUgdXNlciBpc1xyXG4gICAqIGxvZ2dlZCBiYWNrIGluIHZpYSByZWNlaXZpbmcgYSBuZXcgdG9rZW4uXHJcbiAgICogQHBhcmFtIHBhcmFtcyBBZGRpdGlvbmFsIHBhcmFtZXRlciB0byBwYXNzXHJcbiAgICogQHBhcmFtIGxpc3RlblRvIFNldHVwIGF1dG9tYXRpYyByZWZyZXNoIG9mIGEgc3BlY2lmaWMgdG9rZW4gdHlwZVxyXG4gICAqL1xyXG4gIHB1YmxpYyBzZXR1cEF1dG9tYXRpY1NpbGVudFJlZnJlc2goXHJcbiAgICBwYXJhbXM6IG9iamVjdCA9IHt9LFxyXG4gICAgbGlzdGVuVG8/OiAnYWNjZXNzX3Rva2VuJyB8ICdpZF90b2tlbicgfCAnYW55JyxcclxuICAgIG5vUHJvbXB0ID0gdHJ1ZVxyXG4gICk6IHZvaWQge1xyXG4gICAgbGV0IHNob3VsZFJ1blNpbGVudFJlZnJlc2ggPSB0cnVlO1xyXG4gICAgdGhpcy5ldmVudHNcclxuICAgICAgLnBpcGUoXHJcbiAgICAgICAgdGFwKGUgPT4ge1xyXG4gICAgICAgICAgaWYgKGUudHlwZSA9PT0gJ3Rva2VuX3JlY2VpdmVkJykge1xyXG4gICAgICAgICAgICBzaG91bGRSdW5TaWxlbnRSZWZyZXNoID0gdHJ1ZTtcclxuICAgICAgICAgIH0gZWxzZSBpZiAoZS50eXBlID09PSAnbG9nb3V0Jykge1xyXG4gICAgICAgICAgICBzaG91bGRSdW5TaWxlbnRSZWZyZXNoID0gZmFsc2U7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgfSksXHJcbiAgICAgICAgZmlsdGVyKGUgPT4gZS50eXBlID09PSAndG9rZW5fZXhwaXJlcycpLFxyXG4gICAgICAgIGRlYm91bmNlVGltZSgxMDAwKVxyXG4gICAgICApXHJcbiAgICAgIC5zdWJzY3JpYmUoZSA9PiB7XHJcbiAgICAgICAgY29uc3QgZXZlbnQgPSBlIGFzIE9BdXRoSW5mb0V2ZW50O1xyXG4gICAgICAgIGlmIChcclxuICAgICAgICAgIChsaXN0ZW5UbyA9PSBudWxsIHx8IGxpc3RlblRvID09PSAnYW55JyB8fCBldmVudC5pbmZvID09PSBsaXN0ZW5UbykgJiZcclxuICAgICAgICAgIHNob3VsZFJ1blNpbGVudFJlZnJlc2hcclxuICAgICAgICApIHtcclxuICAgICAgICAgIC8vIHRoaXMuc2lsZW50UmVmcmVzaChwYXJhbXMsIG5vUHJvbXB0KS5jYXRjaChfID0+IHtcclxuICAgICAgICAgIHRoaXMucmVmcmVzaEludGVybmFsKHBhcmFtcywgbm9Qcm9tcHQpLmNhdGNoKF8gPT4ge1xyXG4gICAgICAgICAgICB0aGlzLmRlYnVnKCdBdXRvbWF0aWMgc2lsZW50IHJlZnJlc2ggZGlkIG5vdCB3b3JrJyk7XHJcbiAgICAgICAgICB9KTtcclxuICAgICAgICB9XHJcbiAgICAgIH0pO1xyXG5cclxuICAgIHRoaXMucmVzdGFydFJlZnJlc2hUaW1lcklmU3RpbGxMb2dnZWRJbigpO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHJlZnJlc2hJbnRlcm5hbChcclxuICAgIHBhcmFtcyxcclxuICAgIG5vUHJvbXB0XHJcbiAgKTogUHJvbWlzZTxUb2tlblJlc3BvbnNlIHwgT0F1dGhFdmVudD4ge1xyXG4gICAgaWYgKCF0aGlzLnVzZVNpbGVudFJlZnJlc2ggJiYgdGhpcy5yZXNwb25zZVR5cGUgPT09ICdjb2RlJykge1xyXG4gICAgICByZXR1cm4gdGhpcy5yZWZyZXNoVG9rZW4oKTtcclxuICAgIH0gZWxzZSB7XHJcbiAgICAgIHJldHVybiB0aGlzLnNpbGVudFJlZnJlc2gocGFyYW1zLCBub1Byb21wdCk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBDb252ZW5pZW5jZSBtZXRob2QgdGhhdCBmaXJzdCBjYWxscyBgbG9hZERpc2NvdmVyeURvY3VtZW50KC4uLilgIGFuZFxyXG4gICAqIGRpcmVjdGx5IGNoYWlucyB1c2luZyB0aGUgYHRoZW4oLi4uKWAgcGFydCBvZiB0aGUgcHJvbWlzZSB0byBjYWxsXHJcbiAgICogdGhlIGB0cnlMb2dpbiguLi4pYCBtZXRob2QuXHJcbiAgICpcclxuICAgKiBAcGFyYW0gb3B0aW9ucyBMb2dpbk9wdGlvbnMgdG8gcGFzcyB0aHJvdWdoIHRvIGB0cnlMb2dpbiguLi4pYFxyXG4gICAqL1xyXG4gIHB1YmxpYyBsb2FkRGlzY292ZXJ5RG9jdW1lbnRBbmRUcnlMb2dpbihcclxuICAgIG9wdGlvbnM6IExvZ2luT3B0aW9ucyA9IG51bGxcclxuICApOiBQcm9taXNlPGJvb2xlYW4+IHtcclxuICAgIHJldHVybiB0aGlzLmxvYWREaXNjb3ZlcnlEb2N1bWVudCgpLnRoZW4oZG9jID0+IHtcclxuICAgICAgcmV0dXJuIHRoaXMudHJ5TG9naW4ob3B0aW9ucyk7XHJcbiAgICB9KTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIENvbnZlbmllbmNlIG1ldGhvZCB0aGF0IGZpcnN0IGNhbGxzIGBsb2FkRGlzY292ZXJ5RG9jdW1lbnRBbmRUcnlMb2dpbiguLi4pYFxyXG4gICAqIGFuZCBpZiB0aGVuIGNoYWlucyB0byBgaW5pdExvZ2luRmxvdygpYCwgYnV0IG9ubHkgaWYgdGhlcmUgaXMgbm8gdmFsaWRcclxuICAgKiBJZFRva2VuIG9yIG5vIHZhbGlkIEFjY2Vzc1Rva2VuLlxyXG4gICAqXHJcbiAgICogQHBhcmFtIG9wdGlvbnMgTG9naW5PcHRpb25zIHRvIHBhc3MgdGhyb3VnaCB0byBgdHJ5TG9naW4oLi4uKWBcclxuICAgKi9cclxuICBwdWJsaWMgbG9hZERpc2NvdmVyeURvY3VtZW50QW5kTG9naW4oXHJcbiAgICBvcHRpb25zOiBMb2dpbk9wdGlvbnMgJiB7IHN0YXRlPzogc3RyaW5nIH0gPSBudWxsXHJcbiAgKTogUHJvbWlzZTxib29sZWFuPiB7XHJcbiAgICBpZiAoIW9wdGlvbnMpIHtcclxuICAgICAgb3B0aW9ucyA9IHsgc3RhdGU6ICcnIH07XHJcbiAgICB9XHJcbiAgICByZXR1cm4gdGhpcy5sb2FkRGlzY292ZXJ5RG9jdW1lbnRBbmRUcnlMb2dpbihvcHRpb25zKS50aGVuKF8gPT4ge1xyXG4gICAgICBpZiAoIXRoaXMuaGFzVmFsaWRJZFRva2VuKCkgfHwgIXRoaXMuaGFzVmFsaWRBY2Nlc3NUb2tlbigpKSB7XHJcbiAgICAgICAgaWYgKHRoaXMucmVzcG9uc2VUeXBlID09PSAnY29kZScpIHtcclxuICAgICAgICAgIHRoaXMuaW5pdENvZGVGbG93KG9wdGlvbnMuc3RhdGUpO1xyXG4gICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICB0aGlzLmluaXRJbXBsaWNpdEZsb3cob3B0aW9ucy5zdGF0ZSk7XHJcbiAgICAgICAgfVxyXG4gICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgfSBlbHNlIHtcclxuICAgICAgICByZXR1cm4gdHJ1ZTtcclxuICAgICAgfVxyXG4gICAgfSk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgZGVidWcoLi4uYXJncyk6IHZvaWQge1xyXG4gICAgaWYgKHRoaXMuc2hvd0RlYnVnSW5mb3JtYXRpb24pIHtcclxuICAgICAgdGhpcy5sb2dnZXIuZGVidWcuYXBwbHkodGhpcy5sb2dnZXIsIGFyZ3MpO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KHVybDogc3RyaW5nKTogc3RyaW5nW10ge1xyXG4gICAgY29uc3QgZXJyb3JzOiBzdHJpbmdbXSA9IFtdO1xyXG4gICAgY29uc3QgaHR0cHNDaGVjayA9IHRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh1cmwpO1xyXG4gICAgY29uc3QgaXNzdWVyQ2hlY2sgPSB0aGlzLnZhbGlkYXRlVXJsQWdhaW5zdElzc3Vlcih1cmwpO1xyXG5cclxuICAgIGlmICghaHR0cHNDaGVjaykge1xyXG4gICAgICBlcnJvcnMucHVzaChcclxuICAgICAgICAnaHR0cHMgZm9yIGFsbCB1cmxzIHJlcXVpcmVkLiBBbHNvIGZvciB1cmxzIHJlY2VpdmVkIGJ5IGRpc2NvdmVyeS4nXHJcbiAgICAgICk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKCFpc3N1ZXJDaGVjaykge1xyXG4gICAgICBlcnJvcnMucHVzaChcclxuICAgICAgICAnRXZlcnkgdXJsIGluIGRpc2NvdmVyeSBkb2N1bWVudCBoYXMgdG8gc3RhcnQgd2l0aCB0aGUgaXNzdWVyIHVybC4nICtcclxuICAgICAgICAgICdBbHNvIHNlZSBwcm9wZXJ0eSBzdHJpY3REaXNjb3ZlcnlEb2N1bWVudFZhbGlkYXRpb24uJ1xyXG4gICAgICApO1xyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiBlcnJvcnM7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgdmFsaWRhdGVVcmxGb3JIdHRwcyh1cmw6IHN0cmluZyk6IGJvb2xlYW4ge1xyXG4gICAgaWYgKCF1cmwpIHtcclxuICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3QgbGNVcmwgPSB1cmwudG9Mb3dlckNhc2UoKTtcclxuXHJcbiAgICBpZiAodGhpcy5yZXF1aXJlSHR0cHMgPT09IGZhbHNlKSB7XHJcbiAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgfVxyXG5cclxuICAgIGlmIChcclxuICAgICAgKGxjVXJsLm1hdGNoKC9eaHR0cDpcXC9cXC9sb2NhbGhvc3QoJHxbOlxcL10pLykgfHxcclxuICAgICAgICBsY1VybC5tYXRjaCgvXmh0dHA6XFwvXFwvbG9jYWxob3N0KCR8WzpcXC9dKS8pKSAmJlxyXG4gICAgICB0aGlzLnJlcXVpcmVIdHRwcyA9PT0gJ3JlbW90ZU9ubHknXHJcbiAgICApIHtcclxuICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIGxjVXJsLnN0YXJ0c1dpdGgoJ2h0dHBzOi8vJyk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgYXNzZXJ0VXJsTm90TnVsbEFuZENvcnJlY3RQcm90b2NvbChcclxuICAgIHVybDogc3RyaW5nIHwgdW5kZWZpbmVkLFxyXG4gICAgZGVzY3JpcHRpb246IHN0cmluZ1xyXG4gICkge1xyXG4gICAgaWYgKCF1cmwpIHtcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKGAnJHtkZXNjcmlwdGlvbn0nIHNob3VsZCBub3QgYmUgbnVsbGApO1xyXG4gICAgfVxyXG4gICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModXJsKSkge1xyXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXHJcbiAgICAgICAgYCcke2Rlc2NyaXB0aW9ufScgbXVzdCB1c2UgSFRUUFMgKHdpdGggVExTKSwgb3IgY29uZmlnIHZhbHVlIGZvciBwcm9wZXJ0eSAncmVxdWlyZUh0dHBzJyBtdXN0IGJlIHNldCB0byAnZmFsc2UnIGFuZCBhbGxvdyBIVFRQICh3aXRob3V0IFRMUykuYFxyXG4gICAgICApO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHZhbGlkYXRlVXJsQWdhaW5zdElzc3Vlcih1cmw6IHN0cmluZykge1xyXG4gICAgaWYgKCF0aGlzLnN0cmljdERpc2NvdmVyeURvY3VtZW50VmFsaWRhdGlvbikge1xyXG4gICAgICByZXR1cm4gdHJ1ZTtcclxuICAgIH1cclxuICAgIGlmICghdXJsKSB7XHJcbiAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIHVybC50b0xvd2VyQ2FzZSgpLnN0YXJ0c1dpdGgodGhpcy5pc3N1ZXIudG9Mb3dlckNhc2UoKSk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgc2V0dXBSZWZyZXNoVGltZXIoKTogdm9pZCB7XHJcbiAgICBpZiAodHlwZW9mIHdpbmRvdyA9PT0gJ3VuZGVmaW5lZCcpIHtcclxuICAgICAgdGhpcy5kZWJ1ZygndGltZXIgbm90IHN1cHBvcnRlZCBvbiB0aGlzIHBsYXR0Zm9ybScpO1xyXG4gICAgICByZXR1cm47XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHRoaXMuaGFzVmFsaWRJZFRva2VuKCkgfHwgdGhpcy5oYXNWYWxpZEFjY2Vzc1Rva2VuKCkpIHtcclxuICAgICAgdGhpcy5jbGVhckFjY2Vzc1Rva2VuVGltZXIoKTtcclxuICAgICAgdGhpcy5jbGVhcklkVG9rZW5UaW1lcigpO1xyXG4gICAgICB0aGlzLnNldHVwRXhwaXJhdGlvblRpbWVycygpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICh0aGlzLnRva2VuUmVjZWl2ZWRTdWJzY3JpcHRpb24pXHJcbiAgICAgIHRoaXMudG9rZW5SZWNlaXZlZFN1YnNjcmlwdGlvbi51bnN1YnNjcmliZSgpO1xyXG5cclxuICAgIHRoaXMudG9rZW5SZWNlaXZlZFN1YnNjcmlwdGlvbiA9IHRoaXMuZXZlbnRzXHJcbiAgICAgIC5waXBlKGZpbHRlcihlID0+IGUudHlwZSA9PT0gJ3Rva2VuX3JlY2VpdmVkJykpXHJcbiAgICAgIC5zdWJzY3JpYmUoXyA9PiB7XHJcbiAgICAgICAgdGhpcy5jbGVhckFjY2Vzc1Rva2VuVGltZXIoKTtcclxuICAgICAgICB0aGlzLmNsZWFySWRUb2tlblRpbWVyKCk7XHJcbiAgICAgICAgdGhpcy5zZXR1cEV4cGlyYXRpb25UaW1lcnMoKTtcclxuICAgICAgfSk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgc2V0dXBFeHBpcmF0aW9uVGltZXJzKCk6IHZvaWQge1xyXG4gICAgaWYgKHRoaXMuaGFzVmFsaWRBY2Nlc3NUb2tlbigpKSB7XHJcbiAgICAgIC8vdGhpcy5zZXR1cEFjY2Vzc1Rva2VuVGltZXIoKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAodGhpcy5oYXNWYWxpZElkVG9rZW4oKSkge1xyXG4gICAgICAvL3RoaXMuc2V0dXBJZFRva2VuVGltZXIoKTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBzZXR1cEFjY2Vzc1Rva2VuVGltZXIoKTogdm9pZCB7XHJcbiAgICBjb25zdCBleHBpcmF0aW9uID0gdGhpcy5nZXRBY2Nlc3NUb2tlbkV4cGlyYXRpb24oKTtcclxuICAgIGNvbnN0IHN0b3JlZEF0ID0gdGhpcy5nZXRBY2Nlc3NUb2tlblN0b3JlZEF0KCk7XHJcbiAgICBjb25zdCB0aW1lb3V0ID0gdGhpcy5jYWxjVGltZW91dChzdG9yZWRBdCwgZXhwaXJhdGlvbik7XHJcblxyXG4gICAgdGhpcy5uZ1pvbmUucnVuT3V0c2lkZUFuZ3VsYXIoKCkgPT4ge1xyXG4gICAgICB0aGlzLmFjY2Vzc1Rva2VuVGltZW91dFN1YnNjcmlwdGlvbiA9IG9mKFxyXG4gICAgICAgIG5ldyBPQXV0aEluZm9FdmVudCgndG9rZW5fZXhwaXJlcycsICdhY2Nlc3NfdG9rZW4nKVxyXG4gICAgICApXHJcbiAgICAgICAgLnBpcGUoZGVsYXkodGltZW91dCkpXHJcbiAgICAgICAgLnN1YnNjcmliZShlID0+IHtcclxuICAgICAgICAgIHRoaXMubmdab25lLnJ1bigoKSA9PiB7XHJcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGUpO1xyXG4gICAgICAgICAgfSk7XHJcbiAgICAgICAgfSk7XHJcbiAgICB9KTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBzZXR1cElkVG9rZW5UaW1lcigpOiB2b2lkIHtcclxuICAgIGNvbnN0IGV4cGlyYXRpb24gPSB0aGlzLmdldElkVG9rZW5FeHBpcmF0aW9uKCk7XHJcbiAgICBjb25zdCBzdG9yZWRBdCA9IHRoaXMuZ2V0SWRUb2tlblN0b3JlZEF0KCk7XHJcbiAgICBjb25zdCB0aW1lb3V0ID0gdGhpcy5jYWxjVGltZW91dChzdG9yZWRBdCwgZXhwaXJhdGlvbik7XHJcblxyXG4gICAgdGhpcy5uZ1pvbmUucnVuT3V0c2lkZUFuZ3VsYXIoKCkgPT4ge1xyXG4gICAgICB0aGlzLmlkVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uID0gb2YoXHJcbiAgICAgICAgbmV3IE9BdXRoSW5mb0V2ZW50KCd0b2tlbl9leHBpcmVzJywgJ2lkX3Rva2VuJylcclxuICAgICAgKVxyXG4gICAgICAgIC5waXBlKGRlbGF5KHRpbWVvdXQpKVxyXG4gICAgICAgIC5zdWJzY3JpYmUoZSA9PiB7XHJcbiAgICAgICAgICB0aGlzLm5nWm9uZS5ydW4oKCkgPT4ge1xyXG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlKTtcclxuICAgICAgICAgIH0pO1xyXG4gICAgICAgIH0pO1xyXG4gICAgfSk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBTdG9wcyB0aW1lcnMgZm9yIGF1dG9tYXRpYyByZWZyZXNoLlxyXG4gICAqIFRvIHJlc3RhcnQgaXQsIGNhbGwgc2V0dXBBdXRvbWF0aWNTaWxlbnRSZWZyZXNoIGFnYWluLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBzdG9wQXV0b21hdGljUmVmcmVzaCgpIHtcclxuICAgIHRoaXMuY2xlYXJBY2Nlc3NUb2tlblRpbWVyKCk7XHJcbiAgICB0aGlzLmNsZWFySWRUb2tlblRpbWVyKCk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgY2xlYXJBY2Nlc3NUb2tlblRpbWVyKCk6IHZvaWQge1xyXG4gICAgaWYgKHRoaXMuYWNjZXNzVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uKSB7XHJcbiAgICAgIHRoaXMuYWNjZXNzVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uLnVuc3Vic2NyaWJlKCk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgY2xlYXJJZFRva2VuVGltZXIoKTogdm9pZCB7XHJcbiAgICBpZiAodGhpcy5pZFRva2VuVGltZW91dFN1YnNjcmlwdGlvbikge1xyXG4gICAgICB0aGlzLmlkVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uLnVuc3Vic2NyaWJlKCk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgY2FsY1RpbWVvdXQoc3RvcmVkQXQ6IG51bWJlciwgZXhwaXJhdGlvbjogbnVtYmVyKTogbnVtYmVyIHtcclxuICAgIGNvbnN0IG5vdyA9IERhdGUubm93KCk7XHJcbiAgICBjb25zdCBkZWx0YSA9XHJcbiAgICAgIChleHBpcmF0aW9uIC0gc3RvcmVkQXQpICogdGhpcy50aW1lb3V0RmFjdG9yIC0gKG5vdyAtIHN0b3JlZEF0KTtcclxuICAgIHJldHVybiBNYXRoLm1heCgwLCBkZWx0YSk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBERVBSRUNBVEVELiBVc2UgYSBwcm92aWRlciBmb3IgT0F1dGhTdG9yYWdlIGluc3RlYWQ6XHJcbiAgICpcclxuICAgKiB7IHByb3ZpZGU6IE9BdXRoU3RvcmFnZSwgdXNlRmFjdG9yeTogb0F1dGhTdG9yYWdlRmFjdG9yeSB9XHJcbiAgICogZXhwb3J0IGZ1bmN0aW9uIG9BdXRoU3RvcmFnZUZhY3RvcnkoKTogT0F1dGhTdG9yYWdlIHsgcmV0dXJuIGxvY2FsU3RvcmFnZTsgfVxyXG4gICAqIFNldHMgYSBjdXN0b20gc3RvcmFnZSB1c2VkIHRvIHN0b3JlIHRoZSByZWNlaXZlZFxyXG4gICAqIHRva2VucyBvbiBjbGllbnQgc2lkZS4gQnkgZGVmYXVsdCwgdGhlIGJyb3dzZXInc1xyXG4gICAqIHNlc3Npb25TdG9yYWdlIGlzIHVzZWQuXHJcbiAgICogQGlnbm9yZVxyXG4gICAqXHJcbiAgICogQHBhcmFtIHN0b3JhZ2VcclxuICAgKi9cclxuICBwdWJsaWMgc2V0U3RvcmFnZShzdG9yYWdlOiBPQXV0aFN0b3JhZ2UpOiB2b2lkIHtcclxuICAgIHRoaXMuX3N0b3JhZ2UgPSBzdG9yYWdlO1xyXG4gICAgdGhpcy5jb25maWdDaGFuZ2VkKCk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBMb2FkcyB0aGUgZGlzY292ZXJ5IGRvY3VtZW50IHRvIGNvbmZpZ3VyZSBtb3N0XHJcbiAgICogcHJvcGVydGllcyBvZiB0aGlzIHNlcnZpY2UuIFRoZSB1cmwgb2YgdGhlIGRpc2NvdmVyeVxyXG4gICAqIGRvY3VtZW50IGlzIGluZmVyZWQgZnJvbSB0aGUgaXNzdWVyJ3MgdXJsIGFjY29yZGluZ1xyXG4gICAqIHRvIHRoZSBPcGVuSWQgQ29ubmVjdCBzcGVjLiBUbyB1c2UgYW5vdGhlciB1cmwgeW91XHJcbiAgICogY2FuIHBhc3MgaXQgdG8gdG8gb3B0aW9uYWwgcGFyYW1ldGVyIGZ1bGxVcmwuXHJcbiAgICpcclxuICAgKiBAcGFyYW0gZnVsbFVybFxyXG4gICAqL1xyXG4gIHB1YmxpYyBsb2FkRGlzY292ZXJ5RG9jdW1lbnQoXHJcbiAgICBmdWxsVXJsOiBzdHJpbmcgPSBudWxsXHJcbiAgKTogUHJvbWlzZTxPQXV0aFN1Y2Nlc3NFdmVudD4ge1xyXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcclxuICAgICAgaWYgKCFmdWxsVXJsKSB7XHJcbiAgICAgICAgZnVsbFVybCA9IHRoaXMuaXNzdWVyIHx8ICcnO1xyXG4gICAgICAgIGlmICghZnVsbFVybC5lbmRzV2l0aCgnLycpKSB7XHJcbiAgICAgICAgICBmdWxsVXJsICs9ICcvJztcclxuICAgICAgICB9XHJcbiAgICAgICAgZnVsbFVybCArPSAnLndlbGwta25vd24vb3BlbmlkLWNvbmZpZ3VyYXRpb24nO1xyXG4gICAgICB9XHJcblxyXG4gICAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyhmdWxsVXJsKSkge1xyXG4gICAgICAgIHJlamVjdChcclxuICAgICAgICAgIFwiaXNzdWVyICBtdXN0IHVzZSBIVFRQUyAod2l0aCBUTFMpLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5ICdyZXF1aXJlSHR0cHMnIG11c3QgYmUgc2V0IHRvICdmYWxzZScgYW5kIGFsbG93IEhUVFAgKHdpdGhvdXQgVExTKS5cIlxyXG4gICAgICAgICk7XHJcbiAgICAgICAgcmV0dXJuO1xyXG4gICAgICB9XHJcblxyXG4gICAgICB0aGlzLmh0dHAuZ2V0PE9pZGNEaXNjb3ZlcnlEb2M+KGZ1bGxVcmwpLnN1YnNjcmliZShcclxuICAgICAgICBkb2MgPT4ge1xyXG4gICAgICAgICAgaWYgKCF0aGlzLnZhbGlkYXRlRGlzY292ZXJ5RG9jdW1lbnQoZG9jKSkge1xyXG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcclxuICAgICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCdkaXNjb3ZlcnlfZG9jdW1lbnRfdmFsaWRhdGlvbl9lcnJvcicsIG51bGwpXHJcbiAgICAgICAgICAgICk7XHJcbiAgICAgICAgICAgIHJlamVjdCgnZGlzY292ZXJ5X2RvY3VtZW50X3ZhbGlkYXRpb25fZXJyb3InKTtcclxuICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgfVxyXG5cclxuICAgICAgICAgIHRoaXMubG9naW5VcmwgPSBkb2MuYXV0aG9yaXphdGlvbl9lbmRwb2ludDtcclxuICAgICAgICAgIHRoaXMubG9nb3V0VXJsID0gZG9jLmVuZF9zZXNzaW9uX2VuZHBvaW50IHx8IHRoaXMubG9nb3V0VXJsO1xyXG4gICAgICAgICAgdGhpcy5ncmFudFR5cGVzU3VwcG9ydGVkID0gZG9jLmdyYW50X3R5cGVzX3N1cHBvcnRlZDtcclxuICAgICAgICAgIHRoaXMuaXNzdWVyID0gZG9jLmlzc3VlcjtcclxuICAgICAgICAgIHRoaXMudG9rZW5FbmRwb2ludCA9IGRvYy50b2tlbl9lbmRwb2ludDtcclxuICAgICAgICAgIHRoaXMudXNlcmluZm9FbmRwb2ludCA9XHJcbiAgICAgICAgICAgIGRvYy51c2VyaW5mb19lbmRwb2ludCB8fCB0aGlzLnVzZXJpbmZvRW5kcG9pbnQ7XHJcbiAgICAgICAgICB0aGlzLmp3a3NVcmkgPSBkb2Muandrc191cmk7XHJcbiAgICAgICAgICB0aGlzLnNlc3Npb25DaGVja0lGcmFtZVVybCA9XHJcbiAgICAgICAgICAgIGRvYy5jaGVja19zZXNzaW9uX2lmcmFtZSB8fCB0aGlzLnNlc3Npb25DaGVja0lGcmFtZVVybDtcclxuXHJcbiAgICAgICAgICB0aGlzLmRpc2NvdmVyeURvY3VtZW50TG9hZGVkID0gdHJ1ZTtcclxuICAgICAgICAgIHRoaXMuZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWRTdWJqZWN0Lm5leHQoZG9jKTtcclxuICAgICAgICAgIHRoaXMucmV2b2NhdGlvbkVuZHBvaW50ID0gZG9jLnJldm9jYXRpb25fZW5kcG9pbnQ7XHJcblxyXG4gICAgICAgICAgaWYgKHRoaXMuc2Vzc2lvbkNoZWNrc0VuYWJsZWQpIHtcclxuICAgICAgICAgICAgdGhpcy5yZXN0YXJ0U2Vzc2lvbkNoZWNrc0lmU3RpbGxMb2dnZWRJbigpO1xyXG4gICAgICAgICAgfVxyXG5cclxuICAgICAgICAgIHRoaXMubG9hZEp3a3MoKVxyXG4gICAgICAgICAgICAudGhlbihqd2tzID0+IHtcclxuICAgICAgICAgICAgICBjb25zdCByZXN1bHQ6IG9iamVjdCA9IHtcclxuICAgICAgICAgICAgICAgIGRpc2NvdmVyeURvY3VtZW50OiBkb2MsXHJcbiAgICAgICAgICAgICAgICBqd2tzOiBqd2tzXHJcbiAgICAgICAgICAgICAgfTtcclxuXHJcbiAgICAgICAgICAgICAgY29uc3QgZXZlbnQgPSBuZXcgT0F1dGhTdWNjZXNzRXZlbnQoXHJcbiAgICAgICAgICAgICAgICAnZGlzY292ZXJ5X2RvY3VtZW50X2xvYWRlZCcsXHJcbiAgICAgICAgICAgICAgICByZXN1bHRcclxuICAgICAgICAgICAgICApO1xyXG4gICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGV2ZW50KTtcclxuICAgICAgICAgICAgICByZXNvbHZlKGV2ZW50KTtcclxuICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgIH0pXHJcbiAgICAgICAgICAgIC5jYXRjaChlcnIgPT4ge1xyXG4gICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxyXG4gICAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgnZGlzY292ZXJ5X2RvY3VtZW50X2xvYWRfZXJyb3InLCBlcnIpXHJcbiAgICAgICAgICAgICAgKTtcclxuICAgICAgICAgICAgICByZWplY3QoZXJyKTtcclxuICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgIH0pO1xyXG4gICAgICAgIH0sXHJcbiAgICAgICAgZXJyID0+IHtcclxuICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdlcnJvciBsb2FkaW5nIGRpc2NvdmVyeSBkb2N1bWVudCcsIGVycik7XHJcbiAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcclxuICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgnZGlzY292ZXJ5X2RvY3VtZW50X2xvYWRfZXJyb3InLCBlcnIpXHJcbiAgICAgICAgICApO1xyXG4gICAgICAgICAgcmVqZWN0KGVycik7XHJcbiAgICAgICAgfVxyXG4gICAgICApO1xyXG4gICAgfSk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgbG9hZEp3a3MoKTogUHJvbWlzZTxvYmplY3Q+IHtcclxuICAgIHJldHVybiBuZXcgUHJvbWlzZTxvYmplY3Q+KChyZXNvbHZlLCByZWplY3QpID0+IHtcclxuICAgICAgaWYgKHRoaXMuandrc1VyaSkge1xyXG4gICAgICAgIHRoaXMuaHR0cC5nZXQodGhpcy5qd2tzVXJpKS5zdWJzY3JpYmUoXHJcbiAgICAgICAgICBqd2tzID0+IHtcclxuICAgICAgICAgICAgdGhpcy5qd2tzID0gandrcztcclxuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXHJcbiAgICAgICAgICAgICAgbmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZGVkJylcclxuICAgICAgICAgICAgKTtcclxuICAgICAgICAgICAgcmVzb2x2ZShqd2tzKTtcclxuICAgICAgICAgIH0sXHJcbiAgICAgICAgICBlcnIgPT4ge1xyXG4gICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcignZXJyb3IgbG9hZGluZyBqd2tzJywgZXJyKTtcclxuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXHJcbiAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgnandrc19sb2FkX2Vycm9yJywgZXJyKVxyXG4gICAgICAgICAgICApO1xyXG4gICAgICAgICAgICByZWplY3QoZXJyKTtcclxuICAgICAgICAgIH1cclxuICAgICAgICApO1xyXG4gICAgICB9IGVsc2Uge1xyXG4gICAgICAgIHJlc29sdmUobnVsbCk7XHJcbiAgICAgIH1cclxuICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHZhbGlkYXRlRGlzY292ZXJ5RG9jdW1lbnQoZG9jOiBPaWRjRGlzY292ZXJ5RG9jKTogYm9vbGVhbiB7XHJcbiAgICBsZXQgZXJyb3JzOiBzdHJpbmdbXTtcclxuXHJcbiAgICBpZiAoIXRoaXMuc2tpcElzc3VlckNoZWNrICYmIGRvYy5pc3N1ZXIgIT09IHRoaXMuaXNzdWVyKSB7XHJcbiAgICAgIHRoaXMubG9nZ2VyLmVycm9yKFxyXG4gICAgICAgICdpbnZhbGlkIGlzc3VlciBpbiBkaXNjb3ZlcnkgZG9jdW1lbnQnLFxyXG4gICAgICAgICdleHBlY3RlZDogJyArIHRoaXMuaXNzdWVyLFxyXG4gICAgICAgICdjdXJyZW50OiAnICsgZG9jLmlzc3VlclxyXG4gICAgICApO1xyXG4gICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICB9XHJcblxyXG4gICAgZXJyb3JzID0gdGhpcy52YWxpZGF0ZVVybEZyb21EaXNjb3ZlcnlEb2N1bWVudChkb2MuYXV0aG9yaXphdGlvbl9lbmRwb2ludCk7XHJcbiAgICBpZiAoZXJyb3JzLmxlbmd0aCA+IDApIHtcclxuICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoXHJcbiAgICAgICAgJ2Vycm9yIHZhbGlkYXRpbmcgYXV0aG9yaXphdGlvbl9lbmRwb2ludCBpbiBkaXNjb3ZlcnkgZG9jdW1lbnQnLFxyXG4gICAgICAgIGVycm9yc1xyXG4gICAgICApO1xyXG4gICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICB9XHJcblxyXG4gICAgZXJyb3JzID0gdGhpcy52YWxpZGF0ZVVybEZyb21EaXNjb3ZlcnlEb2N1bWVudChkb2MuZW5kX3Nlc3Npb25fZW5kcG9pbnQpO1xyXG4gICAgaWYgKGVycm9ycy5sZW5ndGggPiAwKSB7XHJcbiAgICAgIHRoaXMubG9nZ2VyLmVycm9yKFxyXG4gICAgICAgICdlcnJvciB2YWxpZGF0aW5nIGVuZF9zZXNzaW9uX2VuZHBvaW50IGluIGRpc2NvdmVyeSBkb2N1bWVudCcsXHJcbiAgICAgICAgZXJyb3JzXHJcbiAgICAgICk7XHJcbiAgICAgIHJldHVybiBmYWxzZTtcclxuICAgIH1cclxuXHJcbiAgICBlcnJvcnMgPSB0aGlzLnZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KGRvYy50b2tlbl9lbmRwb2ludCk7XHJcbiAgICBpZiAoZXJyb3JzLmxlbmd0aCA+IDApIHtcclxuICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoXHJcbiAgICAgICAgJ2Vycm9yIHZhbGlkYXRpbmcgdG9rZW5fZW5kcG9pbnQgaW4gZGlzY292ZXJ5IGRvY3VtZW50JyxcclxuICAgICAgICBlcnJvcnNcclxuICAgICAgKTtcclxuICAgIH1cclxuXHJcbiAgICBlcnJvcnMgPSB0aGlzLnZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KGRvYy5yZXZvY2F0aW9uX2VuZHBvaW50KTtcclxuICAgIGlmIChlcnJvcnMubGVuZ3RoID4gMCkge1xyXG4gICAgICB0aGlzLmxvZ2dlci5lcnJvcihcclxuICAgICAgICAnZXJyb3IgdmFsaWRhdGluZyByZXZvY2F0aW9uX2VuZHBvaW50IGluIGRpc2NvdmVyeSBkb2N1bWVudCcsXHJcbiAgICAgICAgZXJyb3JzXHJcbiAgICAgICk7XHJcbiAgICB9XHJcblxyXG4gICAgZXJyb3JzID0gdGhpcy52YWxpZGF0ZVVybEZyb21EaXNjb3ZlcnlEb2N1bWVudChkb2MudXNlcmluZm9fZW5kcG9pbnQpO1xyXG4gICAgaWYgKGVycm9ycy5sZW5ndGggPiAwKSB7XHJcbiAgICAgIHRoaXMubG9nZ2VyLmVycm9yKFxyXG4gICAgICAgICdlcnJvciB2YWxpZGF0aW5nIHVzZXJpbmZvX2VuZHBvaW50IGluIGRpc2NvdmVyeSBkb2N1bWVudCcsXHJcbiAgICAgICAgZXJyb3JzXHJcbiAgICAgICk7XHJcbiAgICAgIHJldHVybiBmYWxzZTtcclxuICAgIH1cclxuXHJcbiAgICBlcnJvcnMgPSB0aGlzLnZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KGRvYy5qd2tzX3VyaSk7XHJcbiAgICBpZiAoZXJyb3JzLmxlbmd0aCA+IDApIHtcclxuICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoXHJcbiAgICAgICAgJ2Vycm9yIHZhbGlkYXRpbmcgandrc191cmkgaW4gZGlzY292ZXJ5IGRvY3VtZW50JyxcclxuICAgICAgICBlcnJvcnNcclxuICAgICAgKTtcclxuICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICh0aGlzLnNlc3Npb25DaGVja3NFbmFibGVkICYmICFkb2MuY2hlY2tfc2Vzc2lvbl9pZnJhbWUpIHtcclxuICAgICAgdGhpcy5sb2dnZXIud2FybihcclxuICAgICAgICAnc2Vzc2lvbkNoZWNrc0VuYWJsZWQgaXMgYWN0aXZhdGVkIGJ1dCBkaXNjb3ZlcnkgZG9jdW1lbnQnICtcclxuICAgICAgICAgICcgZG9lcyBub3QgY29udGFpbiBhIGNoZWNrX3Nlc3Npb25faWZyYW1lIGZpZWxkJ1xyXG4gICAgICApO1xyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiB0cnVlO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogVXNlcyBwYXNzd29yZCBmbG93IHRvIGV4Y2hhbmdlIHVzZXJOYW1lIGFuZCBwYXNzd29yZCBmb3IgYW5cclxuICAgKiBhY2Nlc3NfdG9rZW4uIEFmdGVyIHJlY2VpdmluZyB0aGUgYWNjZXNzX3Rva2VuLCB0aGlzIG1ldGhvZFxyXG4gICAqIHVzZXMgaXQgdG8gcXVlcnkgdGhlIHVzZXJpbmZvIGVuZHBvaW50IGluIG9yZGVyIHRvIGdldCBpbmZvcm1hdGlvblxyXG4gICAqIGFib3V0IHRoZSB1c2VyIGluIHF1ZXN0aW9uLlxyXG4gICAqXHJcbiAgICogV2hlbiB1c2luZyB0aGlzLCBtYWtlIHN1cmUgdGhhdCB0aGUgcHJvcGVydHkgb2lkYyBpcyBzZXQgdG8gZmFsc2UuXHJcbiAgICogT3RoZXJ3aXNlIHN0cmljdGVyIHZhbGlkYXRpb25zIHRha2UgcGxhY2UgdGhhdCBtYWtlIHRoaXMgb3BlcmF0aW9uXHJcbiAgICogZmFpbC5cclxuICAgKlxyXG4gICAqIEBwYXJhbSB1c2VyTmFtZVxyXG4gICAqIEBwYXJhbSBwYXNzd29yZFxyXG4gICAqIEBwYXJhbSBoZWFkZXJzIE9wdGlvbmFsIGFkZGl0aW9uYWwgaHR0cC1oZWFkZXJzLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBmZXRjaFRva2VuVXNpbmdQYXNzd29yZEZsb3dBbmRMb2FkVXNlclByb2ZpbGUoXHJcbiAgICB1c2VyTmFtZTogc3RyaW5nLFxyXG4gICAgcGFzc3dvcmQ6IHN0cmluZyxcclxuICAgIGhlYWRlcnM6IEh0dHBIZWFkZXJzID0gbmV3IEh0dHBIZWFkZXJzKClcclxuICApOiBQcm9taXNlPFVzZXJJbmZvPiB7XHJcbiAgICByZXR1cm4gdGhpcy5mZXRjaFRva2VuVXNpbmdQYXNzd29yZEZsb3coXHJcbiAgICAgIHVzZXJOYW1lLFxyXG4gICAgICBwYXNzd29yZCxcclxuICAgICAgaGVhZGVyc1xyXG4gICAgKS50aGVuKCgpID0+IHRoaXMubG9hZFVzZXJQcm9maWxlKCkpO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogTG9hZHMgdGhlIHVzZXIgcHJvZmlsZSBieSBhY2Nlc3NpbmcgdGhlIHVzZXIgaW5mbyBlbmRwb2ludCBkZWZpbmVkIGJ5IE9wZW5JZCBDb25uZWN0LlxyXG4gICAqXHJcbiAgICogV2hlbiB1c2luZyB0aGlzIHdpdGggT0F1dGgyIHBhc3N3b3JkIGZsb3csIG1ha2Ugc3VyZSB0aGF0IHRoZSBwcm9wZXJ0eSBvaWRjIGlzIHNldCB0byBmYWxzZS5cclxuICAgKiBPdGhlcndpc2Ugc3RyaWN0ZXIgdmFsaWRhdGlvbnMgdGFrZSBwbGFjZSB0aGF0IG1ha2UgdGhpcyBvcGVyYXRpb24gZmFpbC5cclxuICAgKi9cclxuICBwdWJsaWMgbG9hZFVzZXJQcm9maWxlKCk6IFByb21pc2U8VXNlckluZm8+IHtcclxuICAgIGlmICghdGhpcy5oYXNWYWxpZEFjY2Vzc1Rva2VuKCkpIHtcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKCdDYW4gbm90IGxvYWQgVXNlciBQcm9maWxlIHdpdGhvdXQgYWNjZXNzX3Rva2VuJyk7XHJcbiAgICB9XHJcbiAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh0aGlzLnVzZXJpbmZvRW5kcG9pbnQpKSB7XHJcbiAgICAgIHRocm93IG5ldyBFcnJvcihcclxuICAgICAgICBcInVzZXJpbmZvRW5kcG9pbnQgbXVzdCB1c2UgSFRUUFMgKHdpdGggVExTKSwgb3IgY29uZmlnIHZhbHVlIGZvciBwcm9wZXJ0eSAncmVxdWlyZUh0dHBzJyBtdXN0IGJlIHNldCB0byAnZmFsc2UnIGFuZCBhbGxvdyBIVFRQICh3aXRob3V0IFRMUykuXCJcclxuICAgICAgKTtcclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xyXG4gICAgICBjb25zdCBoZWFkZXJzID0gbmV3IEh0dHBIZWFkZXJzKCkuc2V0KFxyXG4gICAgICAgICdBdXRob3JpemF0aW9uJyxcclxuICAgICAgICAnQmVhcmVyICcgKyB0aGlzLmdldEFjY2Vzc1Rva2VuKClcclxuICAgICAgKTtcclxuXHJcbiAgICAgIHRoaXMuaHR0cFxyXG4gICAgICAgIC5nZXQ8VXNlckluZm8+KHRoaXMudXNlcmluZm9FbmRwb2ludCwgeyBoZWFkZXJzIH0pXHJcbiAgICAgICAgLnN1YnNjcmliZShcclxuICAgICAgICAgIGluZm8gPT4ge1xyXG4gICAgICAgICAgICB0aGlzLmRlYnVnKCd1c2VyaW5mbyByZWNlaXZlZCcsIGluZm8pO1xyXG5cclxuICAgICAgICAgICAgY29uc3QgZXhpc3RpbmdDbGFpbXMgPSB0aGlzLmdldElkZW50aXR5Q2xhaW1zKCkgfHwge307XHJcblxyXG4gICAgICAgICAgICBpZiAoIXRoaXMuc2tpcFN1YmplY3RDaGVjaykge1xyXG4gICAgICAgICAgICAgIGlmIChcclxuICAgICAgICAgICAgICAgIHRoaXMub2lkYyAmJlxyXG4gICAgICAgICAgICAgICAgKCFleGlzdGluZ0NsYWltc1snc3ViJ10gfHwgaW5mby5zdWIgIT09IGV4aXN0aW5nQ2xhaW1zWydzdWInXSlcclxuICAgICAgICAgICAgICApIHtcclxuICAgICAgICAgICAgICAgIGNvbnN0IGVyciA9XHJcbiAgICAgICAgICAgICAgICAgICdpZiBwcm9wZXJ0eSBvaWRjIGlzIHRydWUsIHRoZSByZWNlaXZlZCB1c2VyLWlkIChzdWIpIGhhcyB0byBiZSB0aGUgdXNlci1pZCAnICtcclxuICAgICAgICAgICAgICAgICAgJ29mIHRoZSB1c2VyIHRoYXQgaGFzIGxvZ2dlZCBpbiB3aXRoIG9pZGMuXFxuJyArXHJcbiAgICAgICAgICAgICAgICAgICdpZiB5b3UgYXJlIG5vdCB1c2luZyBvaWRjIGJ1dCBqdXN0IG9hdXRoMiBwYXNzd29yZCBmbG93IHNldCBvaWRjIHRvIGZhbHNlJztcclxuXHJcbiAgICAgICAgICAgICAgICByZWplY3QoZXJyKTtcclxuICAgICAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIGluZm8gPSBPYmplY3QuYXNzaWduKHt9LCBleGlzdGluZ0NsYWltcywgaW5mbyk7XHJcblxyXG4gICAgICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2lkX3Rva2VuX2NsYWltc19vYmonLCBKU09OLnN0cmluZ2lmeShpbmZvKSk7XHJcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxyXG4gICAgICAgICAgICAgIG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndXNlcl9wcm9maWxlX2xvYWRlZCcpXHJcbiAgICAgICAgICAgICk7XHJcbiAgICAgICAgICAgIHJlc29sdmUoaW5mbyk7XHJcbiAgICAgICAgICB9LFxyXG4gICAgICAgICAgZXJyID0+IHtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ2Vycm9yIGxvYWRpbmcgdXNlciBpbmZvJywgZXJyKTtcclxuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXHJcbiAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgndXNlcl9wcm9maWxlX2xvYWRfZXJyb3InLCBlcnIpXHJcbiAgICAgICAgICAgICk7XHJcbiAgICAgICAgICAgIHJlamVjdChlcnIpO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICk7XHJcbiAgICB9KTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFVzZXMgcGFzc3dvcmQgZmxvdyB0byBleGNoYW5nZSB1c2VyTmFtZSBhbmQgcGFzc3dvcmQgZm9yIGFuIGFjY2Vzc190b2tlbi5cclxuICAgKiBAcGFyYW0gdXNlck5hbWVcclxuICAgKiBAcGFyYW0gcGFzc3dvcmRcclxuICAgKiBAcGFyYW0gaGVhZGVycyBPcHRpb25hbCBhZGRpdGlvbmFsIGh0dHAtaGVhZGVycy5cclxuICAgKi9cclxuICBwdWJsaWMgZmV0Y2hUb2tlblVzaW5nUGFzc3dvcmRGbG93KFxyXG4gICAgdXNlck5hbWU6IHN0cmluZyxcclxuICAgIHBhc3N3b3JkOiBzdHJpbmcsXHJcbiAgICBoZWFkZXJzOiBIdHRwSGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpXHJcbiAgKTogUHJvbWlzZTxUb2tlblJlc3BvbnNlPiB7XHJcbiAgICB0aGlzLmFzc2VydFVybE5vdE51bGxBbmRDb3JyZWN0UHJvdG9jb2woXHJcbiAgICAgIHRoaXMudG9rZW5FbmRwb2ludCxcclxuICAgICAgJ3Rva2VuRW5kcG9pbnQnXHJcbiAgICApO1xyXG5cclxuICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XHJcbiAgICAgIC8qKlxyXG4gICAgICAgKiBBIGBIdHRwUGFyYW1ldGVyQ29kZWNgIHRoYXQgdXNlcyBgZW5jb2RlVVJJQ29tcG9uZW50YCBhbmQgYGRlY29kZVVSSUNvbXBvbmVudGAgdG9cclxuICAgICAgICogc2VyaWFsaXplIGFuZCBwYXJzZSBVUkwgcGFyYW1ldGVyIGtleXMgYW5kIHZhbHVlcy5cclxuICAgICAgICpcclxuICAgICAgICogQHN0YWJsZVxyXG4gICAgICAgKi9cclxuICAgICAgbGV0IHBhcmFtcyA9IG5ldyBIdHRwUGFyYW1zKHsgZW5jb2RlcjogbmV3IFdlYkh0dHBVcmxFbmNvZGluZ0NvZGVjKCkgfSlcclxuICAgICAgICAuc2V0KCdncmFudF90eXBlJywgJ3Bhc3N3b3JkJylcclxuICAgICAgICAuc2V0KCdzY29wZScsIHRoaXMuc2NvcGUpXHJcbiAgICAgICAgLnNldCgndXNlcm5hbWUnLCB1c2VyTmFtZSlcclxuICAgICAgICAuc2V0KCdwYXNzd29yZCcsIHBhc3N3b3JkKTtcclxuXHJcbiAgICAgIGlmICh0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcclxuICAgICAgICBjb25zdCBoZWFkZXIgPSBidG9hKGAke3RoaXMuY2xpZW50SWR9OiR7dGhpcy5kdW1teUNsaWVudFNlY3JldH1gKTtcclxuICAgICAgICBoZWFkZXJzID0gaGVhZGVycy5zZXQoJ0F1dGhvcml6YXRpb24nLCAnQmFzaWMgJyArIGhlYWRlcik7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIGlmICghdGhpcy51c2VIdHRwQmFzaWNBdXRoKSB7XHJcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY2xpZW50X2lkJywgdGhpcy5jbGllbnRJZCk7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIGlmICghdGhpcy51c2VIdHRwQmFzaWNBdXRoICYmIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpIHtcclxuICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdjbGllbnRfc2VjcmV0JywgdGhpcy5kdW1teUNsaWVudFNlY3JldCk7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIGlmICh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSB7XHJcbiAgICAgICAgZm9yIChjb25zdCBrZXkgb2YgT2JqZWN0LmdldE93blByb3BlcnR5TmFtZXModGhpcy5jdXN0b21RdWVyeVBhcmFtcykpIHtcclxuICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoa2V5LCB0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zW2tleV0pO1xyXG4gICAgICAgIH1cclxuICAgICAgfVxyXG5cclxuICAgICAgaGVhZGVycyA9IGhlYWRlcnMuc2V0KFxyXG4gICAgICAgICdDb250ZW50LVR5cGUnLFxyXG4gICAgICAgICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnXHJcbiAgICAgICk7XHJcblxyXG4gICAgICB0aGlzLmh0dHBcclxuICAgICAgICAucG9zdDxUb2tlblJlc3BvbnNlPih0aGlzLnRva2VuRW5kcG9pbnQsIHBhcmFtcywgeyBoZWFkZXJzIH0pXHJcbiAgICAgICAgLnN1YnNjcmliZShcclxuICAgICAgICAgIHRva2VuUmVzcG9uc2UgPT4ge1xyXG4gICAgICAgICAgICB0aGlzLmRlYnVnKCd0b2tlblJlc3BvbnNlJywgdG9rZW5SZXNwb25zZSk7XHJcbiAgICAgICAgICAgIHRoaXMuc3RvcmVBY2Nlc3NUb2tlblJlc3BvbnNlKFxyXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuYWNjZXNzX3Rva2VuLFxyXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UucmVmcmVzaF90b2tlbixcclxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmV4cGlyZXNfaW4gfHxcclxuICAgICAgICAgICAgICAgIHRoaXMuZmFsbGJhY2tBY2Nlc3NUb2tlbkV4cGlyYXRpb25UaW1lSW5TZWMsXHJcbiAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5zY29wZSxcclxuICAgICAgICAgICAgICB0aGlzLmV4dHJhY3RSZWNvZ25pemVkQ3VzdG9tUGFyYW1ldGVycyh0b2tlblJlc3BvbnNlKVxyXG4gICAgICAgICAgICApO1xyXG5cclxuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWNlaXZlZCcpKTtcclxuICAgICAgICAgICAgcmVzb2x2ZSh0b2tlblJlc3BvbnNlKTtcclxuICAgICAgICAgIH0sXHJcbiAgICAgICAgICBlcnIgPT4ge1xyXG4gICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcignRXJyb3IgcGVyZm9ybWluZyBwYXNzd29yZCBmbG93JywgZXJyKTtcclxuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoRXJyb3JFdmVudCgndG9rZW5fZXJyb3InLCBlcnIpKTtcclxuICAgICAgICAgICAgcmVqZWN0KGVycik7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgKTtcclxuICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogUmVmcmVzaGVzIHRoZSB0b2tlbiB1c2luZyBhIHJlZnJlc2hfdG9rZW4uXHJcbiAgICogVGhpcyBkb2VzIG5vdCB3b3JrIGZvciBpbXBsaWNpdCBmbG93LCBiL2NcclxuICAgKiB0aGVyZSBpcyBubyByZWZyZXNoX3Rva2VuIGluIHRoaXMgZmxvdy5cclxuICAgKiBBIHNvbHV0aW9uIGZvciB0aGlzIGlzIHByb3ZpZGVkIGJ5IHRoZVxyXG4gICAqIG1ldGhvZCBzaWxlbnRSZWZyZXNoLlxyXG4gICAqL1xyXG4gIHB1YmxpYyByZWZyZXNoVG9rZW4oKTogUHJvbWlzZTxUb2tlblJlc3BvbnNlPiB7XHJcbiAgICB0aGlzLmFzc2VydFVybE5vdE51bGxBbmRDb3JyZWN0UHJvdG9jb2woXHJcbiAgICAgIHRoaXMudG9rZW5FbmRwb2ludCxcclxuICAgICAgJ3Rva2VuRW5kcG9pbnQnXHJcbiAgICApO1xyXG5cclxuICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XHJcbiAgICAgIGxldCBwYXJhbXMgPSBuZXcgSHR0cFBhcmFtcygpXHJcbiAgICAgICAgLnNldCgnZ3JhbnRfdHlwZScsICdyZWZyZXNoX3Rva2VuJylcclxuICAgICAgICAuc2V0KCdzY29wZScsIHRoaXMuc2NvcGUpXHJcbiAgICAgICAgLnNldCgncmVmcmVzaF90b2tlbicsIHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgncmVmcmVzaF90b2tlbicpKTtcclxuXHJcbiAgICAgIGxldCBoZWFkZXJzID0gbmV3IEh0dHBIZWFkZXJzKCkuc2V0KFxyXG4gICAgICAgICdDb250ZW50LVR5cGUnLFxyXG4gICAgICAgICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnXHJcbiAgICAgICk7XHJcblxyXG4gICAgICBpZiAodGhpcy51c2VIdHRwQmFzaWNBdXRoKSB7XHJcbiAgICAgICAgY29uc3QgaGVhZGVyID0gYnRvYShgJHt0aGlzLmNsaWVudElkfToke3RoaXMuZHVtbXlDbGllbnRTZWNyZXR9YCk7XHJcbiAgICAgICAgaGVhZGVycyA9IGhlYWRlcnMuc2V0KCdBdXRob3JpemF0aW9uJywgJ0Jhc2ljICcgKyBoZWFkZXIpO1xyXG4gICAgICB9XHJcblxyXG4gICAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCkge1xyXG4gICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9pZCcsIHRoaXMuY2xpZW50SWQpO1xyXG4gICAgICB9XHJcblxyXG4gICAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCAmJiB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KSB7XHJcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY2xpZW50X3NlY3JldCcsIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpO1xyXG4gICAgICB9XHJcblxyXG4gICAgICBpZiAodGhpcy5jdXN0b21RdWVyeVBhcmFtcykge1xyXG4gICAgICAgIGZvciAoY29uc3Qga2V5IG9mIE9iamVjdC5nZXRPd25Qcm9wZXJ0eU5hbWVzKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpKSB7XHJcbiAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KGtleSwgdGhpcy5jdXN0b21RdWVyeVBhcmFtc1trZXldKTtcclxuICAgICAgICB9XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIHRoaXMuaHR0cFxyXG4gICAgICAgIC5wb3N0PFRva2VuUmVzcG9uc2U+KHRoaXMudG9rZW5FbmRwb2ludCwgcGFyYW1zLCB7IGhlYWRlcnMgfSlcclxuICAgICAgICAucGlwZShcclxuICAgICAgICAgIHN3aXRjaE1hcCh0b2tlblJlc3BvbnNlID0+IHtcclxuICAgICAgICAgICAgaWYgKHRva2VuUmVzcG9uc2UuaWRfdG9rZW4pIHtcclxuICAgICAgICAgICAgICByZXR1cm4gZnJvbShcclxuICAgICAgICAgICAgICAgIHRoaXMucHJvY2Vzc0lkVG9rZW4oXHJcbiAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuaWRfdG9rZW4sXHJcbiAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuYWNjZXNzX3Rva2VuLFxyXG4gICAgICAgICAgICAgICAgICB0cnVlXHJcbiAgICAgICAgICAgICAgICApXHJcbiAgICAgICAgICAgICAgKS5waXBlKFxyXG4gICAgICAgICAgICAgICAgdGFwKHJlc3VsdCA9PiB0aGlzLnN0b3JlSWRUb2tlbihyZXN1bHQpKSxcclxuICAgICAgICAgICAgICAgIG1hcChfID0+IHRva2VuUmVzcG9uc2UpXHJcbiAgICAgICAgICAgICAgKTtcclxuICAgICAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgICByZXR1cm4gb2YodG9rZW5SZXNwb25zZSk7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgIH0pXHJcbiAgICAgICAgKVxyXG4gICAgICAgIC5zdWJzY3JpYmUoXHJcbiAgICAgICAgICB0b2tlblJlc3BvbnNlID0+IHtcclxuICAgICAgICAgICAgdGhpcy5kZWJ1ZygncmVmcmVzaCB0b2tlblJlc3BvbnNlJywgdG9rZW5SZXNwb25zZSk7XHJcbiAgICAgICAgICAgIHRoaXMuc3RvcmVBY2Nlc3NUb2tlblJlc3BvbnNlKFxyXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuYWNjZXNzX3Rva2VuLFxyXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UucmVmcmVzaF90b2tlbixcclxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmV4cGlyZXNfaW4gfHxcclxuICAgICAgICAgICAgICAgIHRoaXMuZmFsbGJhY2tBY2Nlc3NUb2tlbkV4cGlyYXRpb25UaW1lSW5TZWMsXHJcbiAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5zY29wZSxcclxuICAgICAgICAgICAgICB0aGlzLmV4dHJhY3RSZWNvZ25pemVkQ3VzdG9tUGFyYW1ldGVycyh0b2tlblJlc3BvbnNlKVxyXG4gICAgICAgICAgICApO1xyXG5cclxuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWNlaXZlZCcpKTtcclxuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWZyZXNoZWQnKSk7XHJcbiAgICAgICAgICAgIHJlc29sdmUodG9rZW5SZXNwb25zZSk7XHJcbiAgICAgICAgICB9LFxyXG4gICAgICAgICAgZXJyID0+IHtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ0Vycm9yIHJlZnJlc2hpbmcgdG9rZW4nLCBlcnIpO1xyXG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcclxuICAgICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl9yZWZyZXNoX2Vycm9yJywgZXJyKVxyXG4gICAgICAgICAgICApO1xyXG4gICAgICAgICAgICByZWplY3QoZXJyKTtcclxuICAgICAgICAgIH1cclxuICAgICAgICApO1xyXG4gICAgfSk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgcmVtb3ZlU2lsZW50UmVmcmVzaEV2ZW50TGlzdGVuZXIoKTogdm9pZCB7XHJcbiAgICBpZiAodGhpcy5zaWxlbnRSZWZyZXNoUG9zdE1lc3NhZ2VFdmVudExpc3RlbmVyKSB7XHJcbiAgICAgIHdpbmRvdy5yZW1vdmVFdmVudExpc3RlbmVyKFxyXG4gICAgICAgICdtZXNzYWdlJyxcclxuICAgICAgICB0aGlzLnNpbGVudFJlZnJlc2hQb3N0TWVzc2FnZUV2ZW50TGlzdGVuZXJcclxuICAgICAgKTtcclxuICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoUG9zdE1lc3NhZ2VFdmVudExpc3RlbmVyID0gbnVsbDtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBzZXR1cFNpbGVudFJlZnJlc2hFdmVudExpc3RlbmVyKCk6IHZvaWQge1xyXG4gICAgdGhpcy5yZW1vdmVTaWxlbnRSZWZyZXNoRXZlbnRMaXN0ZW5lcigpO1xyXG5cclxuICAgIHRoaXMuc2lsZW50UmVmcmVzaFBvc3RNZXNzYWdlRXZlbnRMaXN0ZW5lciA9IChlOiBNZXNzYWdlRXZlbnQpID0+IHtcclxuICAgICAgY29uc3QgbWVzc2FnZSA9IHRoaXMucHJvY2Vzc01lc3NhZ2VFdmVudE1lc3NhZ2UoZSk7XHJcblxyXG4gICAgICB0aGlzLnRyeUxvZ2luKHtcclxuICAgICAgICBjdXN0b21IYXNoRnJhZ21lbnQ6IG1lc3NhZ2UsXHJcbiAgICAgICAgcHJldmVudENsZWFySGFzaEFmdGVyTG9naW46IHRydWUsXHJcbiAgICAgICAgY3VzdG9tUmVkaXJlY3RVcmk6IHRoaXMuc2lsZW50UmVmcmVzaFJlZGlyZWN0VXJpIHx8IHRoaXMucmVkaXJlY3RVcmlcclxuICAgICAgfSkuY2F0Y2goZXJyID0+IHRoaXMuZGVidWcoJ3RyeUxvZ2luIGR1cmluZyBzaWxlbnQgcmVmcmVzaCBmYWlsZWQnLCBlcnIpKTtcclxuICAgIH07XHJcblxyXG4gICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoXHJcbiAgICAgICdtZXNzYWdlJyxcclxuICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoUG9zdE1lc3NhZ2VFdmVudExpc3RlbmVyXHJcbiAgICApO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogUGVyZm9ybXMgYSBzaWxlbnQgcmVmcmVzaCBmb3IgaW1wbGljaXQgZmxvdy5cclxuICAgKiBVc2UgdGhpcyBtZXRob2QgdG8gZ2V0IG5ldyB0b2tlbnMgd2hlbi9iZWZvcmVcclxuICAgKiB0aGUgZXhpc3RpbmcgdG9rZW5zIGV4cGlyZS5cclxuICAgKi9cclxuICBwdWJsaWMgc2lsZW50UmVmcmVzaChcclxuICAgIHBhcmFtczogb2JqZWN0ID0ge30sXHJcbiAgICBub1Byb21wdCA9IHRydWVcclxuICApOiBQcm9taXNlPE9BdXRoRXZlbnQ+IHtcclxuICAgIGNvbnN0IGNsYWltczogb2JqZWN0ID0gdGhpcy5nZXRJZGVudGl0eUNsYWltcygpIHx8IHt9O1xyXG5cclxuICAgIGlmICh0aGlzLnVzZUlkVG9rZW5IaW50Rm9yU2lsZW50UmVmcmVzaCAmJiB0aGlzLmhhc1ZhbGlkSWRUb2tlbigpKSB7XHJcbiAgICAgIHBhcmFtc1snaWRfdG9rZW5faGludCddID0gdGhpcy5nZXRJZFRva2VuKCk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModGhpcy5sb2dpblVybCkpIHtcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKFxyXG4gICAgICAgIFwibG9naW5VcmwgIG11c3QgdXNlIEhUVFBTICh3aXRoIFRMUyksIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgJ3JlcXVpcmVIdHRwcycgbXVzdCBiZSBzZXQgdG8gJ2ZhbHNlJyBhbmQgYWxsb3cgSFRUUCAod2l0aG91dCBUTFMpLlwiXHJcbiAgICAgICk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHR5cGVvZiBkb2N1bWVudCA9PT0gJ3VuZGVmaW5lZCcpIHtcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKCdzaWxlbnQgcmVmcmVzaCBpcyBub3Qgc3VwcG9ydGVkIG9uIHRoaXMgcGxhdGZvcm0nKTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBleGlzdGluZ0lmcmFtZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFxyXG4gICAgICB0aGlzLnNpbGVudFJlZnJlc2hJRnJhbWVOYW1lXHJcbiAgICApO1xyXG5cclxuICAgIGlmIChleGlzdGluZ0lmcmFtZSkge1xyXG4gICAgICBkb2N1bWVudC5ib2R5LnJlbW92ZUNoaWxkKGV4aXN0aW5nSWZyYW1lKTtcclxuICAgIH1cclxuXHJcbiAgICB0aGlzLnNpbGVudFJlZnJlc2hTdWJqZWN0ID0gY2xhaW1zWydzdWInXTtcclxuXHJcbiAgICBjb25zdCBpZnJhbWUgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdpZnJhbWUnKTtcclxuICAgIGlmcmFtZS5pZCA9IHRoaXMuc2lsZW50UmVmcmVzaElGcmFtZU5hbWU7XHJcblxyXG4gICAgdGhpcy5zZXR1cFNpbGVudFJlZnJlc2hFdmVudExpc3RlbmVyKCk7XHJcblxyXG4gICAgY29uc3QgcmVkaXJlY3RVcmkgPSB0aGlzLnNpbGVudFJlZnJlc2hSZWRpcmVjdFVyaSB8fCB0aGlzLnJlZGlyZWN0VXJpO1xyXG4gICAgdGhpcy5jcmVhdGVMb2dpblVybChudWxsLCBudWxsLCByZWRpcmVjdFVyaSwgbm9Qcm9tcHQsIHBhcmFtcykudGhlbih1cmwgPT4ge1xyXG4gICAgICBpZnJhbWUuc2V0QXR0cmlidXRlKCdzcmMnLCB1cmwpO1xyXG5cclxuICAgICAgaWYgKCF0aGlzLnNpbGVudFJlZnJlc2hTaG93SUZyYW1lKSB7XHJcbiAgICAgICAgaWZyYW1lLnN0eWxlWydkaXNwbGF5J10gPSAnbm9uZSc7XHJcbiAgICAgIH1cclxuICAgICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChpZnJhbWUpO1xyXG4gICAgfSk7XHJcblxyXG4gICAgY29uc3QgZXJyb3JzID0gdGhpcy5ldmVudHMucGlwZShcclxuICAgICAgZmlsdGVyKGUgPT4gZSBpbnN0YW5jZW9mIE9BdXRoRXJyb3JFdmVudCksXHJcbiAgICAgIGZpcnN0KClcclxuICAgICk7XHJcbiAgICBjb25zdCBzdWNjZXNzID0gdGhpcy5ldmVudHMucGlwZShcclxuICAgICAgZmlsdGVyKGUgPT4gZS50eXBlID09PSAndG9rZW5fcmVjZWl2ZWQnKSxcclxuICAgICAgZmlyc3QoKVxyXG4gICAgKTtcclxuICAgIGNvbnN0IHRpbWVvdXQgPSBvZihcclxuICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgnc2lsZW50X3JlZnJlc2hfdGltZW91dCcsIG51bGwpXHJcbiAgICApLnBpcGUoZGVsYXkodGhpcy5zaWxlbnRSZWZyZXNoVGltZW91dCkpO1xyXG5cclxuICAgIHJldHVybiByYWNlKFtlcnJvcnMsIHN1Y2Nlc3MsIHRpbWVvdXRdKVxyXG4gICAgICAucGlwZShcclxuICAgICAgICBtYXAoZSA9PiB7XHJcbiAgICAgICAgICBpZiAoZSBpbnN0YW5jZW9mIE9BdXRoRXJyb3JFdmVudCkge1xyXG4gICAgICAgICAgICBpZiAoZS50eXBlID09PSAnc2lsZW50X3JlZnJlc2hfdGltZW91dCcpIHtcclxuICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlKTtcclxuICAgICAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgICBlID0gbmV3IE9BdXRoRXJyb3JFdmVudCgnc2lsZW50X3JlZnJlc2hfZXJyb3InLCBlKTtcclxuICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICB0aHJvdyBlO1xyXG4gICAgICAgICAgfSBlbHNlIGlmIChlLnR5cGUgPT09ICd0b2tlbl9yZWNlaXZlZCcpIHtcclxuICAgICAgICAgICAgZSA9IG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgnc2lsZW50bHlfcmVmcmVzaGVkJyk7XHJcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGUpO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgcmV0dXJuIGU7XHJcbiAgICAgICAgfSlcclxuICAgICAgKVxyXG4gICAgICAudG9Qcm9taXNlKCk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBUaGlzIG1ldGhvZCBleGlzdHMgZm9yIGJhY2t3YXJkcyBjb21wYXRpYmlsaXR5LlxyXG4gICAqIHtAbGluayBPQXV0aFNlcnZpY2UjaW5pdExvZ2luRmxvd0luUG9wdXB9IGhhbmRsZXMgYm90aCBjb2RlXHJcbiAgICogYW5kIGltcGxpY2l0IGZsb3dzLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBpbml0SW1wbGljaXRGbG93SW5Qb3B1cChvcHRpb25zPzoge1xyXG4gICAgaGVpZ2h0PzogbnVtYmVyO1xyXG4gICAgd2lkdGg/OiBudW1iZXI7XHJcbiAgfSkge1xyXG4gICAgcmV0dXJuIHRoaXMuaW5pdExvZ2luRmxvd0luUG9wdXAob3B0aW9ucyk7XHJcbiAgfVxyXG5cclxuICBwdWJsaWMgaW5pdExvZ2luRmxvd0luUG9wdXAob3B0aW9ucz86IHsgaGVpZ2h0PzogbnVtYmVyOyB3aWR0aD86IG51bWJlciB9KSB7XHJcbiAgICBvcHRpb25zID0gb3B0aW9ucyB8fCB7fTtcclxuICAgIHJldHVybiB0aGlzLmNyZWF0ZUxvZ2luVXJsKFxyXG4gICAgICBudWxsLFxyXG4gICAgICBudWxsLFxyXG4gICAgICB0aGlzLnNpbGVudFJlZnJlc2hSZWRpcmVjdFVyaSxcclxuICAgICAgZmFsc2UsXHJcbiAgICAgIHtcclxuICAgICAgICBkaXNwbGF5OiAncG9wdXAnXHJcbiAgICAgIH1cclxuICAgICkudGhlbih1cmwgPT4ge1xyXG4gICAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xyXG4gICAgICAgIC8qKlxyXG4gICAgICAgICAqIEVycm9yIGhhbmRsaW5nIHNlY3Rpb25cclxuICAgICAgICAgKi9cclxuICAgICAgICBjb25zdCBjaGVja0ZvclBvcHVwQ2xvc2VkSW50ZXJ2YWwgPSA1MDA7XHJcbiAgICAgICAgbGV0IHdpbmRvd1JlZiA9IHdpbmRvdy5vcGVuKFxyXG4gICAgICAgICAgdXJsLFxyXG4gICAgICAgICAgJ19ibGFuaycsXHJcbiAgICAgICAgICB0aGlzLmNhbGN1bGF0ZVBvcHVwRmVhdHVyZXMob3B0aW9ucylcclxuICAgICAgICApO1xyXG4gICAgICAgIGxldCBjaGVja0ZvclBvcHVwQ2xvc2VkVGltZXI6IGFueTtcclxuICAgICAgICBjb25zdCBjaGVja0ZvclBvcHVwQ2xvc2VkID0gKCkgPT4ge1xyXG4gICAgICAgICAgaWYgKCF3aW5kb3dSZWYgfHwgd2luZG93UmVmLmNsb3NlZCkge1xyXG4gICAgICAgICAgICBjbGVhbnVwKCk7XHJcbiAgICAgICAgICAgIHJlamVjdChuZXcgT0F1dGhFcnJvckV2ZW50KCdwb3B1cF9jbG9zZWQnLCB7fSkpO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgIH07XHJcbiAgICAgICAgaWYgKCF3aW5kb3dSZWYpIHtcclxuICAgICAgICAgIHJlamVjdChuZXcgT0F1dGhFcnJvckV2ZW50KCdwb3B1cF9ibG9ja2VkJywge30pKTtcclxuICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgY2hlY2tGb3JQb3B1cENsb3NlZFRpbWVyID0gd2luZG93LnNldEludGVydmFsKFxyXG4gICAgICAgICAgICBjaGVja0ZvclBvcHVwQ2xvc2VkLFxyXG4gICAgICAgICAgICBjaGVja0ZvclBvcHVwQ2xvc2VkSW50ZXJ2YWxcclxuICAgICAgICAgICk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBjb25zdCBjbGVhbnVwID0gKCkgPT4ge1xyXG4gICAgICAgICAgd2luZG93LmNsZWFySW50ZXJ2YWwoY2hlY2tGb3JQb3B1cENsb3NlZFRpbWVyKTtcclxuICAgICAgICAgIHdpbmRvdy5yZW1vdmVFdmVudExpc3RlbmVyKCdtZXNzYWdlJywgbGlzdGVuZXIpO1xyXG4gICAgICAgICAgaWYgKHdpbmRvd1JlZiAhPT0gbnVsbCkge1xyXG4gICAgICAgICAgICB3aW5kb3dSZWYuY2xvc2UoKTtcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIHdpbmRvd1JlZiA9IG51bGw7XHJcbiAgICAgICAgfTtcclxuXHJcbiAgICAgICAgY29uc3QgbGlzdGVuZXIgPSAoZTogTWVzc2FnZUV2ZW50KSA9PiB7XHJcbiAgICAgICAgICBjb25zdCBtZXNzYWdlID0gdGhpcy5wcm9jZXNzTWVzc2FnZUV2ZW50TWVzc2FnZShlKTtcclxuXHJcbiAgICAgICAgICBpZiAobWVzc2FnZSAmJiBtZXNzYWdlICE9PSBudWxsKSB7XHJcbiAgICAgICAgICAgIHRoaXMudHJ5TG9naW4oe1xyXG4gICAgICAgICAgICAgIGN1c3RvbUhhc2hGcmFnbWVudDogbWVzc2FnZSxcclxuICAgICAgICAgICAgICBwcmV2ZW50Q2xlYXJIYXNoQWZ0ZXJMb2dpbjogdHJ1ZSxcclxuICAgICAgICAgICAgICBjdXN0b21SZWRpcmVjdFVyaTogdGhpcy5zaWxlbnRSZWZyZXNoUmVkaXJlY3RVcmlcclxuICAgICAgICAgICAgfSkudGhlbihcclxuICAgICAgICAgICAgICAoKSA9PiB7XHJcbiAgICAgICAgICAgICAgICBjbGVhbnVwKCk7XHJcbiAgICAgICAgICAgICAgICByZXNvbHZlKCk7XHJcbiAgICAgICAgICAgICAgfSxcclxuICAgICAgICAgICAgICBlcnIgPT4ge1xyXG4gICAgICAgICAgICAgICAgY2xlYW51cCgpO1xyXG4gICAgICAgICAgICAgICAgcmVqZWN0KGVycik7XHJcbiAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICApO1xyXG4gICAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgY29uc29sZS5sb2coJ2ZhbHNlIGV2ZW50IGZpcmluZycpO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgIH07XHJcblxyXG4gICAgICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKCdtZXNzYWdlJywgbGlzdGVuZXIpO1xyXG4gICAgICB9KTtcclxuICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGNhbGN1bGF0ZVBvcHVwRmVhdHVyZXMob3B0aW9uczoge1xyXG4gICAgaGVpZ2h0PzogbnVtYmVyO1xyXG4gICAgd2lkdGg/OiBudW1iZXI7XHJcbiAgfSk6IHN0cmluZyB7XHJcbiAgICAvLyBTcGVjaWZ5IGFuIHN0YXRpYyBoZWlnaHQgYW5kIHdpZHRoIGFuZCBjYWxjdWxhdGUgY2VudGVyZWQgcG9zaXRpb25cclxuXHJcbiAgICBjb25zdCBoZWlnaHQgPSBvcHRpb25zLmhlaWdodCB8fCA0NzA7XHJcbiAgICBjb25zdCB3aWR0aCA9IG9wdGlvbnMud2lkdGggfHwgNTAwO1xyXG4gICAgY29uc3QgbGVmdCA9IHdpbmRvdy5zY3JlZW5MZWZ0ICsgKHdpbmRvdy5vdXRlcldpZHRoIC0gd2lkdGgpIC8gMjtcclxuICAgIGNvbnN0IHRvcCA9IHdpbmRvdy5zY3JlZW5Ub3AgKyAod2luZG93Lm91dGVySGVpZ2h0IC0gaGVpZ2h0KSAvIDI7XHJcbiAgICByZXR1cm4gYGxvY2F0aW9uPW5vLHRvb2xiYXI9bm8sd2lkdGg9JHt3aWR0aH0saGVpZ2h0PSR7aGVpZ2h0fSx0b3A9JHt0b3B9LGxlZnQ9JHtsZWZ0fWA7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgcHJvY2Vzc01lc3NhZ2VFdmVudE1lc3NhZ2UoZTogTWVzc2FnZUV2ZW50KTogc3RyaW5nIHtcclxuICAgIGxldCBleHBlY3RlZFByZWZpeCA9ICcjJztcclxuXHJcbiAgICBpZiAodGhpcy5zaWxlbnRSZWZyZXNoTWVzc2FnZVByZWZpeCkge1xyXG4gICAgICBleHBlY3RlZFByZWZpeCArPSB0aGlzLnNpbGVudFJlZnJlc2hNZXNzYWdlUHJlZml4O1xyXG4gICAgfVxyXG5cclxuICAgIGlmICghZSB8fCAhZS5kYXRhIHx8IHR5cGVvZiBlLmRhdGEgIT09ICdzdHJpbmcnKSB7XHJcbiAgICAgIHJldHVybjtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBwcmVmaXhlZE1lc3NhZ2U6IHN0cmluZyA9IGUuZGF0YTtcclxuXHJcbiAgICBpZiAoIXByZWZpeGVkTWVzc2FnZS5zdGFydHNXaXRoKGV4cGVjdGVkUHJlZml4KSkge1xyXG4gICAgICByZXR1cm47XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuICcjJyArIHByZWZpeGVkTWVzc2FnZS5zdWJzdHIoZXhwZWN0ZWRQcmVmaXgubGVuZ3RoKTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBjYW5QZXJmb3JtU2Vzc2lvbkNoZWNrKCk6IGJvb2xlYW4ge1xyXG4gICAgaWYgKCF0aGlzLnNlc3Npb25DaGVja3NFbmFibGVkKSB7XHJcbiAgICAgIHJldHVybiBmYWxzZTtcclxuICAgIH1cclxuICAgIGlmICghdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVVcmwpIHtcclxuICAgICAgY29uc29sZS53YXJuKFxyXG4gICAgICAgICdzZXNzaW9uQ2hlY2tzRW5hYmxlZCBpcyBhY3RpdmF0ZWQgYnV0IHRoZXJlIGlzIG5vIHNlc3Npb25DaGVja0lGcmFtZVVybCdcclxuICAgICAgKTtcclxuICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgfVxyXG4gICAgY29uc3Qgc2Vzc2lvblN0YXRlID0gdGhpcy5nZXRTZXNzaW9uU3RhdGUoKTtcclxuICAgIGlmICghc2Vzc2lvblN0YXRlKSB7XHJcbiAgICAgIGNvbnNvbGUud2FybihcclxuICAgICAgICAnc2Vzc2lvbkNoZWNrc0VuYWJsZWQgaXMgYWN0aXZhdGVkIGJ1dCB0aGVyZSBpcyBubyBzZXNzaW9uX3N0YXRlJ1xyXG4gICAgICApO1xyXG4gICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICB9XHJcbiAgICBpZiAodHlwZW9mIGRvY3VtZW50ID09PSAndW5kZWZpbmVkJykge1xyXG4gICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIHRydWU7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgc2V0dXBTZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKCk6IHZvaWQge1xyXG4gICAgdGhpcy5yZW1vdmVTZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKCk7XHJcblxyXG4gICAgdGhpcy5zZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyID0gKGU6IE1lc3NhZ2VFdmVudCkgPT4ge1xyXG4gICAgICBjb25zdCBvcmlnaW4gPSBlLm9yaWdpbi50b0xvd2VyQ2FzZSgpO1xyXG4gICAgICBjb25zdCBpc3N1ZXIgPSB0aGlzLmlzc3Vlci50b0xvd2VyQ2FzZSgpO1xyXG5cclxuICAgICAgdGhpcy5kZWJ1Zygnc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcicpO1xyXG5cclxuICAgICAgaWYgKCFpc3N1ZXIuc3RhcnRzV2l0aChvcmlnaW4pKSB7XHJcbiAgICAgICAgdGhpcy5kZWJ1ZyhcclxuICAgICAgICAgICdzZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyJyxcclxuICAgICAgICAgICd3cm9uZyBvcmlnaW4nLFxyXG4gICAgICAgICAgb3JpZ2luLFxyXG4gICAgICAgICAgJ2V4cGVjdGVkJyxcclxuICAgICAgICAgIGlzc3VlcixcclxuICAgICAgICAgICdldmVudCcsXHJcbiAgICAgICAgICBlXHJcbiAgICAgICAgKTtcclxuXHJcbiAgICAgICAgcmV0dXJuO1xyXG4gICAgICB9XHJcblxyXG4gICAgICAvLyBvbmx5IHJ1biBpbiBBbmd1bGFyIHpvbmUgaWYgaXQgaXMgJ2NoYW5nZWQnIG9yICdlcnJvcidcclxuICAgICAgc3dpdGNoIChlLmRhdGEpIHtcclxuICAgICAgICBjYXNlICd1bmNoYW5nZWQnOlxyXG4gICAgICAgICAgdGhpcy5oYW5kbGVTZXNzaW9uVW5jaGFuZ2VkKCk7XHJcbiAgICAgICAgICBicmVhaztcclxuICAgICAgICBjYXNlICdjaGFuZ2VkJzpcclxuICAgICAgICAgIHRoaXMubmdab25lLnJ1bigoKSA9PiB7XHJcbiAgICAgICAgICAgIHRoaXMuaGFuZGxlU2Vzc2lvbkNoYW5nZSgpO1xyXG4gICAgICAgICAgfSk7XHJcbiAgICAgICAgICBicmVhaztcclxuICAgICAgICBjYXNlICdlcnJvcic6XHJcbiAgICAgICAgICB0aGlzLm5nWm9uZS5ydW4oKCkgPT4ge1xyXG4gICAgICAgICAgICB0aGlzLmhhbmRsZVNlc3Npb25FcnJvcigpO1xyXG4gICAgICAgICAgfSk7XHJcbiAgICAgICAgICBicmVhaztcclxuICAgICAgfVxyXG5cclxuICAgICAgdGhpcy5kZWJ1ZygnZ290IGluZm8gZnJvbSBzZXNzaW9uIGNoZWNrIGluZnJhbWUnLCBlKTtcclxuICAgIH07XHJcblxyXG4gICAgLy8gcHJldmVudCBBbmd1bGFyIGZyb20gcmVmcmVzaGluZyB0aGUgdmlldyBvbiBldmVyeSBtZXNzYWdlIChydW5zIGluIGludGVydmFscylcclxuICAgIHRoaXMubmdab25lLnJ1bk91dHNpZGVBbmd1bGFyKCgpID0+IHtcclxuICAgICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoJ21lc3NhZ2UnLCB0aGlzLnNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIpO1xyXG4gICAgfSk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgaGFuZGxlU2Vzc2lvblVuY2hhbmdlZCgpOiB2b2lkIHtcclxuICAgIHRoaXMuZGVidWcoJ3Nlc3Npb24gY2hlY2snLCAnc2Vzc2lvbiB1bmNoYW5nZWQnKTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBoYW5kbGVTZXNzaW9uQ2hhbmdlKCk6IHZvaWQge1xyXG4gICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoSW5mb0V2ZW50KCdzZXNzaW9uX2NoYW5nZWQnKSk7XHJcbiAgICB0aGlzLnN0b3BTZXNzaW9uQ2hlY2tUaW1lcigpO1xyXG5cclxuICAgIGlmICghdGhpcy51c2VTaWxlbnRSZWZyZXNoICYmIHRoaXMucmVzcG9uc2VUeXBlID09PSAnY29kZScpIHtcclxuICAgICAgdGhpcy5yZWZyZXNoVG9rZW4oKVxyXG4gICAgICAgIC50aGVuKF8gPT4ge1xyXG4gICAgICAgICAgdGhpcy5kZWJ1ZygndG9rZW4gcmVmcmVzaCBhZnRlciBzZXNzaW9uIGNoYW5nZSB3b3JrZWQnKTtcclxuICAgICAgICB9KVxyXG4gICAgICAgIC5jYXRjaChfID0+IHtcclxuICAgICAgICAgIHRoaXMuZGVidWcoJ3Rva2VuIHJlZnJlc2ggZGlkIG5vdCB3b3JrIGFmdGVyIHNlc3Npb24gY2hhbmdlZCcpO1xyXG4gICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoSW5mb0V2ZW50KCdzZXNzaW9uX3Rlcm1pbmF0ZWQnKSk7XHJcbiAgICAgICAgICB0aGlzLmxvZ091dCh0cnVlKTtcclxuICAgICAgICB9KTtcclxuICAgIH0gZWxzZSBpZiAodGhpcy5zaWxlbnRSZWZyZXNoUmVkaXJlY3RVcmkpIHtcclxuICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoKCkuY2F0Y2goXyA9PlxyXG4gICAgICAgIHRoaXMuZGVidWcoJ3NpbGVudCByZWZyZXNoIGZhaWxlZCBhZnRlciBzZXNzaW9uIGNoYW5nZWQnKVxyXG4gICAgICApO1xyXG4gICAgICB0aGlzLndhaXRGb3JTaWxlbnRSZWZyZXNoQWZ0ZXJTZXNzaW9uQ2hhbmdlKCk7XHJcbiAgICB9IGVsc2Uge1xyXG4gICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhJbmZvRXZlbnQoJ3Nlc3Npb25fdGVybWluYXRlZCcpKTtcclxuICAgICAgdGhpcy5sb2dPdXQodHJ1ZSk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgd2FpdEZvclNpbGVudFJlZnJlc2hBZnRlclNlc3Npb25DaGFuZ2UoKTogdm9pZCB7XHJcbiAgICB0aGlzLmV2ZW50c1xyXG4gICAgICAucGlwZShcclxuICAgICAgICBmaWx0ZXIoXHJcbiAgICAgICAgICAoZTogT0F1dGhFdmVudCkgPT5cclxuICAgICAgICAgICAgZS50eXBlID09PSAnc2lsZW50bHlfcmVmcmVzaGVkJyB8fFxyXG4gICAgICAgICAgICBlLnR5cGUgPT09ICdzaWxlbnRfcmVmcmVzaF90aW1lb3V0JyB8fFxyXG4gICAgICAgICAgICBlLnR5cGUgPT09ICdzaWxlbnRfcmVmcmVzaF9lcnJvcidcclxuICAgICAgICApLFxyXG4gICAgICAgIGZpcnN0KClcclxuICAgICAgKVxyXG4gICAgICAuc3Vic2NyaWJlKGUgPT4ge1xyXG4gICAgICAgIGlmIChlLnR5cGUgIT09ICdzaWxlbnRseV9yZWZyZXNoZWQnKSB7XHJcbiAgICAgICAgICB0aGlzLmRlYnVnKCdzaWxlbnQgcmVmcmVzaCBkaWQgbm90IHdvcmsgYWZ0ZXIgc2Vzc2lvbiBjaGFuZ2VkJyk7XHJcbiAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhJbmZvRXZlbnQoJ3Nlc3Npb25fdGVybWluYXRlZCcpKTtcclxuICAgICAgICAgIHRoaXMubG9nT3V0KHRydWUpO1xyXG4gICAgICAgIH1cclxuICAgICAgfSk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgaGFuZGxlU2Vzc2lvbkVycm9yKCk6IHZvaWQge1xyXG4gICAgdGhpcy5zdG9wU2Vzc2lvbkNoZWNrVGltZXIoKTtcclxuICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aEluZm9FdmVudCgnc2Vzc2lvbl9lcnJvcicpKTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCByZW1vdmVTZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKCk6IHZvaWQge1xyXG4gICAgaWYgKHRoaXMuc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcikge1xyXG4gICAgICB3aW5kb3cucmVtb3ZlRXZlbnRMaXN0ZW5lcignbWVzc2FnZScsIHRoaXMuc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcik7XHJcbiAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lciA9IG51bGw7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgaW5pdFNlc3Npb25DaGVjaygpOiB2b2lkIHtcclxuICAgIGlmICghdGhpcy5jYW5QZXJmb3JtU2Vzc2lvbkNoZWNrKCkpIHtcclxuICAgICAgcmV0dXJuO1xyXG4gICAgfVxyXG5cclxuICAgIGNvbnN0IGV4aXN0aW5nSWZyYW1lID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQodGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVOYW1lKTtcclxuICAgIGlmIChleGlzdGluZ0lmcmFtZSkge1xyXG4gICAgICBkb2N1bWVudC5ib2R5LnJlbW92ZUNoaWxkKGV4aXN0aW5nSWZyYW1lKTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBpZnJhbWUgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdpZnJhbWUnKTtcclxuICAgIGlmcmFtZS5pZCA9IHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lTmFtZTtcclxuXHJcbiAgICB0aGlzLnNldHVwU2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcigpO1xyXG5cclxuICAgIGNvbnN0IHVybCA9IHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lVXJsO1xyXG4gICAgaWZyYW1lLnNldEF0dHJpYnV0ZSgnc3JjJywgdXJsKTtcclxuICAgIGlmcmFtZS5zdHlsZS5kaXNwbGF5ID0gJ25vbmUnO1xyXG4gICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChpZnJhbWUpO1xyXG5cclxuICAgIHRoaXMuc3RhcnRTZXNzaW9uQ2hlY2tUaW1lcigpO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHN0YXJ0U2Vzc2lvbkNoZWNrVGltZXIoKTogdm9pZCB7XHJcbiAgICB0aGlzLnN0b3BTZXNzaW9uQ2hlY2tUaW1lcigpO1xyXG4gICAgdGhpcy5uZ1pvbmUucnVuT3V0c2lkZUFuZ3VsYXIoKCkgPT4ge1xyXG4gICAgICB0aGlzLnNlc3Npb25DaGVja1RpbWVyID0gc2V0SW50ZXJ2YWwoXHJcbiAgICAgICAgdGhpcy5jaGVja1Nlc3Npb24uYmluZCh0aGlzKSxcclxuICAgICAgICB0aGlzLnNlc3Npb25DaGVja0ludGVydmFsbFxyXG4gICAgICApO1xyXG4gICAgfSk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgc3RvcFNlc3Npb25DaGVja1RpbWVyKCk6IHZvaWQge1xyXG4gICAgaWYgKHRoaXMuc2Vzc2lvbkNoZWNrVGltZXIpIHtcclxuICAgICAgY2xlYXJJbnRlcnZhbCh0aGlzLnNlc3Npb25DaGVja1RpbWVyKTtcclxuICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tUaW1lciA9IG51bGw7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBwdWJsaWMgY2hlY2tTZXNzaW9uKCk6IHZvaWQge1xyXG4gICAgY29uc3QgaWZyYW1lOiBhbnkgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCh0aGlzLnNlc3Npb25DaGVja0lGcmFtZU5hbWUpO1xyXG5cclxuICAgIGlmICghaWZyYW1lKSB7XHJcbiAgICAgIHRoaXMubG9nZ2VyLndhcm4oXHJcbiAgICAgICAgJ2NoZWNrU2Vzc2lvbiBkaWQgbm90IGZpbmQgaWZyYW1lJyxcclxuICAgICAgICB0aGlzLnNlc3Npb25DaGVja0lGcmFtZU5hbWVcclxuICAgICAgKTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBzZXNzaW9uU3RhdGUgPSB0aGlzLmdldFNlc3Npb25TdGF0ZSgpO1xyXG5cclxuICAgIGlmICghc2Vzc2lvblN0YXRlKSB7XHJcbiAgICAgIHRoaXMuc3RvcFNlc3Npb25DaGVja1RpbWVyKCk7XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3QgbWVzc2FnZSA9IHRoaXMuY2xpZW50SWQgKyAnICcgKyBzZXNzaW9uU3RhdGU7XHJcbiAgICBpZnJhbWUuY29udGVudFdpbmRvdy5wb3N0TWVzc2FnZShtZXNzYWdlLCB0aGlzLmlzc3Vlcik7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgYXN5bmMgY3JlYXRlTG9naW5VcmwoXHJcbiAgICBzdGF0ZSA9ICcnLFxyXG4gICAgbG9naW5IaW50ID0gJycsXHJcbiAgICBjdXN0b21SZWRpcmVjdFVyaSA9ICcnLFxyXG4gICAgbm9Qcm9tcHQgPSBmYWxzZSxcclxuICAgIHBhcmFtczogb2JqZWN0ID0ge31cclxuICApOiBQcm9taXNlPHN0cmluZz4ge1xyXG4gICAgY29uc3QgdGhhdCA9IHRoaXM7XHJcblxyXG4gICAgbGV0IHJlZGlyZWN0VXJpOiBzdHJpbmc7XHJcblxyXG4gICAgaWYgKGN1c3RvbVJlZGlyZWN0VXJpKSB7XHJcbiAgICAgIHJlZGlyZWN0VXJpID0gY3VzdG9tUmVkaXJlY3RVcmk7XHJcbiAgICB9IGVsc2Uge1xyXG4gICAgICByZWRpcmVjdFVyaSA9IHRoaXMucmVkaXJlY3RVcmk7XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3Qgbm9uY2UgPSBhd2FpdCB0aGlzLmNyZWF0ZUFuZFNhdmVOb25jZSgpO1xyXG5cclxuICAgIGlmIChzdGF0ZSkge1xyXG4gICAgICBzdGF0ZSA9XHJcbiAgICAgICAgbm9uY2UgKyB0aGlzLmNvbmZpZy5ub25jZVN0YXRlU2VwYXJhdG9yICsgZW5jb2RlVVJJQ29tcG9uZW50KHN0YXRlKTtcclxuICAgIH0gZWxzZSB7XHJcbiAgICAgIHN0YXRlID0gbm9uY2U7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKCF0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhdGhpcy5vaWRjKSB7XHJcbiAgICAgIHRocm93IG5ldyBFcnJvcignRWl0aGVyIHJlcXVlc3RBY2Nlc3NUb2tlbiBvciBvaWRjIG9yIGJvdGggbXVzdCBiZSB0cnVlJyk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHRoaXMuY29uZmlnLnJlc3BvbnNlVHlwZSkge1xyXG4gICAgICB0aGlzLnJlc3BvbnNlVHlwZSA9IHRoaXMuY29uZmlnLnJlc3BvbnNlVHlwZTtcclxuICAgIH0gZWxzZSB7XHJcbiAgICAgIGlmICh0aGlzLm9pZGMgJiYgdGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4pIHtcclxuICAgICAgICB0aGlzLnJlc3BvbnNlVHlwZSA9ICdpZF90b2tlbiB0b2tlbic7XHJcbiAgICAgIH0gZWxzZSBpZiAodGhpcy5vaWRjICYmICF0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbikge1xyXG4gICAgICAgIHRoaXMucmVzcG9uc2VUeXBlID0gJ2lkX3Rva2VuJztcclxuICAgICAgfSBlbHNlIHtcclxuICAgICAgICB0aGlzLnJlc3BvbnNlVHlwZSA9ICd0b2tlbic7XHJcbiAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBzZXBlcmF0aW9uQ2hhciA9IHRoYXQubG9naW5VcmwuaW5kZXhPZignPycpID4gLTEgPyAnJicgOiAnPyc7XHJcblxyXG4gICAgbGV0IHNjb3BlID0gdGhhdC5zY29wZTtcclxuXHJcbiAgICBpZiAodGhpcy5vaWRjICYmICFzY29wZS5tYXRjaCgvKF58XFxzKW9wZW5pZCgkfFxccykvKSkge1xyXG4gICAgICBzY29wZSA9ICdvcGVuaWQgJyArIHNjb3BlO1xyXG4gICAgfVxyXG5cclxuICAgIGxldCB1cmwgPVxyXG4gICAgICB0aGF0LmxvZ2luVXJsICtcclxuICAgICAgc2VwZXJhdGlvbkNoYXIgK1xyXG4gICAgICAncmVzcG9uc2VfdHlwZT0nICtcclxuICAgICAgZW5jb2RlVVJJQ29tcG9uZW50KHRoYXQucmVzcG9uc2VUeXBlKSArXHJcbiAgICAgICcmY2xpZW50X2lkPScgK1xyXG4gICAgICBlbmNvZGVVUklDb21wb25lbnQodGhhdC5jbGllbnRJZCkgK1xyXG4gICAgICAnJnN0YXRlPScgK1xyXG4gICAgICBlbmNvZGVVUklDb21wb25lbnQoc3RhdGUpICtcclxuICAgICAgJyZyZWRpcmVjdF91cmk9JyArXHJcbiAgICAgIGVuY29kZVVSSUNvbXBvbmVudChyZWRpcmVjdFVyaSkgK1xyXG4gICAgICAnJnNjb3BlPScgK1xyXG4gICAgICBlbmNvZGVVUklDb21wb25lbnQoc2NvcGUpO1xyXG5cclxuICAgIGlmICh0aGlzLnJlc3BvbnNlVHlwZSA9PT0gJ2NvZGUnICYmICF0aGlzLmRpc2FibGVQS0NFKSB7XHJcbiAgICAgIGNvbnN0IFtcclxuICAgICAgICBjaGFsbGVuZ2UsXHJcbiAgICAgICAgdmVyaWZpZXJcclxuICAgICAgXSA9IGF3YWl0IHRoaXMuY3JlYXRlQ2hhbGxhbmdlVmVyaWZpZXJQYWlyRm9yUEtDRSgpO1xyXG5cclxuICAgICAgaWYgKFxyXG4gICAgICAgIHRoaXMuc2F2ZU5vbmNlc0luTG9jYWxTdG9yYWdlICYmXHJcbiAgICAgICAgdHlwZW9mIHdpbmRvd1snbG9jYWxTdG9yYWdlJ10gIT09ICd1bmRlZmluZWQnXHJcbiAgICAgICkge1xyXG4gICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCdQS0NJX3ZlcmlmaWVyJywgdmVyaWZpZXIpO1xyXG4gICAgICB9IGVsc2Uge1xyXG4gICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnUEtDSV92ZXJpZmllcicsIHZlcmlmaWVyKTtcclxuICAgICAgfVxyXG5cclxuICAgICAgdXJsICs9ICcmY29kZV9jaGFsbGVuZ2U9JyArIGNoYWxsZW5nZTtcclxuICAgICAgdXJsICs9ICcmY29kZV9jaGFsbGVuZ2VfbWV0aG9kPVMyNTYnO1xyXG4gICAgfVxyXG5cclxuICAgIGlmIChsb2dpbkhpbnQpIHtcclxuICAgICAgdXJsICs9ICcmbG9naW5faGludD0nICsgZW5jb2RlVVJJQ29tcG9uZW50KGxvZ2luSGludCk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHRoYXQucmVzb3VyY2UpIHtcclxuICAgICAgdXJsICs9ICcmcmVzb3VyY2U9JyArIGVuY29kZVVSSUNvbXBvbmVudCh0aGF0LnJlc291cmNlKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAodGhhdC5vaWRjKSB7XHJcbiAgICAgIHVybCArPSAnJm5vbmNlPScgKyBlbmNvZGVVUklDb21wb25lbnQobm9uY2UpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmIChub1Byb21wdCkge1xyXG4gICAgICB1cmwgKz0gJyZwcm9tcHQ9bm9uZSc7XHJcbiAgICB9XHJcblxyXG4gICAgZm9yIChjb25zdCBrZXkgb2YgT2JqZWN0LmtleXMocGFyYW1zKSkge1xyXG4gICAgICB1cmwgKz1cclxuICAgICAgICAnJicgKyBlbmNvZGVVUklDb21wb25lbnQoa2V5KSArICc9JyArIGVuY29kZVVSSUNvbXBvbmVudChwYXJhbXNba2V5XSk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpIHtcclxuICAgICAgZm9yIChjb25zdCBrZXkgb2YgT2JqZWN0LmdldE93blByb3BlcnR5TmFtZXModGhpcy5jdXN0b21RdWVyeVBhcmFtcykpIHtcclxuICAgICAgICB1cmwgKz1cclxuICAgICAgICAgICcmJyArIGtleSArICc9JyArIGVuY29kZVVSSUNvbXBvbmVudCh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zW2tleV0pO1xyXG4gICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIHVybDtcclxuICB9XHJcblxyXG4gIGluaXRJbXBsaWNpdEZsb3dJbnRlcm5hbChcclxuICAgIGFkZGl0aW9uYWxTdGF0ZSA9ICcnLFxyXG4gICAgcGFyYW1zOiBzdHJpbmcgfCBvYmplY3QgPSAnJ1xyXG4gICk6IHZvaWQge1xyXG4gICAgaWYgKHRoaXMuaW5JbXBsaWNpdEZsb3cpIHtcclxuICAgICAgcmV0dXJuO1xyXG4gICAgfVxyXG5cclxuICAgIHRoaXMuaW5JbXBsaWNpdEZsb3cgPSB0cnVlO1xyXG5cclxuICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHRoaXMubG9naW5VcmwpKSB7XHJcbiAgICAgIHRocm93IG5ldyBFcnJvcihcclxuICAgICAgICBcImxvZ2luVXJsICBtdXN0IHVzZSBIVFRQUyAod2l0aCBUTFMpLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5ICdyZXF1aXJlSHR0cHMnIG11c3QgYmUgc2V0IHRvICdmYWxzZScgYW5kIGFsbG93IEhUVFAgKHdpdGhvdXQgVExTKS5cIlxyXG4gICAgICApO1xyXG4gICAgfVxyXG5cclxuICAgIGxldCBhZGRQYXJhbXM6IG9iamVjdCA9IHt9O1xyXG4gICAgbGV0IGxvZ2luSGludDogc3RyaW5nID0gbnVsbDtcclxuXHJcbiAgICBpZiAodHlwZW9mIHBhcmFtcyA9PT0gJ3N0cmluZycpIHtcclxuICAgICAgbG9naW5IaW50ID0gcGFyYW1zO1xyXG4gICAgfSBlbHNlIGlmICh0eXBlb2YgcGFyYW1zID09PSAnb2JqZWN0Jykge1xyXG4gICAgICBhZGRQYXJhbXMgPSBwYXJhbXM7XHJcbiAgICB9XHJcblxyXG4gICAgdGhpcy5jcmVhdGVMb2dpblVybChhZGRpdGlvbmFsU3RhdGUsIGxvZ2luSGludCwgbnVsbCwgZmFsc2UsIGFkZFBhcmFtcylcclxuICAgICAgLnRoZW4odGhpcy5jb25maWcub3BlblVyaSlcclxuICAgICAgLmNhdGNoKGVycm9yID0+IHtcclxuICAgICAgICBjb25zb2xlLmVycm9yKCdFcnJvciBpbiBpbml0SW1wbGljaXRGbG93JywgZXJyb3IpO1xyXG4gICAgICAgIHRoaXMuaW5JbXBsaWNpdEZsb3cgPSBmYWxzZTtcclxuICAgICAgfSk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBTdGFydHMgdGhlIGltcGxpY2l0IGZsb3cgYW5kIHJlZGlyZWN0cyB0byB1c2VyIHRvXHJcbiAgICogdGhlIGF1dGggc2VydmVycycgbG9naW4gdXJsLlxyXG4gICAqXHJcbiAgICogQHBhcmFtIGFkZGl0aW9uYWxTdGF0ZSBPcHRpb25hbCBzdGF0ZSB0aGF0IGlzIHBhc3NlZCBhcm91bmQuXHJcbiAgICogIFlvdSdsbCBmaW5kIHRoaXMgc3RhdGUgaW4gdGhlIHByb3BlcnR5IGBzdGF0ZWAgYWZ0ZXIgYHRyeUxvZ2luYCBsb2dnZWQgaW4gdGhlIHVzZXIuXHJcbiAgICogQHBhcmFtIHBhcmFtcyBIYXNoIHdpdGggYWRkaXRpb25hbCBwYXJhbWV0ZXIuIElmIGl0IGlzIGEgc3RyaW5nLCBpdCBpcyB1c2VkIGZvciB0aGVcclxuICAgKiAgICAgICAgICAgICAgIHBhcmFtZXRlciBsb2dpbkhpbnQgKGZvciB0aGUgc2FrZSBvZiBjb21wYXRpYmlsaXR5IHdpdGggZm9ybWVyIHZlcnNpb25zKVxyXG4gICAqL1xyXG4gIHB1YmxpYyBpbml0SW1wbGljaXRGbG93KFxyXG4gICAgYWRkaXRpb25hbFN0YXRlID0gJycsXHJcbiAgICBwYXJhbXM6IHN0cmluZyB8IG9iamVjdCA9ICcnXHJcbiAgKTogdm9pZCB7XHJcbiAgICBpZiAodGhpcy5sb2dpblVybCAhPT0gJycpIHtcclxuICAgICAgdGhpcy5pbml0SW1wbGljaXRGbG93SW50ZXJuYWwoYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpO1xyXG4gICAgfSBlbHNlIHtcclxuICAgICAgdGhpcy5ldmVudHNcclxuICAgICAgICAucGlwZShmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZGVkJykpXHJcbiAgICAgICAgLnN1YnNjcmliZShfID0+IHRoaXMuaW5pdEltcGxpY2l0Rmxvd0ludGVybmFsKGFkZGl0aW9uYWxTdGF0ZSwgcGFyYW1zKSk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBSZXNldCBjdXJyZW50IGltcGxpY2l0IGZsb3dcclxuICAgKlxyXG4gICAqIEBkZXNjcmlwdGlvbiBUaGlzIG1ldGhvZCBhbGxvd3MgcmVzZXR0aW5nIHRoZSBjdXJyZW50IGltcGxpY3QgZmxvdyBpbiBvcmRlciB0byBiZSBpbml0aWFsaXplZCBhZ2Fpbi5cclxuICAgKi9cclxuICBwdWJsaWMgcmVzZXRJbXBsaWNpdEZsb3coKTogdm9pZCB7XHJcbiAgICB0aGlzLmluSW1wbGljaXRGbG93ID0gZmFsc2U7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgY2FsbE9uVG9rZW5SZWNlaXZlZElmRXhpc3RzKG9wdGlvbnM6IExvZ2luT3B0aW9ucyk6IHZvaWQge1xyXG4gICAgY29uc3QgdGhhdCA9IHRoaXM7XHJcbiAgICBpZiAob3B0aW9ucy5vblRva2VuUmVjZWl2ZWQpIHtcclxuICAgICAgY29uc3QgdG9rZW5QYXJhbXMgPSB7XHJcbiAgICAgICAgaWRDbGFpbXM6IHRoYXQuZ2V0SWRlbnRpdHlDbGFpbXMoKSxcclxuICAgICAgICBpZFRva2VuOiB0aGF0LmdldElkVG9rZW4oKSxcclxuICAgICAgICBhY2Nlc3NUb2tlbjogdGhhdC5nZXRBY2Nlc3NUb2tlbigpLFxyXG4gICAgICAgIHN0YXRlOiB0aGF0LnN0YXRlXHJcbiAgICAgIH07XHJcbiAgICAgIG9wdGlvbnMub25Ub2tlblJlY2VpdmVkKHRva2VuUGFyYW1zKTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBzdG9yZUFjY2Vzc1Rva2VuUmVzcG9uc2UoXHJcbiAgICBhY2Nlc3NUb2tlbjogc3RyaW5nLFxyXG4gICAgcmVmcmVzaFRva2VuOiBzdHJpbmcsXHJcbiAgICBleHBpcmVzSW46IG51bWJlcixcclxuICAgIGdyYW50ZWRTY29wZXM6IFN0cmluZyxcclxuICAgIGN1c3RvbVBhcmFtZXRlcnM/OiBNYXA8c3RyaW5nLCBzdHJpbmc+XHJcbiAgKTogdm9pZCB7XHJcbiAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2FjY2Vzc190b2tlbicsIGFjY2Vzc1Rva2VuKTtcclxuICAgIGlmIChncmFudGVkU2NvcGVzICYmICFBcnJheS5pc0FycmF5KGdyYW50ZWRTY29wZXMpKSB7XHJcbiAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbShcclxuICAgICAgICAnZ3JhbnRlZF9zY29wZXMnLFxyXG4gICAgICAgIEpTT04uc3RyaW5naWZ5KGdyYW50ZWRTY29wZXMuc3BsaXQoJysnKSlcclxuICAgICAgKTtcclxuICAgIH0gZWxzZSBpZiAoZ3JhbnRlZFNjb3BlcyAmJiBBcnJheS5pc0FycmF5KGdyYW50ZWRTY29wZXMpKSB7XHJcbiAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnZ3JhbnRlZF9zY29wZXMnLCBKU09OLnN0cmluZ2lmeShncmFudGVkU2NvcGVzKSk7XHJcbiAgICB9XHJcblxyXG4gICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdhY2Nlc3NfdG9rZW5fc3RvcmVkX2F0JywgJycgKyBEYXRlLm5vdygpKTtcclxuICAgIGlmIChleHBpcmVzSW4pIHtcclxuICAgICAgY29uc3QgZXhwaXJlc0luTWlsbGlTZWNvbmRzID0gZXhwaXJlc0luICogMTAwMDtcclxuICAgICAgY29uc3Qgbm93ID0gbmV3IERhdGUoKTtcclxuICAgICAgY29uc3QgZXhwaXJlc0F0ID0gbm93LmdldFRpbWUoKSArIGV4cGlyZXNJbk1pbGxpU2Vjb25kcztcclxuICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdleHBpcmVzX2F0JywgJycgKyBleHBpcmVzQXQpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmIChyZWZyZXNoVG9rZW4pIHtcclxuICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdyZWZyZXNoX3Rva2VuJywgcmVmcmVzaFRva2VuKTtcclxuICAgIH1cclxuICAgIGlmIChjdXN0b21QYXJhbWV0ZXJzKSB7XHJcbiAgICAgIGN1c3RvbVBhcmFtZXRlcnMuZm9yRWFjaCgodmFsdWU6IHN0cmluZywga2V5OiBzdHJpbmcpID0+IHtcclxuICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oa2V5LCB2YWx1ZSk7XHJcbiAgICAgIH0pO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogRGVsZWdhdGVzIHRvIHRyeUxvZ2luSW1wbGljaXRGbG93IGZvciB0aGUgc2FrZSBvZiBjb21wZXRhYmlsaXR5XHJcbiAgICogQHBhcmFtIG9wdGlvbnMgT3B0aW9uYWwgb3B0aW9ucy5cclxuICAgKi9cclxuICBwdWJsaWMgdHJ5TG9naW4ob3B0aW9uczogTG9naW5PcHRpb25zID0gbnVsbCk6IFByb21pc2U8Ym9vbGVhbj4ge1xyXG4gICAgaWYgKHRoaXMuY29uZmlnLnJlc3BvbnNlVHlwZSA9PT0gJ2NvZGUnKSB7XHJcbiAgICAgIHJldHVybiB0aGlzLnRyeUxvZ2luQ29kZUZsb3cob3B0aW9ucykudGhlbihfID0+IHRydWUpO1xyXG4gICAgfSBlbHNlIHtcclxuICAgICAgcmV0dXJuIHRoaXMudHJ5TG9naW5JbXBsaWNpdEZsb3cob3B0aW9ucyk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBwcml2YXRlIHBhcnNlUXVlcnlTdHJpbmcocXVlcnlTdHJpbmc6IHN0cmluZyk6IG9iamVjdCB7XHJcbiAgICBpZiAoIXF1ZXJ5U3RyaW5nIHx8IHF1ZXJ5U3RyaW5nLmxlbmd0aCA9PT0gMCkge1xyXG4gICAgICByZXR1cm4ge307XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHF1ZXJ5U3RyaW5nLmNoYXJBdCgwKSA9PT0gJz8nKSB7XHJcbiAgICAgIHF1ZXJ5U3RyaW5nID0gcXVlcnlTdHJpbmcuc3Vic3RyKDEpO1xyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiB0aGlzLnVybEhlbHBlci5wYXJzZVF1ZXJ5U3RyaW5nKHF1ZXJ5U3RyaW5nKTtcclxuICB9XHJcblxyXG4gIHB1YmxpYyB0cnlMb2dpbkNvZGVGbG93KG9wdGlvbnM6IExvZ2luT3B0aW9ucyA9IG51bGwpOiBQcm9taXNlPHZvaWQ+IHtcclxuICAgIG9wdGlvbnMgPSBvcHRpb25zIHx8IHt9O1xyXG5cclxuICAgIGNvbnN0IHF1ZXJ5U291cmNlID0gb3B0aW9ucy5jdXN0b21IYXNoRnJhZ21lbnRcclxuICAgICAgPyBvcHRpb25zLmN1c3RvbUhhc2hGcmFnbWVudC5zdWJzdHJpbmcoMSlcclxuICAgICAgOiB3aW5kb3cubG9jYXRpb24uc2VhcmNoO1xyXG5cclxuICAgIGNvbnN0IHBhcnRzID0gdGhpcy5nZXRDb2RlUGFydHNGcm9tVXJsKHF1ZXJ5U291cmNlKTtcclxuXHJcbiAgICBjb25zdCBjb2RlID0gcGFydHNbJ2NvZGUnXTtcclxuICAgIGNvbnN0IHN0YXRlID0gcGFydHNbJ3N0YXRlJ107XHJcblxyXG4gICAgY29uc3Qgc2Vzc2lvblN0YXRlID0gcGFydHNbJ3Nlc3Npb25fc3RhdGUnXTtcclxuXHJcbiAgICBpZiAoIW9wdGlvbnMucHJldmVudENsZWFySGFzaEFmdGVyTG9naW4pIHtcclxuICAgICAgY29uc3QgaHJlZiA9IGxvY2F0aW9uLmhyZWZcclxuICAgICAgICAucmVwbGFjZSgvWyZcXD9dY29kZT1bXiZcXCRdKi8sICcnKVxyXG4gICAgICAgIC5yZXBsYWNlKC9bJlxcP11zY29wZT1bXiZcXCRdKi8sICcnKVxyXG4gICAgICAgIC5yZXBsYWNlKC9bJlxcP11zdGF0ZT1bXiZcXCRdKi8sICcnKVxyXG4gICAgICAgIC5yZXBsYWNlKC9bJlxcP11zZXNzaW9uX3N0YXRlPVteJlxcJF0qLywgJycpO1xyXG5cclxuICAgICAgaGlzdG9yeS5yZXBsYWNlU3RhdGUobnVsbCwgd2luZG93Lm5hbWUsIGhyZWYpO1xyXG4gICAgfVxyXG5cclxuICAgIGxldCBbbm9uY2VJblN0YXRlLCB1c2VyU3RhdGVdID0gdGhpcy5wYXJzZVN0YXRlKHN0YXRlKTtcclxuICAgIHRoaXMuc3RhdGUgPSB1c2VyU3RhdGU7XHJcblxyXG4gICAgaWYgKHBhcnRzWydlcnJvciddKSB7XHJcbiAgICAgIHRoaXMuZGVidWcoJ2Vycm9yIHRyeWluZyB0byBsb2dpbicpO1xyXG4gICAgICB0aGlzLmhhbmRsZUxvZ2luRXJyb3Ioe30sIHBhcnRzKTtcclxuICAgICAgY29uc3QgZXJyID0gbmV3IE9BdXRoRXJyb3JFdmVudCgnY29kZV9lcnJvcicsIHt9LCBwYXJ0cyk7XHJcbiAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGVycik7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xyXG4gICAgfVxyXG4gICAgbm9uY2VJblN0YXRlID0gc2Vzc2lvblN0b3JhZ2UuZ2V0SXRlbSgnbm9uY2UnKTtcclxuICAgIGlmICghbm9uY2VJblN0YXRlKSB7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBzdWNjZXNzID0gdGhpcy52YWxpZGF0ZU5vbmNlKG5vbmNlSW5TdGF0ZSk7XHJcbiAgICBpZiAoIXN1Y2Nlc3MpIHtcclxuICAgICAgY29uc3QgZXZlbnQgPSBuZXcgT0F1dGhFcnJvckV2ZW50KCdpbnZhbGlkX25vbmNlX2luX3N0YXRlJywgbnVsbCk7XHJcbiAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGV2ZW50KTtcclxuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGV2ZW50KTtcclxuICAgIH1cclxuXHJcbiAgICB0aGlzLnN0b3JlU2Vzc2lvblN0YXRlKHNlc3Npb25TdGF0ZSk7XHJcblxyXG4gICAgaWYgKGNvZGUpIHtcclxuICAgICAgcmV0dXJuIHRoaXMuZ2V0VG9rZW5Gcm9tQ29kZShjb2RlLCBvcHRpb25zKS50aGVuKF8gPT4gbnVsbCk7XHJcbiAgICB9IGVsc2Uge1xyXG4gICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBSZXRyaWV2ZSB0aGUgcmV0dXJuZWQgYXV0aCBjb2RlIGZyb20gdGhlIHJlZGlyZWN0IHVyaSB0aGF0IGhhcyBiZWVuIGNhbGxlZC5cclxuICAgKiBJZiByZXF1aXJlZCBhbHNvIGNoZWNrIGhhc2gsIGFzIHdlIGNvdWxkIHVzZSBoYXNoIGxvY2F0aW9uIHN0cmF0ZWd5LlxyXG4gICAqL1xyXG4gIHByaXZhdGUgZ2V0Q29kZVBhcnRzRnJvbVVybChxdWVyeVN0cmluZzogc3RyaW5nKTogb2JqZWN0IHtcclxuICAgIGlmICghcXVlcnlTdHJpbmcgfHwgcXVlcnlTdHJpbmcubGVuZ3RoID09PSAwKSB7XHJcbiAgICAgIHJldHVybiB0aGlzLnVybEhlbHBlci5nZXRIYXNoRnJhZ21lbnRQYXJhbXMoKTtcclxuICAgIH1cclxuXHJcbiAgICAvLyBub3JtYWxpemUgcXVlcnkgc3RyaW5nXHJcbiAgICBpZiAocXVlcnlTdHJpbmcuY2hhckF0KDApID09PSAnPycpIHtcclxuICAgICAgcXVlcnlTdHJpbmcgPSBxdWVyeVN0cmluZy5zdWJzdHIoMSk7XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIHRoaXMudXJsSGVscGVyLnBhcnNlUXVlcnlTdHJpbmcocXVlcnlTdHJpbmcpO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogR2V0IHRva2VuIHVzaW5nIGFuIGludGVybWVkaWF0ZSBjb2RlLiBXb3JrcyBmb3IgdGhlIEF1dGhvcml6YXRpb24gQ29kZSBmbG93LlxyXG4gICAqL1xyXG4gIHByaXZhdGUgZ2V0VG9rZW5Gcm9tQ29kZShcclxuICAgIGNvZGU6IHN0cmluZyxcclxuICAgIG9wdGlvbnM6IExvZ2luT3B0aW9uc1xyXG4gICk6IFByb21pc2U8b2JqZWN0PiB7XHJcbiAgICBsZXQgcGFyYW1zID0gbmV3IEh0dHBQYXJhbXMoKVxyXG4gICAgICAuc2V0KCdncmFudF90eXBlJywgJ2F1dGhvcml6YXRpb25fY29kZScpXHJcbiAgICAgIC5zZXQoJ2NvZGUnLCBjb2RlKVxyXG4gICAgICAuc2V0KCdyZWRpcmVjdF91cmknLCBvcHRpb25zLmN1c3RvbVJlZGlyZWN0VXJpIHx8IHRoaXMucmVkaXJlY3RVcmkpO1xyXG5cclxuICAgIGlmICghdGhpcy5kaXNhYmxlUEtDRSkge1xyXG4gICAgICBsZXQgcGtjaVZlcmlmaWVyO1xyXG5cclxuICAgICAgaWYgKFxyXG4gICAgICAgIHRoaXMuc2F2ZU5vbmNlc0luTG9jYWxTdG9yYWdlICYmXHJcbiAgICAgICAgdHlwZW9mIHdpbmRvd1snbG9jYWxTdG9yYWdlJ10gIT09ICd1bmRlZmluZWQnXHJcbiAgICAgICkge1xyXG4gICAgICAgIHBrY2lWZXJpZmllciA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdQS0NJX3ZlcmlmaWVyJyk7XHJcbiAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgcGtjaVZlcmlmaWVyID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdQS0NJX3ZlcmlmaWVyJyk7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIGlmICghcGtjaVZlcmlmaWVyKSB7XHJcbiAgICAgICAgY29uc29sZS53YXJuKCdObyBQS0NJIHZlcmlmaWVyIGZvdW5kIGluIG9hdXRoIHN0b3JhZ2UhJyk7XHJcbiAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY29kZV92ZXJpZmllcicsIHBrY2lWZXJpZmllcik7XHJcbiAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gdGhpcy5mZXRjaEFuZFByb2Nlc3NUb2tlbihwYXJhbXMpO1xyXG4gIH1cclxuXHJcbiAgcHJpdmF0ZSBmZXRjaEFuZFByb2Nlc3NUb2tlbihwYXJhbXM6IEh0dHBQYXJhbXMpOiBQcm9taXNlPFRva2VuUmVzcG9uc2U+IHtcclxuICAgIHRoaXMuYXNzZXJ0VXJsTm90TnVsbEFuZENvcnJlY3RQcm90b2NvbChcclxuICAgICAgdGhpcy50b2tlbkVuZHBvaW50LFxyXG4gICAgICAndG9rZW5FbmRwb2ludCdcclxuICAgICk7XHJcbiAgICBsZXQgaGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpLnNldChcclxuICAgICAgJ0NvbnRlbnQtVHlwZScsXHJcbiAgICAgICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnXHJcbiAgICApO1xyXG5cclxuICAgIGlmICh0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcclxuICAgICAgY29uc3QgaGVhZGVyID0gYnRvYShgJHt0aGlzLmNsaWVudElkfToke3RoaXMuZHVtbXlDbGllbnRTZWNyZXR9YCk7XHJcbiAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldCgnQXV0aG9yaXphdGlvbicsICdCYXNpYyAnICsgaGVhZGVyKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCkge1xyXG4gICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdjbGllbnRfaWQnLCB0aGlzLmNsaWVudElkKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCAmJiB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KSB7XHJcbiAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9zZWNyZXQnLCB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KTtcclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xyXG4gICAgICBpZiAodGhpcy5jdXN0b21RdWVyeVBhcmFtcykge1xyXG4gICAgICAgIGZvciAobGV0IGtleSBvZiBPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSkge1xyXG4gICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldChrZXksIHRoaXMuY3VzdG9tUXVlcnlQYXJhbXNba2V5XSk7XHJcbiAgICAgICAgfVxyXG4gICAgICB9XHJcblxyXG4gICAgICB0aGlzLmh0dHBcclxuICAgICAgICAucG9zdDxUb2tlblJlc3BvbnNlPih0aGlzLnRva2VuRW5kcG9pbnQsIHBhcmFtcywgeyBoZWFkZXJzIH0pXHJcbiAgICAgICAgLnN1YnNjcmliZShcclxuICAgICAgICAgIHRva2VuUmVzcG9uc2UgPT4ge1xyXG4gICAgICAgICAgICB0aGlzLmRlYnVnKCdyZWZyZXNoIHRva2VuUmVzcG9uc2UnLCB0b2tlblJlc3BvbnNlKTtcclxuICAgICAgICAgICAgdGhpcy5zdG9yZUFjY2Vzc1Rva2VuUmVzcG9uc2UoXHJcbiAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5hY2Nlc3NfdG9rZW4sXHJcbiAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5yZWZyZXNoX3Rva2VuLFxyXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuZXhwaXJlc19pbiB8fFxyXG4gICAgICAgICAgICAgICAgdGhpcy5mYWxsYmFja0FjY2Vzc1Rva2VuRXhwaXJhdGlvblRpbWVJblNlYyxcclxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLnNjb3BlLFxyXG4gICAgICAgICAgICAgIHRoaXMuZXh0cmFjdFJlY29nbml6ZWRDdXN0b21QYXJhbWV0ZXJzKHRva2VuUmVzcG9uc2UpXHJcbiAgICAgICAgICAgICk7XHJcblxyXG4gICAgICAgICAgICBpZiAodGhpcy5vaWRjICYmIHRva2VuUmVzcG9uc2UuaWRfdG9rZW4pIHtcclxuICAgICAgICAgICAgICB0aGlzLnByb2Nlc3NJZFRva2VuKFxyXG4gICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5pZF90b2tlbixcclxuICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuYWNjZXNzX3Rva2VuXHJcbiAgICAgICAgICAgICAgKVxyXG4gICAgICAgICAgICAgICAgLnRoZW4ocmVzdWx0ID0+IHtcclxuICAgICAgICAgICAgICAgICAgdGhpcy5zdG9yZUlkVG9rZW4ocmVzdWx0KTtcclxuXHJcbiAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxyXG4gICAgICAgICAgICAgICAgICAgIG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVjZWl2ZWQnKVxyXG4gICAgICAgICAgICAgICAgICApO1xyXG4gICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcclxuICAgICAgICAgICAgICAgICAgICBuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlZnJlc2hlZCcpXHJcbiAgICAgICAgICAgICAgICAgICk7XHJcblxyXG4gICAgICAgICAgICAgICAgICByZXNvbHZlKHRva2VuUmVzcG9uc2UpO1xyXG4gICAgICAgICAgICAgICAgfSlcclxuICAgICAgICAgICAgICAgIC5jYXRjaChyZWFzb24gPT4ge1xyXG4gICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcclxuICAgICAgICAgICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl92YWxpZGF0aW9uX2Vycm9yJywgcmVhc29uKVxyXG4gICAgICAgICAgICAgICAgICApO1xyXG4gICAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKCdFcnJvciB2YWxpZGF0aW5nIHRva2VucycpO1xyXG4gICAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKHJlYXNvbik7XHJcblxyXG4gICAgICAgICAgICAgICAgICByZWplY3QocmVhc29uKTtcclxuICAgICAgICAgICAgICAgIH0pO1xyXG4gICAgICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVjZWl2ZWQnKSk7XHJcbiAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWZyZXNoZWQnKSk7XHJcblxyXG4gICAgICAgICAgICAgIHJlc29sdmUodG9rZW5SZXNwb25zZSk7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgIH0sXHJcbiAgICAgICAgICBlcnIgPT4ge1xyXG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKCdFcnJvciBnZXR0aW5nIHRva2VuJywgZXJyKTtcclxuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXHJcbiAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgndG9rZW5fcmVmcmVzaF9lcnJvcicsIGVycilcclxuICAgICAgICAgICAgKTtcclxuICAgICAgICAgICAgcmVqZWN0KGVycik7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgKTtcclxuICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogQ2hlY2tzIHdoZXRoZXIgdGhlcmUgYXJlIHRva2VucyBpbiB0aGUgaGFzaCBmcmFnbWVudFxyXG4gICAqIGFzIGEgcmVzdWx0IG9mIHRoZSBpbXBsaWNpdCBmbG93LiBUaGVzZSB0b2tlbnMgYXJlXHJcbiAgICogcGFyc2VkLCB2YWxpZGF0ZWQgYW5kIHVzZWQgdG8gc2lnbiB0aGUgdXNlciBpbiB0byB0aGVcclxuICAgKiBjdXJyZW50IGNsaWVudC5cclxuICAgKlxyXG4gICAqIEBwYXJhbSBvcHRpb25zIE9wdGlvbmFsIG9wdGlvbnMuXHJcbiAgICovXHJcbiAgcHVibGljIHRyeUxvZ2luSW1wbGljaXRGbG93KG9wdGlvbnM6IExvZ2luT3B0aW9ucyA9IG51bGwpOiBQcm9taXNlPGJvb2xlYW4+IHtcclxuICAgIG9wdGlvbnMgPSBvcHRpb25zIHx8IHt9O1xyXG5cclxuICAgIGxldCBwYXJ0czogb2JqZWN0O1xyXG5cclxuICAgIGlmIChvcHRpb25zLmN1c3RvbUhhc2hGcmFnbWVudCkge1xyXG4gICAgICBwYXJ0cyA9IHRoaXMudXJsSGVscGVyLmdldEhhc2hGcmFnbWVudFBhcmFtcyhvcHRpb25zLmN1c3RvbUhhc2hGcmFnbWVudCk7XHJcbiAgICB9IGVsc2Uge1xyXG4gICAgICBwYXJ0cyA9IHRoaXMudXJsSGVscGVyLmdldEhhc2hGcmFnbWVudFBhcmFtcygpO1xyXG4gICAgfVxyXG5cclxuICAgIHRoaXMuZGVidWcoJ3BhcnNlZCB1cmwnLCBwYXJ0cyk7XHJcblxyXG4gICAgY29uc3Qgc3RhdGUgPSBwYXJ0c1snc3RhdGUnXTtcclxuXHJcbiAgICBsZXQgW25vbmNlSW5TdGF0ZSwgdXNlclN0YXRlXSA9IHRoaXMucGFyc2VTdGF0ZShzdGF0ZSk7XHJcbiAgICB0aGlzLnN0YXRlID0gdXNlclN0YXRlO1xyXG5cclxuICAgIGlmIChwYXJ0c1snZXJyb3InXSkge1xyXG4gICAgICB0aGlzLmRlYnVnKCdlcnJvciB0cnlpbmcgdG8gbG9naW4nKTtcclxuICAgICAgdGhpcy5oYW5kbGVMb2dpbkVycm9yKG9wdGlvbnMsIHBhcnRzKTtcclxuICAgICAgY29uc3QgZXJyID0gbmV3IE9BdXRoRXJyb3JFdmVudCgndG9rZW5fZXJyb3InLCB7fSwgcGFydHMpO1xyXG4gICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlcnIpO1xyXG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBhY2Nlc3NUb2tlbiA9IHBhcnRzWydhY2Nlc3NfdG9rZW4nXTtcclxuICAgIGNvbnN0IGlkVG9rZW4gPSBwYXJ0c1snaWRfdG9rZW4nXTtcclxuICAgIGNvbnN0IHNlc3Npb25TdGF0ZSA9IHBhcnRzWydzZXNzaW9uX3N0YXRlJ107XHJcbiAgICBjb25zdCBncmFudGVkU2NvcGVzID0gcGFydHNbJ3Njb3BlJ107XHJcblxyXG4gICAgaWYgKCF0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhdGhpcy5vaWRjKSB7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChcclxuICAgICAgICAnRWl0aGVyIHJlcXVlc3RBY2Nlc3NUb2tlbiBvciBvaWRjIChvciBib3RoKSBtdXN0IGJlIHRydWUuJ1xyXG4gICAgICApO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICh0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhYWNjZXNzVG9rZW4pIHtcclxuICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShmYWxzZSk7XHJcbiAgICB9XHJcbiAgICBpZiAodGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4gJiYgIW9wdGlvbnMuZGlzYWJsZU9BdXRoMlN0YXRlQ2hlY2sgJiYgIXN0YXRlKSB7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoZmFsc2UpO1xyXG4gICAgfVxyXG4gICAgaWYgKHRoaXMub2lkYyAmJiAhaWRUb2tlbikge1xyXG4gICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKGZhbHNlKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAodGhpcy5zZXNzaW9uQ2hlY2tzRW5hYmxlZCAmJiAhc2Vzc2lvblN0YXRlKSB7XHJcbiAgICAgIHRoaXMubG9nZ2VyLndhcm4oXHJcbiAgICAgICAgJ3Nlc3Npb24gY2hlY2tzIChTZXNzaW9uIFN0YXR1cyBDaGFuZ2UgTm90aWZpY2F0aW9uKSAnICtcclxuICAgICAgICAgICd3ZXJlIGFjdGl2YXRlZCBpbiB0aGUgY29uZmlndXJhdGlvbiBidXQgdGhlIGlkX3Rva2VuICcgK1xyXG4gICAgICAgICAgJ2RvZXMgbm90IGNvbnRhaW4gYSBzZXNzaW9uX3N0YXRlIGNsYWltJ1xyXG4gICAgICApO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICh0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhb3B0aW9ucy5kaXNhYmxlT0F1dGgyU3RhdGVDaGVjaykge1xyXG4gICAgICBjb25zdCBzdWNjZXNzID0gdGhpcy52YWxpZGF0ZU5vbmNlKG5vbmNlSW5TdGF0ZSk7XHJcblxyXG4gICAgICBpZiAoIXN1Y2Nlc3MpIHtcclxuICAgICAgICBjb25zdCBldmVudCA9IG5ldyBPQXV0aEVycm9yRXZlbnQoJ2ludmFsaWRfbm9uY2VfaW5fc3RhdGUnLCBudWxsKTtcclxuICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChldmVudCk7XHJcbiAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGV2ZW50KTtcclxuICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIGlmICh0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbikge1xyXG4gICAgICB0aGlzLnN0b3JlQWNjZXNzVG9rZW5SZXNwb25zZShcclxuICAgICAgICBhY2Nlc3NUb2tlbixcclxuICAgICAgICBudWxsLFxyXG4gICAgICAgIHBhcnRzWydleHBpcmVzX2luJ10gfHwgdGhpcy5mYWxsYmFja0FjY2Vzc1Rva2VuRXhwaXJhdGlvblRpbWVJblNlYyxcclxuICAgICAgICBncmFudGVkU2NvcGVzXHJcbiAgICAgICk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKCF0aGlzLm9pZGMpIHtcclxuICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWNlaXZlZCcpKTtcclxuICAgICAgaWYgKHRoaXMuY2xlYXJIYXNoQWZ0ZXJMb2dpbiAmJiAhb3B0aW9ucy5wcmV2ZW50Q2xlYXJIYXNoQWZ0ZXJMb2dpbikge1xyXG4gICAgICAgIGxvY2F0aW9uLmhhc2ggPSAnJztcclxuICAgICAgfVxyXG5cclxuICAgICAgdGhpcy5jYWxsT25Ub2tlblJlY2VpdmVkSWZFeGlzdHMob3B0aW9ucyk7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUodHJ1ZSk7XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIHRoaXMucHJvY2Vzc0lkVG9rZW4oaWRUb2tlbiwgYWNjZXNzVG9rZW4pXHJcbiAgICAgIC50aGVuKHJlc3VsdCA9PiB7XHJcbiAgICAgICAgaWYgKG9wdGlvbnMudmFsaWRhdGlvbkhhbmRsZXIpIHtcclxuICAgICAgICAgIHJldHVybiBvcHRpb25zXHJcbiAgICAgICAgICAgIC52YWxpZGF0aW9uSGFuZGxlcih7XHJcbiAgICAgICAgICAgICAgYWNjZXNzVG9rZW46IGFjY2Vzc1Rva2VuLFxyXG4gICAgICAgICAgICAgIGlkQ2xhaW1zOiByZXN1bHQuaWRUb2tlbkNsYWltcyxcclxuICAgICAgICAgICAgICBpZFRva2VuOiByZXN1bHQuaWRUb2tlbixcclxuICAgICAgICAgICAgICBzdGF0ZTogc3RhdGVcclxuICAgICAgICAgICAgfSlcclxuICAgICAgICAgICAgLnRoZW4oXyA9PiByZXN1bHQpO1xyXG4gICAgICAgIH1cclxuICAgICAgICByZXR1cm4gcmVzdWx0O1xyXG4gICAgICB9KVxyXG4gICAgICAudGhlbihyZXN1bHQgPT4ge1xyXG4gICAgICAgIHRoaXMuc3RvcmVJZFRva2VuKHJlc3VsdCk7XHJcbiAgICAgICAgdGhpcy5zdG9yZVNlc3Npb25TdGF0ZShzZXNzaW9uU3RhdGUpO1xyXG4gICAgICAgIGlmICh0aGlzLmNsZWFySGFzaEFmdGVyTG9naW4gJiYgIW9wdGlvbnMucHJldmVudENsZWFySGFzaEFmdGVyTG9naW4pIHtcclxuICAgICAgICAgIGxvY2F0aW9uLmhhc2ggPSAnJztcclxuICAgICAgICB9XHJcbiAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWNlaXZlZCcpKTtcclxuICAgICAgICB0aGlzLmNhbGxPblRva2VuUmVjZWl2ZWRJZkV4aXN0cyhvcHRpb25zKTtcclxuICAgICAgICB0aGlzLmluSW1wbGljaXRGbG93ID0gZmFsc2U7XHJcbiAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICAgIH0pXHJcbiAgICAgIC5jYXRjaChyZWFzb24gPT4ge1xyXG4gICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxyXG4gICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgndG9rZW5fdmFsaWRhdGlvbl9lcnJvcicsIHJlYXNvbilcclxuICAgICAgICApO1xyXG4gICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdFcnJvciB2YWxpZGF0aW5nIHRva2VucycpO1xyXG4gICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKHJlYXNvbik7XHJcbiAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KHJlYXNvbik7XHJcbiAgICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgcHJpdmF0ZSBwYXJzZVN0YXRlKHN0YXRlOiBzdHJpbmcpOiBbc3RyaW5nLCBzdHJpbmddIHtcclxuICAgIGxldCBub25jZSA9IHN0YXRlO1xyXG4gICAgbGV0IHVzZXJTdGF0ZSA9ICcnO1xyXG5cclxuICAgIGlmIChzdGF0ZSkge1xyXG4gICAgICBjb25zdCBpZHggPSBzdGF0ZS5pbmRleE9mKHRoaXMuY29uZmlnLm5vbmNlU3RhdGVTZXBhcmF0b3IpO1xyXG4gICAgICBpZiAoaWR4ID4gLTEpIHtcclxuICAgICAgICBub25jZSA9IHN0YXRlLnN1YnN0cigwLCBpZHgpO1xyXG4gICAgICAgIHVzZXJTdGF0ZSA9IHN0YXRlLnN1YnN0cihpZHggKyB0aGlzLmNvbmZpZy5ub25jZVN0YXRlU2VwYXJhdG9yLmxlbmd0aCk7XHJcbiAgICAgIH1cclxuICAgIH1cclxuICAgIHJldHVybiBbbm9uY2UsIHVzZXJTdGF0ZV07XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgdmFsaWRhdGVOb25jZShub25jZUluU3RhdGU6IHN0cmluZyk6IGJvb2xlYW4ge1xyXG4gICAgbGV0IHNhdmVkTm9uY2U7XHJcblxyXG4gICAgaWYgKFxyXG4gICAgICB0aGlzLnNhdmVOb25jZXNJbkxvY2FsU3RvcmFnZSAmJlxyXG4gICAgICB0eXBlb2Ygd2luZG93Wydsb2NhbFN0b3JhZ2UnXSAhPT0gJ3VuZGVmaW5lZCdcclxuICAgICkge1xyXG4gICAgICBzYXZlZE5vbmNlID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ25vbmNlJyk7XHJcbiAgICB9IGVsc2Uge1xyXG4gICAgICBzYXZlZE5vbmNlID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdub25jZScpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmIChzYXZlZE5vbmNlICE9PSBub25jZUluU3RhdGUpIHtcclxuICAgICAgY29uc3QgZXJyID0gJ1ZhbGlkYXRpbmcgYWNjZXNzX3Rva2VuIGZhaWxlZCwgd3Jvbmcgc3RhdGUvbm9uY2UuJztcclxuICAgICAgY29uc29sZS5lcnJvcihlcnIsIHNhdmVkTm9uY2UsIG5vbmNlSW5TdGF0ZSk7XHJcbiAgICAgIHJldHVybiBmYWxzZTtcclxuICAgIH1cclxuICAgIHJldHVybiB0cnVlO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHN0b3JlSWRUb2tlbihpZFRva2VuOiBQYXJzZWRJZFRva2VuKTogdm9pZCB7XHJcbiAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2lkX3Rva2VuJywgaWRUb2tlbi5pZFRva2VuKTtcclxuICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnaWRfdG9rZW5fY2xhaW1zX29iaicsIGlkVG9rZW4uaWRUb2tlbkNsYWltc0pzb24pO1xyXG4gICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdpZF90b2tlbl9leHBpcmVzX2F0JywgJycgKyBpZFRva2VuLmlkVG9rZW5FeHBpcmVzQXQpO1xyXG4gICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdpZF90b2tlbl9zdG9yZWRfYXQnLCAnJyArIERhdGUubm93KCkpO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHN0b3JlU2Vzc2lvblN0YXRlKHNlc3Npb25TdGF0ZTogc3RyaW5nKTogdm9pZCB7XHJcbiAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ3Nlc3Npb25fc3RhdGUnLCBzZXNzaW9uU3RhdGUpO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGdldFNlc3Npb25TdGF0ZSgpOiBzdHJpbmcge1xyXG4gICAgcmV0dXJuIHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnc2Vzc2lvbl9zdGF0ZScpO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGhhbmRsZUxvZ2luRXJyb3Iob3B0aW9uczogTG9naW5PcHRpb25zLCBwYXJ0czogb2JqZWN0KTogdm9pZCB7XHJcbiAgICBpZiAob3B0aW9ucy5vbkxvZ2luRXJyb3IpIHtcclxuICAgICAgb3B0aW9ucy5vbkxvZ2luRXJyb3IocGFydHMpO1xyXG4gICAgfVxyXG4gICAgaWYgKHRoaXMuY2xlYXJIYXNoQWZ0ZXJMb2dpbiAmJiAhb3B0aW9ucy5wcmV2ZW50Q2xlYXJIYXNoQWZ0ZXJMb2dpbikge1xyXG4gICAgICBsb2NhdGlvbi5oYXNoID0gJyc7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBAaWdub3JlXHJcbiAgICovXHJcbiAgcHVibGljIHByb2Nlc3NJZFRva2VuKFxyXG4gICAgaWRUb2tlbjogc3RyaW5nLFxyXG4gICAgYWNjZXNzVG9rZW46IHN0cmluZyxcclxuICAgIHNraXBOb25jZUNoZWNrID0gZmFsc2VcclxuICApOiBQcm9taXNlPFBhcnNlZElkVG9rZW4+IHtcclxuICAgIGNvbnN0IHRva2VuUGFydHMgPSBpZFRva2VuLnNwbGl0KCcuJyk7XHJcbiAgICBjb25zdCBoZWFkZXJCYXNlNjQgPSB0aGlzLnBhZEJhc2U2NCh0b2tlblBhcnRzWzBdKTtcclxuICAgIGNvbnN0IGhlYWRlckpzb24gPSBiNjREZWNvZGVVbmljb2RlKGhlYWRlckJhc2U2NCk7XHJcbiAgICBjb25zdCBoZWFkZXIgPSBKU09OLnBhcnNlKGhlYWRlckpzb24pO1xyXG4gICAgY29uc3QgY2xhaW1zQmFzZTY0ID0gdGhpcy5wYWRCYXNlNjQodG9rZW5QYXJ0c1sxXSk7XHJcbiAgICBjb25zdCBjbGFpbXNKc29uID0gYjY0RGVjb2RlVW5pY29kZShjbGFpbXNCYXNlNjQpO1xyXG4gICAgY29uc3QgY2xhaW1zID0gSlNPTi5wYXJzZShjbGFpbXNKc29uKTtcclxuXHJcbiAgICBsZXQgc2F2ZWROb25jZTtcclxuICAgIGlmIChcclxuICAgICAgdGhpcy5zYXZlTm9uY2VzSW5Mb2NhbFN0b3JhZ2UgJiZcclxuICAgICAgdHlwZW9mIHdpbmRvd1snbG9jYWxTdG9yYWdlJ10gIT09ICd1bmRlZmluZWQnXHJcbiAgICApIHtcclxuICAgICAgc2F2ZWROb25jZSA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdub25jZScpO1xyXG4gICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgnbm9uY2UnLGNsYWltcy5qdGkpO1xyXG4gICAgfSBlbHNlIHtcclxuICAgICAgc2F2ZWROb25jZSA9IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnbm9uY2UnKTtcclxuICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdub25jZScsY2xhaW1zLmp0aSlcclxuICAgIH1cclxuXHJcbiAgICBpZiAoQXJyYXkuaXNBcnJheShjbGFpbXMuYXVkKSkge1xyXG4gICAgICBpZiAoY2xhaW1zLmF1ZC5ldmVyeSh2ID0+IHYgIT09IHRoaXMuY2xpZW50SWQpKSB7XHJcbiAgICAgICAgY29uc3QgZXJyID0gJ1dyb25nIGF1ZGllbmNlOiAnICsgY2xhaW1zLmF1ZC5qb2luKCcsJyk7XHJcbiAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xyXG4gICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xyXG4gICAgICB9XHJcbiAgICB9IGVsc2Uge1xyXG4gICAgICBpZiAoY2xhaW1zLmF1ZCAhPT0gdGhpcy5jbGllbnRJZCkge1xyXG4gICAgICAgIGNvbnN0IGVyciA9ICdXcm9uZyBhdWRpZW5jZTogJyArIGNsYWltcy5hdWQ7XHJcbiAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xyXG4gICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xyXG4gICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKCFjbGFpbXMuc3ViKSB7XHJcbiAgICAgIGNvbnN0IGVyciA9ICdObyBzdWIgY2xhaW0gaW4gaWRfdG9rZW4nO1xyXG4gICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xyXG4gICAgfVxyXG5cclxuICAgIC8qIEZvciBub3csIHdlIG9ubHkgY2hlY2sgd2hldGhlciB0aGUgc3ViIGFnYWluc3RcclxuICAgICAqIHNpbGVudFJlZnJlc2hTdWJqZWN0IHdoZW4gc2Vzc2lvbkNoZWNrc0VuYWJsZWQgaXMgb25cclxuICAgICAqIFdlIHdpbGwgcmVjb25zaWRlciBpbiBhIGxhdGVyIHZlcnNpb24gdG8gZG8gdGhpc1xyXG4gICAgICogaW4gZXZlcnkgb3RoZXIgY2FzZSB0b28uXHJcbiAgICAgKi9cclxuICAgIGlmIChcclxuICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tzRW5hYmxlZCAmJlxyXG4gICAgICB0aGlzLnNpbGVudFJlZnJlc2hTdWJqZWN0ICYmXHJcbiAgICAgIHRoaXMuc2lsZW50UmVmcmVzaFN1YmplY3QgIT09IGNsYWltc1snc3ViJ11cclxuICAgICkge1xyXG4gICAgICBjb25zdCBlcnIgPVxyXG4gICAgICAgICdBZnRlciByZWZyZXNoaW5nLCB3ZSBnb3QgYW4gaWRfdG9rZW4gZm9yIGFub3RoZXIgdXNlciAoc3ViKS4gJyArXHJcbiAgICAgICAgYEV4cGVjdGVkIHN1YjogJHt0aGlzLnNpbGVudFJlZnJlc2hTdWJqZWN0fSwgcmVjZWl2ZWQgc3ViOiAke2NsYWltc1snc3ViJ119YDtcclxuXHJcbiAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcclxuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKCFjbGFpbXMuaWF0KSB7XHJcbiAgICAgIGNvbnN0IGVyciA9ICdObyBpYXQgY2xhaW0gaW4gaWRfdG9rZW4nO1xyXG4gICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICghdGhpcy5za2lwSXNzdWVyQ2hlY2sgJiYgY2xhaW1zLmlzcyAhPT0gdGhpcy5pc3N1ZXIpIHtcclxuICAgICAgY29uc3QgZXJyID0gJ1dyb25nIGlzc3VlcjogJyArIGNsYWltcy5pc3M7XHJcbiAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcclxuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XHJcbiAgICB9XHJcbiAgICAvLyBhdF9oYXNoIGlzIG5vdCBhcHBsaWNhYmxlIHRvIGF1dGhvcml6YXRpb24gY29kZSBmbG93XHJcbiAgICAvLyBhZGRyZXNzaW5nIGh0dHBzOi8vZ2l0aHViLmNvbS9tYW5mcmVkc3RleWVyL2FuZ3VsYXItb2F1dGgyLW9pZGMvaXNzdWVzLzY2MVxyXG4gICAgLy8gaS5lLiBCYXNlZCBvbiBzcGVjIHRoZSBhdF9oYXNoIGNoZWNrIGlzIG9ubHkgdHJ1ZSBmb3IgaW1wbGljaXQgY29kZSBmbG93IG9uIFBpbmcgRmVkZXJhdGVcclxuICAgIC8vIGh0dHBzOi8vd3d3LnBpbmdpZGVudGl0eS5jb20vZGV2ZWxvcGVyL2VuL3Jlc291cmNlcy9vcGVuaWQtY29ubmVjdC1kZXZlbG9wZXJzLWd1aWRlLmh0bWxcclxuICAgIGlmICh0aGlzLmhhc093blByb3BlcnR5KCdyZXNwb25zZVR5cGUnKSAmJiB0aGlzLnJlc3BvbnNlVHlwZSA9PT0gJ2NvZGUnKSB7XHJcbiAgICAgIHRoaXMuZGlzYWJsZUF0SGFzaENoZWNrID0gdHJ1ZTtcclxuICAgIH1cclxuICAgIGlmIChcclxuICAgICAgIXRoaXMuZGlzYWJsZUF0SGFzaENoZWNrICYmXHJcbiAgICAgIHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmXHJcbiAgICAgICFjbGFpbXNbJ2F0X2hhc2gnXVxyXG4gICAgKSB7XHJcbiAgICAgIGNvbnN0IGVyciA9ICdBbiBhdF9oYXNoIGlzIG5lZWRlZCEnO1xyXG4gICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xyXG4gICAgfVxyXG5cclxuICAgIGNvbnN0IG5vdyA9IERhdGUubm93KCk7XHJcbiAgICBjb25zdCBpc3N1ZWRBdE1TZWMgPSBjbGFpbXMuaWF0ICogMTAwMDtcclxuICAgIGNvbnN0IGV4cGlyZXNBdE1TZWMgPSBjbGFpbXMuZXhwICogMTAwMDtcclxuICAgIGNvbnN0IGNsb2NrU2tld0luTVNlYyA9ICh0aGlzLmNsb2NrU2tld0luU2VjIHx8IDYwMCkgKiAxMDAwO1xyXG5cclxuICAgIGlmIChcclxuICAgICAgaXNzdWVkQXRNU2VjIC0gY2xvY2tTa2V3SW5NU2VjID49IG5vdyB8fFxyXG4gICAgICBleHBpcmVzQXRNU2VjICsgY2xvY2tTa2V3SW5NU2VjIDw9IG5vd1xyXG4gICAgKSB7XHJcbiAgICAgIGNvbnN0IGVyciA9ICdUb2tlbiBoYXMgZXhwaXJlZCc7XHJcbiAgICAgIGNvbnNvbGUuZXJyb3IoZXJyKTtcclxuICAgICAgY29uc29sZS5lcnJvcih7XHJcbiAgICAgICAgbm93OiBub3csXHJcbiAgICAgICAgaXNzdWVkQXRNU2VjOiBpc3N1ZWRBdE1TZWMsXHJcbiAgICAgICAgZXhwaXJlc0F0TVNlYzogZXhwaXJlc0F0TVNlY1xyXG4gICAgICB9KTtcclxuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3QgdmFsaWRhdGlvblBhcmFtczogVmFsaWRhdGlvblBhcmFtcyA9IHtcclxuICAgICAgYWNjZXNzVG9rZW46IGFjY2Vzc1Rva2VuLFxyXG4gICAgICBpZFRva2VuOiBpZFRva2VuLFxyXG4gICAgICBqd2tzOiB0aGlzLmp3a3MsXHJcbiAgICAgIGlkVG9rZW5DbGFpbXM6IGNsYWltcyxcclxuICAgICAgaWRUb2tlbkhlYWRlcjogaGVhZGVyLFxyXG4gICAgICBsb2FkS2V5czogKCkgPT4gdGhpcy5sb2FkSndrcygpXHJcbiAgICB9O1xyXG5cclxuICAgIGlmICh0aGlzLmRpc2FibGVBdEhhc2hDaGVjaykge1xyXG4gICAgICByZXR1cm4gdGhpcy5jaGVja1NpZ25hdHVyZSh2YWxpZGF0aW9uUGFyYW1zKS50aGVuKF8gPT4ge1xyXG4gICAgICAgIGNvbnN0IHJlc3VsdDogUGFyc2VkSWRUb2tlbiA9IHtcclxuICAgICAgICAgIGlkVG9rZW46IGlkVG9rZW4sXHJcbiAgICAgICAgICBpZFRva2VuQ2xhaW1zOiBjbGFpbXMsXHJcbiAgICAgICAgICBpZFRva2VuQ2xhaW1zSnNvbjogY2xhaW1zSnNvbixcclxuICAgICAgICAgIGlkVG9rZW5IZWFkZXI6IGhlYWRlcixcclxuICAgICAgICAgIGlkVG9rZW5IZWFkZXJKc29uOiBoZWFkZXJKc29uLFxyXG4gICAgICAgICAgaWRUb2tlbkV4cGlyZXNBdDogZXhwaXJlc0F0TVNlY1xyXG4gICAgICAgIH07XHJcbiAgICAgICAgcmV0dXJuIHJlc3VsdDtcclxuICAgICAgfSk7XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIHRoaXMuY2hlY2tBdEhhc2godmFsaWRhdGlvblBhcmFtcykudGhlbihhdEhhc2hWYWxpZCA9PiB7XHJcbiAgICAgIGlmICghdGhpcy5kaXNhYmxlQXRIYXNoQ2hlY2sgJiYgdGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4gJiYgIWF0SGFzaFZhbGlkKSB7XHJcbiAgICAgICAgY29uc3QgZXJyID0gJ1dyb25nIGF0X2hhc2gnO1xyXG4gICAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcclxuICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcclxuICAgICAgfVxyXG5cclxuICAgICAgcmV0dXJuIHRoaXMuY2hlY2tTaWduYXR1cmUodmFsaWRhdGlvblBhcmFtcykudGhlbihfID0+IHtcclxuICAgICAgICBjb25zdCBhdEhhc2hDaGVja0VuYWJsZWQgPSAhdGhpcy5kaXNhYmxlQXRIYXNoQ2hlY2s7XHJcbiAgICAgICAgY29uc3QgcmVzdWx0OiBQYXJzZWRJZFRva2VuID0ge1xyXG4gICAgICAgICAgaWRUb2tlbjogaWRUb2tlbixcclxuICAgICAgICAgIGlkVG9rZW5DbGFpbXM6IGNsYWltcyxcclxuICAgICAgICAgIGlkVG9rZW5DbGFpbXNKc29uOiBjbGFpbXNKc29uLFxyXG4gICAgICAgICAgaWRUb2tlbkhlYWRlcjogaGVhZGVyLFxyXG4gICAgICAgICAgaWRUb2tlbkhlYWRlckpzb246IGhlYWRlckpzb24sXHJcbiAgICAgICAgICBpZFRva2VuRXhwaXJlc0F0OiBleHBpcmVzQXRNU2VjXHJcbiAgICAgICAgfTtcclxuICAgICAgICBpZiAoYXRIYXNoQ2hlY2tFbmFibGVkKSB7XHJcbiAgICAgICAgICByZXR1cm4gdGhpcy5jaGVja0F0SGFzaCh2YWxpZGF0aW9uUGFyYW1zKS50aGVuKGF0SGFzaFZhbGlkID0+IHtcclxuICAgICAgICAgICAgaWYgKHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmICFhdEhhc2hWYWxpZCkge1xyXG4gICAgICAgICAgICAgIGNvbnN0IGVyciA9ICdXcm9uZyBhdF9oYXNoJztcclxuICAgICAgICAgICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XHJcbiAgICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XHJcbiAgICAgICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICAgICAgcmV0dXJuIHJlc3VsdDtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgfSk7XHJcbiAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgIHJldHVybiByZXN1bHQ7XHJcbiAgICAgICAgfVxyXG4gICAgICB9KTtcclxuICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogUmV0dXJucyB0aGUgcmVjZWl2ZWQgY2xhaW1zIGFib3V0IHRoZSB1c2VyLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBnZXRJZGVudGl0eUNsYWltcygpOiBvYmplY3Qge1xyXG4gICAgY29uc3QgY2xhaW1zID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdpZF90b2tlbl9jbGFpbXNfb2JqJyk7XHJcbiAgICBpZiAoIWNsYWltcykge1xyXG4gICAgICByZXR1cm4gbnVsbDtcclxuICAgIH1cclxuICAgIHJldHVybiBKU09OLnBhcnNlKGNsYWltcyk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBSZXR1cm5zIHRoZSBncmFudGVkIHNjb3BlcyBmcm9tIHRoZSBzZXJ2ZXIuXHJcbiAgICovXHJcbiAgcHVibGljIGdldEdyYW50ZWRTY29wZXMoKTogb2JqZWN0IHtcclxuICAgIGNvbnN0IHNjb3BlcyA9IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnZ3JhbnRlZF9zY29wZXMnKTtcclxuICAgIGlmICghc2NvcGVzKSB7XHJcbiAgICAgIHJldHVybiBudWxsO1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIEpTT04ucGFyc2Uoc2NvcGVzKTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFJldHVybnMgdGhlIGN1cnJlbnQgaWRfdG9rZW4uXHJcbiAgICovXHJcbiAgcHVibGljIGdldElkVG9rZW4oKTogc3RyaW5nIHtcclxuICAgIHJldHVybiB0aGlzLl9zdG9yYWdlID8gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdpZF90b2tlbicpIDogbnVsbDtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBwYWRCYXNlNjQoYmFzZTY0ZGF0YSk6IHN0cmluZyB7XHJcbiAgICB3aGlsZSAoYmFzZTY0ZGF0YS5sZW5ndGggJSA0ICE9PSAwKSB7XHJcbiAgICAgIGJhc2U2NGRhdGEgKz0gJz0nO1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIGJhc2U2NGRhdGE7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBSZXR1cm5zIHRoZSBjdXJyZW50IGFjY2Vzc190b2tlbi5cclxuICAgKi9cclxuICBwdWJsaWMgZ2V0QWNjZXNzVG9rZW4oKTogc3RyaW5nIHtcclxuICAgIHJldHVybiB0aGlzLl9zdG9yYWdlID8gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdhY2Nlc3NfdG9rZW4nKSA6IG51bGw7XHJcbiAgfVxyXG5cclxuICBwdWJsaWMgZ2V0UmVmcmVzaFRva2VuKCk6IHN0cmluZyB7XHJcbiAgICByZXR1cm4gdGhpcy5fc3RvcmFnZSA/IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgncmVmcmVzaF90b2tlbicpIDogbnVsbDtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFJldHVybnMgdGhlIGV4cGlyYXRpb24gZGF0ZSBvZiB0aGUgYWNjZXNzX3Rva2VuXHJcbiAgICogYXMgbWlsbGlzZWNvbmRzIHNpbmNlIDE5NzAuXHJcbiAgICovXHJcbiAgcHVibGljIGdldEFjY2Vzc1Rva2VuRXhwaXJhdGlvbigpOiBudW1iZXIge1xyXG4gICAgaWYgKCF0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2V4cGlyZXNfYXQnKSkge1xyXG4gICAgICByZXR1cm4gbnVsbDtcclxuICAgIH1cclxuICAgIHJldHVybiBwYXJzZUludCh0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2V4cGlyZXNfYXQnKSwgMTApO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGdldEFjY2Vzc1Rva2VuU3RvcmVkQXQoKTogbnVtYmVyIHtcclxuICAgIHJldHVybiBwYXJzZUludCh0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2FjY2Vzc190b2tlbl9zdG9yZWRfYXQnKSwgMTApO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGdldElkVG9rZW5TdG9yZWRBdCgpOiBudW1iZXIge1xyXG4gICAgcmV0dXJuIHBhcnNlSW50KHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnaWRfdG9rZW5fc3RvcmVkX2F0JyksIDEwKTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFJldHVybnMgdGhlIGV4cGlyYXRpb24gZGF0ZSBvZiB0aGUgaWRfdG9rZW5cclxuICAgKiBhcyBtaWxsaXNlY29uZHMgc2luY2UgMTk3MC5cclxuICAgKi9cclxuICBwdWJsaWMgZ2V0SWRUb2tlbkV4cGlyYXRpb24oKTogbnVtYmVyIHtcclxuICAgIGlmICghdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdpZF90b2tlbl9leHBpcmVzX2F0JykpIHtcclxuICAgICAgcmV0dXJuIG51bGw7XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIHBhcnNlSW50KHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnaWRfdG9rZW5fZXhwaXJlc19hdCcpLCAxMCk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBDaGVja2VzLCB3aGV0aGVyIHRoZXJlIGlzIGEgdmFsaWQgYWNjZXNzX3Rva2VuLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBoYXNWYWxpZEFjY2Vzc1Rva2VuKCk6IGJvb2xlYW4ge1xyXG4gICAgaWYgKHRoaXMuZ2V0QWNjZXNzVG9rZW4oKSkge1xyXG4gICAgICBjb25zdCBleHBpcmVzQXQgPSB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2V4cGlyZXNfYXQnKTtcclxuICAgICAgY29uc3Qgbm93ID0gbmV3IERhdGUoKTtcclxuICAgICAgaWYgKGV4cGlyZXNBdCAmJiBwYXJzZUludChleHBpcmVzQXQsIDEwKSA8IG5vdy5nZXRUaW1lKCkpIHtcclxuICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiBmYWxzZTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIENoZWNrcyB3aGV0aGVyIHRoZXJlIGlzIGEgdmFsaWQgaWRfdG9rZW4uXHJcbiAgICovXHJcbiAgcHVibGljIGhhc1ZhbGlkSWRUb2tlbigpOiBib29sZWFuIHtcclxuICAgIGlmICh0aGlzLmdldElkVG9rZW4oKSkge1xyXG4gICAgICBjb25zdCBleHBpcmVzQXQgPSB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2lkX3Rva2VuX2V4cGlyZXNfYXQnKTtcclxuICAgICAgY29uc3Qgbm93ID0gbmV3IERhdGUoKTtcclxuICAgICAgaWYgKGV4cGlyZXNBdCAmJiBwYXJzZUludChleHBpcmVzQXQsIDEwKSA8IG5vdy5nZXRUaW1lKCkpIHtcclxuICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiBmYWxzZTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFJldHJpZXZlIGEgc2F2ZWQgY3VzdG9tIHByb3BlcnR5IG9mIHRoZSBUb2tlblJlcG9uc2Ugb2JqZWN0LiBPbmx5IGlmIHByZWRlZmluZWQgaW4gYXV0aGNvbmZpZy5cclxuICAgKi9cclxuICBwdWJsaWMgZ2V0Q3VzdG9tVG9rZW5SZXNwb25zZVByb3BlcnR5KHJlcXVlc3RlZFByb3BlcnR5OiBzdHJpbmcpOiBhbnkge1xyXG4gICAgcmV0dXJuIHRoaXMuX3N0b3JhZ2UgJiZcclxuICAgICAgdGhpcy5jb25maWcuY3VzdG9tVG9rZW5QYXJhbWV0ZXJzICYmXHJcbiAgICAgIHRoaXMuY29uZmlnLmN1c3RvbVRva2VuUGFyYW1ldGVycy5pbmRleE9mKHJlcXVlc3RlZFByb3BlcnR5KSA+PSAwICYmXHJcbiAgICAgIHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbShyZXF1ZXN0ZWRQcm9wZXJ0eSkgIT09IG51bGxcclxuICAgICAgPyBKU09OLnBhcnNlKHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbShyZXF1ZXN0ZWRQcm9wZXJ0eSkpXHJcbiAgICAgIDogbnVsbDtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFJldHVybnMgdGhlIGF1dGgtaGVhZGVyIHRoYXQgY2FuIGJlIHVzZWRcclxuICAgKiB0byB0cmFuc21pdCB0aGUgYWNjZXNzX3Rva2VuIHRvIGEgc2VydmljZVxyXG4gICAqL1xyXG4gIHB1YmxpYyBhdXRob3JpemF0aW9uSGVhZGVyKCk6IHN0cmluZyB7XHJcbiAgICByZXR1cm4gJ0JlYXJlciAnICsgdGhpcy5nZXRBY2Nlc3NUb2tlbigpO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogUmVtb3ZlcyBhbGwgdG9rZW5zIGFuZCBsb2dzIHRoZSB1c2VyIG91dC5cclxuICAgKiBJZiBhIGxvZ291dCB1cmwgaXMgY29uZmlndXJlZCwgdGhlIHVzZXIgaXNcclxuICAgKiByZWRpcmVjdGVkIHRvIGl0IHdpdGggb3B0aW9uYWwgc3RhdGUgcGFyYW1ldGVyLlxyXG4gICAqIEBwYXJhbSBub1JlZGlyZWN0VG9Mb2dvdXRVcmxcclxuICAgKiBAcGFyYW0gc3RhdGVcclxuICAgKi9cclxuICBwdWJsaWMgbG9nT3V0KG5vUmVkaXJlY3RUb0xvZ291dFVybCA9IGZhbHNlLCBzdGF0ZSA9ICcnKTogdm9pZCB7XHJcbiAgICBjb25zdCBpZF90b2tlbiA9IHRoaXMuZ2V0SWRUb2tlbigpO1xyXG4gICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdhY2Nlc3NfdG9rZW4nKTtcclxuICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnaWRfdG9rZW4nKTtcclxuICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgncmVmcmVzaF90b2tlbicpO1xyXG5cclxuICAgIGlmICh0aGlzLnNhdmVOb25jZXNJbkxvY2FsU3RvcmFnZSkge1xyXG4gICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgnbm9uY2UnKTtcclxuICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oJ1BLQ0lfdmVyaWZpZXInKTtcclxuICAgIH0gZWxzZSB7XHJcbiAgICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnbm9uY2UnKTtcclxuICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdQS0NJX3ZlcmlmaWVyJyk7XHJcbiAgICB9XHJcblxyXG4gICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdleHBpcmVzX2F0Jyk7XHJcbiAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2lkX3Rva2VuX2NsYWltc19vYmonKTtcclxuICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnaWRfdG9rZW5fZXhwaXJlc19hdCcpO1xyXG4gICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdpZF90b2tlbl9zdG9yZWRfYXQnKTtcclxuICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnYWNjZXNzX3Rva2VuX3N0b3JlZF9hdCcpO1xyXG4gICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdncmFudGVkX3Njb3BlcycpO1xyXG4gICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdzZXNzaW9uX3N0YXRlJyk7XHJcbiAgICBpZiAodGhpcy5jb25maWcuY3VzdG9tVG9rZW5QYXJhbWV0ZXJzKSB7XHJcbiAgICAgIHRoaXMuY29uZmlnLmN1c3RvbVRva2VuUGFyYW1ldGVycy5mb3JFYWNoKGN1c3RvbVBhcmFtID0+XHJcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKGN1c3RvbVBhcmFtKVxyXG4gICAgICApO1xyXG4gICAgfVxyXG4gICAgdGhpcy5zaWxlbnRSZWZyZXNoU3ViamVjdCA9IG51bGw7XHJcblxyXG4gICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoSW5mb0V2ZW50KCdsb2dvdXQnKSk7XHJcblxyXG4gICAgaWYgKCF0aGlzLmxvZ291dFVybCkge1xyXG4gICAgICByZXR1cm47XHJcbiAgICB9XHJcbiAgICBpZiAobm9SZWRpcmVjdFRvTG9nb3V0VXJsKSB7XHJcbiAgICAgIHJldHVybjtcclxuICAgIH1cclxuXHJcbiAgICBpZiAoIWlkX3Rva2VuICYmICF0aGlzLnBvc3RMb2dvdXRSZWRpcmVjdFVyaSkge1xyXG4gICAgICByZXR1cm47XHJcbiAgICB9XHJcblxyXG4gICAgbGV0IGxvZ291dFVybDogc3RyaW5nO1xyXG5cclxuICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHRoaXMubG9nb3V0VXJsKSkge1xyXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXHJcbiAgICAgICAgXCJsb2dvdXRVcmwgIG11c3QgdXNlIEhUVFBTICh3aXRoIFRMUyksIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgJ3JlcXVpcmVIdHRwcycgbXVzdCBiZSBzZXQgdG8gJ2ZhbHNlJyBhbmQgYWxsb3cgSFRUUCAod2l0aG91dCBUTFMpLlwiXHJcbiAgICAgICk7XHJcbiAgICB9XHJcblxyXG4gICAgLy8gRm9yIGJhY2t3YXJkIGNvbXBhdGliaWxpdHlcclxuICAgIGlmICh0aGlzLmxvZ291dFVybC5pbmRleE9mKCd7eycpID4gLTEpIHtcclxuICAgICAgbG9nb3V0VXJsID0gdGhpcy5sb2dvdXRVcmxcclxuICAgICAgICAucmVwbGFjZSgvXFx7XFx7aWRfdG9rZW5cXH1cXH0vLCBpZF90b2tlbilcclxuICAgICAgICAucmVwbGFjZSgvXFx7XFx7Y2xpZW50X2lkXFx9XFx9LywgdGhpcy5jbGllbnRJZCk7XHJcbiAgICB9IGVsc2Uge1xyXG4gICAgICBsZXQgcGFyYW1zID0gbmV3IEh0dHBQYXJhbXMoKTtcclxuXHJcbiAgICAgIGlmIChpZF90b2tlbikge1xyXG4gICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2lkX3Rva2VuX2hpbnQnLCBpZF90b2tlbik7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIGNvbnN0IHBvc3RMb2dvdXRVcmwgPSB0aGlzLnBvc3RMb2dvdXRSZWRpcmVjdFVyaSB8fCB0aGlzLnJlZGlyZWN0VXJpO1xyXG4gICAgICBpZiAocG9zdExvZ291dFVybCkge1xyXG4gICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ3Bvc3RfbG9nb3V0X3JlZGlyZWN0X3VyaScsIHBvc3RMb2dvdXRVcmwpO1xyXG5cclxuICAgICAgICBpZiAoc3RhdGUpIHtcclxuICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ3N0YXRlJywgc3RhdGUpO1xyXG4gICAgICAgIH1cclxuICAgICAgfVxyXG5cclxuICAgICAgbG9nb3V0VXJsID1cclxuICAgICAgICB0aGlzLmxvZ291dFVybCArXHJcbiAgICAgICAgKHRoaXMubG9nb3V0VXJsLmluZGV4T2YoJz8nKSA+IC0xID8gJyYnIDogJz8nKSArXHJcbiAgICAgICAgcGFyYW1zLnRvU3RyaW5nKCk7XHJcbiAgICB9XHJcbiAgICB0aGlzLmNvbmZpZy5vcGVuVXJpKGxvZ291dFVybCk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBAaWdub3JlXHJcbiAgICovXHJcbiAgcHVibGljIGNyZWF0ZUFuZFNhdmVOb25jZSgpOiBQcm9taXNlPHN0cmluZz4ge1xyXG4gICAgY29uc3QgdGhhdCA9IHRoaXM7XHJcbiAgICByZXR1cm4gdGhpcy5jcmVhdGVOb25jZSgpLnRoZW4oZnVuY3Rpb24obm9uY2U6IGFueSkge1xyXG4gICAgICAvLyBVc2UgbG9jYWxTdG9yYWdlIGZvciBub25jZSBpZiBwb3NzaWJsZVxyXG4gICAgICAvLyBsb2NhbFN0b3JhZ2UgaXMgdGhlIG9ubHkgc3RvcmFnZSB3aG8gc3Vydml2ZXMgYVxyXG4gICAgICAvLyByZWRpcmVjdCBpbiBBTEwgYnJvd3NlcnMgKGFsc28gSUUpXHJcbiAgICAgIC8vIE90aGVyd2llc2Ugd2UnZCBmb3JjZSB0ZWFtcyB3aG8gaGF2ZSB0byBzdXBwb3J0XHJcbiAgICAgIC8vIElFIGludG8gdXNpbmcgbG9jYWxTdG9yYWdlIGZvciBldmVyeXRoaW5nXHJcbiAgICAgIGlmIChcclxuICAgICAgICB0aGF0LnNhdmVOb25jZXNJbkxvY2FsU3RvcmFnZSAmJlxyXG4gICAgICAgIHR5cGVvZiB3aW5kb3dbJ2xvY2FsU3RvcmFnZSddICE9PSAndW5kZWZpbmVkJ1xyXG4gICAgICApIHtcclxuICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgnbm9uY2UnLCBub25jZSk7XHJcbiAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgdGhhdC5fc3RvcmFnZS5zZXRJdGVtKCdub25jZScsIG5vbmNlKTtcclxuICAgICAgfVxyXG4gICAgICByZXR1cm4gbm9uY2U7XHJcbiAgICB9KTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIEBpZ25vcmVcclxuICAgKi9cclxuICBwdWJsaWMgbmdPbkRlc3Ryb3koKTogdm9pZCB7XHJcbiAgICB0aGlzLmNsZWFyQWNjZXNzVG9rZW5UaW1lcigpO1xyXG4gICAgdGhpcy5jbGVhcklkVG9rZW5UaW1lcigpO1xyXG5cclxuICAgIHRoaXMucmVtb3ZlU2lsZW50UmVmcmVzaEV2ZW50TGlzdGVuZXIoKTtcclxuICAgIGNvbnN0IHNpbGVudFJlZnJlc2hGcmFtZSA9IHRoaXMuZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXHJcbiAgICAgIHRoaXMuc2lsZW50UmVmcmVzaElGcmFtZU5hbWVcclxuICAgICk7XHJcbiAgICBpZiAoc2lsZW50UmVmcmVzaEZyYW1lKSB7XHJcbiAgICAgIHNpbGVudFJlZnJlc2hGcmFtZS5yZW1vdmUoKTtcclxuICAgIH1cclxuXHJcbiAgICB0aGlzLnN0b3BTZXNzaW9uQ2hlY2tUaW1lcigpO1xyXG4gICAgdGhpcy5yZW1vdmVTZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKCk7XHJcbiAgICBjb25zdCBzZXNzaW9uQ2hlY2tGcmFtZSA9IHRoaXMuZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXHJcbiAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lTmFtZVxyXG4gICAgKTtcclxuICAgIGlmIChzZXNzaW9uQ2hlY2tGcmFtZSkge1xyXG4gICAgICBzZXNzaW9uQ2hlY2tGcmFtZS5yZW1vdmUoKTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBjcmVhdGVOb25jZSgpOiBQcm9taXNlPHN0cmluZz4ge1xyXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKHJlc29sdmUgPT4ge1xyXG4gICAgICBpZiAodGhpcy5ybmdVcmwpIHtcclxuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXHJcbiAgICAgICAgICAnY3JlYXRlTm9uY2Ugd2l0aCBybmctd2ViLWFwaSBoYXMgbm90IGJlZW4gaW1wbGVtZW50ZWQgc28gZmFyJ1xyXG4gICAgICAgICk7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIC8qXHJcbiAgICAgICAqIFRoaXMgYWxwaGFiZXQgaXMgZnJvbTpcclxuICAgICAgICogaHR0cHM6Ly90b29scy5pZXRmLm9yZy9odG1sL3JmYzc2MzYjc2VjdGlvbi00LjFcclxuICAgICAgICpcclxuICAgICAgICogW0EtWl0gLyBbYS16XSAvIFswLTldIC8gXCItXCIgLyBcIi5cIiAvIFwiX1wiIC8gXCJ+XCJcclxuICAgICAgICovXHJcbiAgICAgIGNvbnN0IHVucmVzZXJ2ZWQgPVxyXG4gICAgICAgICdBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OS0uX34nO1xyXG4gICAgICBsZXQgc2l6ZSA9IDQ1O1xyXG4gICAgICBsZXQgaWQgPSAnJztcclxuXHJcbiAgICAgIGNvbnN0IGNyeXB0byA9XHJcbiAgICAgICAgdHlwZW9mIHNlbGYgPT09ICd1bmRlZmluZWQnID8gbnVsbCA6IHNlbGYuY3J5cHRvIHx8IHNlbGZbJ21zQ3J5cHRvJ107XHJcbiAgICAgIGlmIChjcnlwdG8pIHtcclxuICAgICAgICBsZXQgYnl0ZXMgPSBuZXcgVWludDhBcnJheShzaXplKTtcclxuICAgICAgICBjcnlwdG8uZ2V0UmFuZG9tVmFsdWVzKGJ5dGVzKTtcclxuXHJcbiAgICAgICAgLy8gTmVlZGVkIGZvciBJRVxyXG4gICAgICAgIGlmICghYnl0ZXMubWFwKSB7XHJcbiAgICAgICAgICAoYnl0ZXMgYXMgYW55KS5tYXAgPSBBcnJheS5wcm90b3R5cGUubWFwO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgYnl0ZXMgPSBieXRlcy5tYXAoeCA9PiB1bnJlc2VydmVkLmNoYXJDb2RlQXQoeCAlIHVucmVzZXJ2ZWQubGVuZ3RoKSk7XHJcbiAgICAgICAgaWQgPSBTdHJpbmcuZnJvbUNoYXJDb2RlLmFwcGx5KG51bGwsIGJ5dGVzKTtcclxuICAgICAgfSBlbHNlIHtcclxuICAgICAgICB3aGlsZSAoMCA8IHNpemUtLSkge1xyXG4gICAgICAgICAgaWQgKz0gdW5yZXNlcnZlZFsoTWF0aC5yYW5kb20oKSAqIHVucmVzZXJ2ZWQubGVuZ3RoKSB8IDBdO1xyXG4gICAgICAgIH1cclxuICAgICAgfVxyXG5cclxuICAgICAgcmVzb2x2ZShiYXNlNjRVcmxFbmNvZGUoaWQpKTtcclxuICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGFzeW5jIGNoZWNrQXRIYXNoKHBhcmFtczogVmFsaWRhdGlvblBhcmFtcyk6IFByb21pc2U8Ym9vbGVhbj4ge1xyXG4gICAgaWYgKCF0aGlzLnRva2VuVmFsaWRhdGlvbkhhbmRsZXIpIHtcclxuICAgICAgdGhpcy5sb2dnZXIud2FybihcclxuICAgICAgICAnTm8gdG9rZW5WYWxpZGF0aW9uSGFuZGxlciBjb25maWd1cmVkLiBDYW5ub3QgY2hlY2sgYXRfaGFzaC4nXHJcbiAgICAgICk7XHJcbiAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIHRoaXMudG9rZW5WYWxpZGF0aW9uSGFuZGxlci52YWxpZGF0ZUF0SGFzaChwYXJhbXMpO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGNoZWNrU2lnbmF0dXJlKHBhcmFtczogVmFsaWRhdGlvblBhcmFtcyk6IFByb21pc2U8YW55PiB7XHJcbiAgICBpZiAoIXRoaXMudG9rZW5WYWxpZGF0aW9uSGFuZGxlcikge1xyXG4gICAgICB0aGlzLmxvZ2dlci53YXJuKFxyXG4gICAgICAgICdObyB0b2tlblZhbGlkYXRpb25IYW5kbGVyIGNvbmZpZ3VyZWQuIENhbm5vdCBjaGVjayBzaWduYXR1cmUuJ1xyXG4gICAgICApO1xyXG4gICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKG51bGwpO1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIHRoaXMudG9rZW5WYWxpZGF0aW9uSGFuZGxlci52YWxpZGF0ZVNpZ25hdHVyZShwYXJhbXMpO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogU3RhcnQgdGhlIGltcGxpY2l0IGZsb3cgb3IgdGhlIGNvZGUgZmxvdyxcclxuICAgKiBkZXBlbmRpbmcgb24geW91ciBjb25maWd1cmF0aW9uLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBpbml0TG9naW5GbG93KGFkZGl0aW9uYWxTdGF0ZSA9ICcnLCBwYXJhbXMgPSB7fSk6IHZvaWQge1xyXG4gICAgaWYgKHRoaXMucmVzcG9uc2VUeXBlID09PSAnY29kZScpIHtcclxuICAgICAgcmV0dXJuIHRoaXMuaW5pdENvZGVGbG93KGFkZGl0aW9uYWxTdGF0ZSwgcGFyYW1zKTtcclxuICAgIH0gZWxzZSB7XHJcbiAgICAgIHJldHVybiB0aGlzLmluaXRJbXBsaWNpdEZsb3coYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogU3RhcnRzIHRoZSBhdXRob3JpemF0aW9uIGNvZGUgZmxvdyBhbmQgcmVkaXJlY3RzIHRvIHVzZXIgdG9cclxuICAgKiB0aGUgYXV0aCBzZXJ2ZXJzIGxvZ2luIHVybC5cclxuICAgKi9cclxuICBwdWJsaWMgaW5pdENvZGVGbG93KGFkZGl0aW9uYWxTdGF0ZSA9ICcnLCBwYXJhbXMgPSB7fSk6IHZvaWQge1xyXG4gICAgaWYgKHRoaXMubG9naW5VcmwgIT09ICcnKSB7XHJcbiAgICAgIHRoaXMuaW5pdENvZGVGbG93SW50ZXJuYWwoYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpO1xyXG4gICAgfSBlbHNlIHtcclxuICAgICAgdGhpcy5ldmVudHNcclxuICAgICAgICAucGlwZShmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZGVkJykpXHJcbiAgICAgICAgLnN1YnNjcmliZShfID0+IHRoaXMuaW5pdENvZGVGbG93SW50ZXJuYWwoYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpKTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIHByaXZhdGUgaW5pdENvZGVGbG93SW50ZXJuYWwoYWRkaXRpb25hbFN0YXRlID0gJycsIHBhcmFtcyA9IHt9KTogdm9pZCB7XHJcbiAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh0aGlzLmxvZ2luVXJsKSkge1xyXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXHJcbiAgICAgICAgXCJsb2dpblVybCAgbXVzdCB1c2UgSFRUUFMgKHdpdGggVExTKSwgb3IgY29uZmlnIHZhbHVlIGZvciBwcm9wZXJ0eSAncmVxdWlyZUh0dHBzJyBtdXN0IGJlIHNldCB0byAnZmFsc2UnIGFuZCBhbGxvdyBIVFRQICh3aXRob3V0IFRMUykuXCJcclxuICAgICAgKTtcclxuICAgIH1cclxuXHJcbiAgICB0aGlzLmNyZWF0ZUxvZ2luVXJsKGFkZGl0aW9uYWxTdGF0ZSwgJycsIG51bGwsIGZhbHNlLCBwYXJhbXMpXHJcbiAgICAgIC50aGVuKHRoaXMuY29uZmlnLm9wZW5VcmkpXHJcbiAgICAgIC5jYXRjaChlcnJvciA9PiB7XHJcbiAgICAgICAgY29uc29sZS5lcnJvcignRXJyb3IgaW4gaW5pdEF1dGhvcml6YXRpb25Db2RlRmxvdycpO1xyXG4gICAgICAgIGNvbnNvbGUuZXJyb3IoZXJyb3IpO1xyXG4gICAgICB9KTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBhc3luYyBjcmVhdGVDaGFsbGFuZ2VWZXJpZmllclBhaXJGb3JQS0NFKCk6IFByb21pc2U8XHJcbiAgICBbc3RyaW5nLCBzdHJpbmddXHJcbiAgPiB7XHJcbiAgICBpZiAoIXRoaXMuY3J5cHRvKSB7XHJcbiAgICAgIHRocm93IG5ldyBFcnJvcihcclxuICAgICAgICAnUEtDRSBzdXBwb3J0IGZvciBjb2RlIGZsb3cgbmVlZHMgYSBDcnlwdG9IYW5kZXIuIERpZCB5b3UgaW1wb3J0IHRoZSBPQXV0aE1vZHVsZSB1c2luZyBmb3JSb290KCkgPydcclxuICAgICAgKTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCB2ZXJpZmllciA9IGF3YWl0IHRoaXMuY3JlYXRlTm9uY2UoKTtcclxuICAgIGNvbnN0IGNoYWxsZW5nZVJhdyA9IGF3YWl0IHRoaXMuY3J5cHRvLmNhbGNIYXNoKHZlcmlmaWVyLCAnc2hhLTI1NicpO1xyXG4gICAgY29uc3QgY2hhbGxlbmdlID0gYmFzZTY0VXJsRW5jb2RlKGNoYWxsZW5nZVJhdyk7XHJcblxyXG4gICAgcmV0dXJuIFtjaGFsbGVuZ2UsIHZlcmlmaWVyXTtcclxuICB9XHJcblxyXG4gIHByaXZhdGUgZXh0cmFjdFJlY29nbml6ZWRDdXN0b21QYXJhbWV0ZXJzKFxyXG4gICAgdG9rZW5SZXNwb25zZTogVG9rZW5SZXNwb25zZVxyXG4gICk6IE1hcDxzdHJpbmcsIHN0cmluZz4ge1xyXG4gICAgbGV0IGZvdW5kUGFyYW1ldGVyczogTWFwPHN0cmluZywgc3RyaW5nPiA9IG5ldyBNYXA8c3RyaW5nLCBzdHJpbmc+KCk7XHJcbiAgICBpZiAoIXRoaXMuY29uZmlnLmN1c3RvbVRva2VuUGFyYW1ldGVycykge1xyXG4gICAgICByZXR1cm4gZm91bmRQYXJhbWV0ZXJzO1xyXG4gICAgfVxyXG4gICAgdGhpcy5jb25maWcuY3VzdG9tVG9rZW5QYXJhbWV0ZXJzLmZvckVhY2goKHJlY29nbml6ZWRQYXJhbWV0ZXI6IHN0cmluZykgPT4ge1xyXG4gICAgICBpZiAodG9rZW5SZXNwb25zZVtyZWNvZ25pemVkUGFyYW1ldGVyXSkge1xyXG4gICAgICAgIGZvdW5kUGFyYW1ldGVycy5zZXQoXHJcbiAgICAgICAgICByZWNvZ25pemVkUGFyYW1ldGVyLFxyXG4gICAgICAgICAgSlNPTi5zdHJpbmdpZnkodG9rZW5SZXNwb25zZVtyZWNvZ25pemVkUGFyYW1ldGVyXSlcclxuICAgICAgICApO1xyXG4gICAgICB9XHJcbiAgICB9KTtcclxuICAgIHJldHVybiBmb3VuZFBhcmFtZXRlcnM7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBSZXZva2VzIHRoZSBhdXRoIHRva2VuIHRvIHNlY3VyZSB0aGUgdnVsbmFyYWJpbGl0eVxyXG4gICAqIG9mIHRoZSB0b2tlbiBpc3N1ZWQgYWxsb3dpbmcgdGhlIGF1dGhvcml6YXRpb24gc2VydmVyIHRvIGNsZWFuXHJcbiAgICogdXAgYW55IHNlY3VyaXR5IGNyZWRlbnRpYWxzIGFzc29jaWF0ZWQgd2l0aCB0aGUgYXV0aG9yaXphdGlvblxyXG4gICAqL1xyXG4gIHB1YmxpYyByZXZva2VUb2tlbkFuZExvZ291dCgpOiBQcm9taXNlPGFueT4ge1xyXG4gICAgbGV0IHJldm9rZUVuZHBvaW50ID0gdGhpcy5yZXZvY2F0aW9uRW5kcG9pbnQ7XHJcbiAgICBsZXQgYWNjZXNzVG9rZW4gPSB0aGlzLmdldEFjY2Vzc1Rva2VuKCk7XHJcbiAgICBsZXQgcmVmcmVzaFRva2VuID0gdGhpcy5nZXRSZWZyZXNoVG9rZW4oKTtcclxuXHJcbiAgICBpZiAoIWFjY2Vzc1Rva2VuKSB7XHJcbiAgICAgIHJldHVybjtcclxuICAgIH1cclxuXHJcbiAgICBsZXQgcGFyYW1zID0gbmV3IEh0dHBQYXJhbXMoKTtcclxuXHJcbiAgICBsZXQgaGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpLnNldChcclxuICAgICAgJ0NvbnRlbnQtVHlwZScsXHJcbiAgICAgICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnXHJcbiAgICApO1xyXG5cclxuICAgIGlmICh0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcclxuICAgICAgY29uc3QgaGVhZGVyID0gYnRvYShgJHt0aGlzLmNsaWVudElkfToke3RoaXMuZHVtbXlDbGllbnRTZWNyZXR9YCk7XHJcbiAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldCgnQXV0aG9yaXphdGlvbicsICdCYXNpYyAnICsgaGVhZGVyKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCkge1xyXG4gICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdjbGllbnRfaWQnLCB0aGlzLmNsaWVudElkKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCAmJiB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KSB7XHJcbiAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9zZWNyZXQnLCB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAodGhpcy5jdXN0b21RdWVyeVBhcmFtcykge1xyXG4gICAgICBmb3IgKGNvbnN0IGtleSBvZiBPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSkge1xyXG4gICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoa2V5LCB0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zW2tleV0pO1xyXG4gICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcclxuICAgICAgbGV0IHJldm9rZUFjY2Vzc1Rva2VuOiBPYnNlcnZhYmxlPHZvaWQ+O1xyXG4gICAgICBsZXQgcmV2b2tlUmVmcmVzaFRva2VuOiBPYnNlcnZhYmxlPHZvaWQ+O1xyXG5cclxuICAgICAgaWYgKGFjY2Vzc1Rva2VuKSB7XHJcbiAgICAgICAgbGV0IHJldm9rYXRpb25QYXJhbXMgPSBwYXJhbXNcclxuICAgICAgICAgIC5zZXQoJ3Rva2VuJywgYWNjZXNzVG9rZW4pXHJcbiAgICAgICAgICAuc2V0KCd0b2tlbl90eXBlX2hpbnQnLCAnYWNjZXNzX3Rva2VuJyk7XHJcbiAgICAgICAgcmV2b2tlQWNjZXNzVG9rZW4gPSB0aGlzLmh0dHAucG9zdDx2b2lkPihcclxuICAgICAgICAgIHJldm9rZUVuZHBvaW50LFxyXG4gICAgICAgICAgcmV2b2thdGlvblBhcmFtcyxcclxuICAgICAgICAgIHsgaGVhZGVycyB9XHJcbiAgICAgICAgKTtcclxuICAgICAgfSBlbHNlIHtcclxuICAgICAgICByZXZva2VBY2Nlc3NUb2tlbiA9IG9mKG51bGwpO1xyXG4gICAgICB9XHJcblxyXG4gICAgICBpZiAocmVmcmVzaFRva2VuKSB7XHJcbiAgICAgICAgbGV0IHJldm9rYXRpb25QYXJhbXMgPSBwYXJhbXNcclxuICAgICAgICAgIC5zZXQoJ3Rva2VuJywgcmVmcmVzaFRva2VuKVxyXG4gICAgICAgICAgLnNldCgndG9rZW5fdHlwZV9oaW50JywgJ3JlZnJlc2hfdG9rZW4nKTtcclxuICAgICAgICByZXZva2VSZWZyZXNoVG9rZW4gPSB0aGlzLmh0dHAucG9zdDx2b2lkPihcclxuICAgICAgICAgIHJldm9rZUVuZHBvaW50LFxyXG4gICAgICAgICAgcmV2b2thdGlvblBhcmFtcyxcclxuICAgICAgICAgIHsgaGVhZGVycyB9XHJcbiAgICAgICAgKTtcclxuICAgICAgfSBlbHNlIHtcclxuICAgICAgICByZXZva2VSZWZyZXNoVG9rZW4gPSBvZihudWxsKTtcclxuICAgICAgfVxyXG5cclxuICAgICAgY29tYmluZUxhdGVzdChbcmV2b2tlQWNjZXNzVG9rZW4sIHJldm9rZVJlZnJlc2hUb2tlbl0pLnN1YnNjcmliZShcclxuICAgICAgICByZXMgPT4ge1xyXG4gICAgICAgICAgdGhpcy5sb2dPdXQoKTtcclxuICAgICAgICAgIHJlc29sdmUocmVzKTtcclxuICAgICAgICAgIHRoaXMubG9nZ2VyLmluZm8oJ1Rva2VuIHN1Y2Nlc3NmdWxseSByZXZva2VkJyk7XHJcbiAgICAgICAgfSxcclxuICAgICAgICBlcnIgPT4ge1xyXG4gICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ0Vycm9yIHJldm9raW5nIHRva2VuJywgZXJyKTtcclxuICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxyXG4gICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl9yZXZva2VfZXJyb3InLCBlcnIpXHJcbiAgICAgICAgICApO1xyXG4gICAgICAgICAgcmVqZWN0KGVycik7XHJcbiAgICAgICAgfVxyXG4gICAgICApO1xyXG4gICAgfSk7XHJcbiAgfVxyXG59XHJcbiJdfQ==