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
            this.setupAccessTokenTimer();
        }
        if (this.hasValidIdToken()) {
            this.setupIdTokenTimer();
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2F1dGgtc2VydmljZS5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItb2F1dGgyLW9pZGMvIiwic291cmNlcyI6WyJvYXV0aC1zZXJ2aWNlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQSxPQUFPLEVBQUUsVUFBVSxFQUFFLE1BQU0sRUFBRSxRQUFRLEVBQUUsU0FBUyxFQUFFLE1BQU0sRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUNoRixPQUFPLEVBQUUsVUFBVSxFQUFFLFdBQVcsRUFBRSxVQUFVLEVBQUUsTUFBTSxzQkFBc0IsQ0FBQztBQUMzRSxPQUFPLEVBRUwsT0FBTyxFQUVQLEVBQUUsRUFDRixJQUFJLEVBQ0osSUFBSSxFQUNKLGFBQWEsRUFDZCxNQUFNLE1BQU0sQ0FBQztBQUNkLE9BQU8sRUFDTCxNQUFNLEVBQ04sS0FBSyxFQUNMLEtBQUssRUFDTCxHQUFHLEVBQ0gsR0FBRyxFQUNILFNBQVMsRUFDVCxZQUFZLEVBQ2IsTUFBTSxnQkFBZ0IsQ0FBQztBQUN4QixPQUFPLEVBQUUsUUFBUSxFQUFFLE1BQU0saUJBQWlCLENBQUM7QUFFM0MsT0FBTyxFQUNMLGlCQUFpQixFQUNqQixnQkFBZ0IsRUFDakIsTUFBTSx1Q0FBdUMsQ0FBQztBQUMvQyxPQUFPLEVBQUUsZ0JBQWdCLEVBQUUsTUFBTSxzQkFBc0IsQ0FBQztBQUN4RCxPQUFPLEVBRUwsY0FBYyxFQUNkLGVBQWUsRUFDZixpQkFBaUIsRUFDbEIsTUFBTSxVQUFVLENBQUM7QUFDbEIsT0FBTyxFQUNMLFdBQVcsRUFDWCxZQUFZLEVBQ1osWUFBWSxFQUNaLGFBQWEsRUFDYixnQkFBZ0IsRUFDaEIsYUFBYSxFQUNiLFFBQVEsRUFDVCxNQUFNLFNBQVMsQ0FBQztBQUNqQixPQUFPLEVBQUUsZ0JBQWdCLEVBQUUsZUFBZSxFQUFFLE1BQU0saUJBQWlCLENBQUM7QUFDcEUsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUMzQyxPQUFPLEVBQUUsdUJBQXVCLEVBQUUs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QkFBM0MsTUFBTSxTQUFDLFFBQVE7O0lBN0RQLFlBQVk7UUFEeEIsVUFBVSxFQUFFO1FBd0RSLFdBQUEsUUFBUSxFQUFFLENBQUE7UUFDVixXQUFBLFFBQVEsRUFBRSxDQUFBO1FBQ1YsV0FBQSxRQUFRLEVBQUUsQ0FBQTtRQUdWLFdBQUEsUUFBUSxFQUFFLENBQUE7UUFDVixXQUFBLE1BQU0sQ0FBQyxRQUFRLENBQUMsQ0FBQTt5Q0FSQyxNQUFNO1lBQ1IsVUFBVTtZQUNMLFlBQVk7WUFDRyxpQkFBaUI7WUFDdkIsVUFBVTtZQUNuQixnQkFBZ0I7WUFDbkIsV0FBVztZQUNDLFdBQVc7WUFDTCxRQUFRO09BN0RuQyxZQUFZLENBOGhGeEI7SUFBRCxtQkFBQztDQUFBLEFBOWhGRCxDQUFrQyxVQUFVLEdBOGhGM0M7U0E5aEZZLFlBQVkiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBJbmplY3RhYmxlLCBOZ1pvbmUsIE9wdGlvbmFsLCBPbkRlc3Ryb3ksIEluamVjdCB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xyXG5pbXBvcnQgeyBIdHRwQ2xpZW50LCBIdHRwSGVhZGVycywgSHR0cFBhcmFtcyB9IGZyb20gJ0Bhbmd1bGFyL2NvbW1vbi9odHRwJztcclxuaW1wb3J0IHtcclxuICBPYnNlcnZhYmxlLFxyXG4gIFN1YmplY3QsXHJcbiAgU3Vic2NyaXB0aW9uLFxyXG4gIG9mLFxyXG4gIHJhY2UsXHJcbiAgZnJvbSxcclxuICBjb21iaW5lTGF0ZXN0XHJcbn0gZnJvbSAncnhqcyc7XHJcbmltcG9ydCB7XHJcbiAgZmlsdGVyLFxyXG4gIGRlbGF5LFxyXG4gIGZpcnN0LFxyXG4gIHRhcCxcclxuICBtYXAsXHJcbiAgc3dpdGNoTWFwLFxyXG4gIGRlYm91bmNlVGltZVxyXG59IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcclxuaW1wb3J0IHsgRE9DVU1FTlQgfSBmcm9tICdAYW5ndWxhci9jb21tb24nO1xyXG5cclxuaW1wb3J0IHtcclxuICBWYWxpZGF0aW9uSGFuZGxlcixcclxuICBWYWxpZGF0aW9uUGFyYW1zXHJcbn0gZnJvbSAnLi90b2tlbi12YWxpZGF0aW9uL3ZhbGlkYXRpb24taGFuZGxlcic7XHJcbmltcG9ydCB7IFVybEhlbHBlclNlcnZpY2UgfSBmcm9tICcuL3VybC1oZWxwZXIuc2VydmljZSc7XHJcbmltcG9ydCB7XHJcbiAgT0F1dGhFdmVudCxcclxuICBPQXV0aEluZm9FdmVudCxcclxuICBPQXV0aEVycm9yRXZlbnQsXHJcbiAgT0F1dGhTdWNjZXNzRXZlbnRcclxufSBmcm9tICcuL2V2ZW50cyc7XHJcbmltcG9ydCB7XHJcbiAgT0F1dGhMb2dnZXIsXHJcbiAgT0F1dGhTdG9yYWdlLFxyXG4gIExvZ2luT3B0aW9ucyxcclxuICBQYXJzZWRJZFRva2VuLFxyXG4gIE9pZGNEaXNjb3ZlcnlEb2MsXHJcbiAgVG9rZW5SZXNwb25zZSxcclxuICBVc2VySW5mb1xyXG59IGZyb20gJy4vdHlwZXMnO1xyXG5pbXBvcnQgeyBiNjREZWNvZGVVbmljb2RlLCBiYXNlNjRVcmxFbmNvZGUgfSBmcm9tICcuL2Jhc2U2NC1oZWxwZXInO1xyXG5pbXBvcnQgeyBBdXRoQ29uZmlnIH0gZnJvbSAnLi9hdXRoLmNvbmZpZyc7XHJcbmltcG9ydCB7IFdlYkh0dHBVcmxFbmNvZGluZ0NvZGVjIH0gZnJvbSAnLi9lbmNvZGVyJztcclxuaW1wb3J0IHsgSGFzaEhhbmRsZXIgfSBmcm9tICcuL3Rva2VuLXZhbGlkYXRpb24vaGFzaC1oYW5kbGVyJztcclxuXHJcbi8qKlxyXG4gKiBTZXJ2aWNlIGZvciBsb2dnaW5nIGluIGFuZCBsb2dnaW5nIG91dCB3aXRoXHJcbiAqIE9JREMgYW5kIE9BdXRoMi4gU3VwcG9ydHMgaW1wbGljaXQgZmxvdyBhbmRcclxuICogcGFzc3dvcmQgZmxvdy5cclxuICovXHJcbkBJbmplY3RhYmxlKClcclxuZXhwb3J0IGNsYXNzIE9BdXRoU2VydmljZSBleHRlbmRzIEF1dGhDb25maWcgaW1wbGVtZW50cyBPbkRlc3Ryb3kge1xyXG4gIC8vIEV4dGVuZGluZyBBdXRoQ29uZmlnIGlzdCBqdXN0IGZvciBMRUdBQ1kgcmVhc29uc1xyXG4gIC8vIHRvIG5vdCBicmVhayBleGlzdGluZyBjb2RlLlxyXG5cclxuICAvKipcclxuICAgKiBUaGUgVmFsaWRhdGlvbkhhbmRsZXIgdXNlZCB0byB2YWxpZGF0ZSByZWNlaXZlZFxyXG4gICAqIGlkX3Rva2Vucy5cclxuICAgKi9cclxuICBwdWJsaWMgdG9rZW5WYWxpZGF0aW9uSGFuZGxlcjogVmFsaWRhdGlvbkhhbmRsZXI7XHJcblxyXG4gIC8qKlxyXG4gICAqIEBpbnRlcm5hbFxyXG4gICAqIERlcHJlY2F0ZWQ6ICB1c2UgcHJvcGVydHkgZXZlbnRzIGluc3RlYWRcclxuICAgKi9cclxuICBwdWJsaWMgZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWQgPSBmYWxzZTtcclxuXHJcbiAgLyoqXHJcbiAgICogQGludGVybmFsXHJcbiAgICogRGVwcmVjYXRlZDogIHVzZSBwcm9wZXJ0eSBldmVudHMgaW5zdGVhZFxyXG4gICAqL1xyXG4gIHB1YmxpYyBkaXNjb3ZlcnlEb2N1bWVudExvYWRlZCQ6IE9ic2VydmFibGU8T2lkY0Rpc2NvdmVyeURvYz47XHJcblxyXG4gIC8qKlxyXG4gICAqIEluZm9ybXMgYWJvdXQgZXZlbnRzLCBsaWtlIHRva2VuX3JlY2VpdmVkIG9yIHRva2VuX2V4cGlyZXMuXHJcbiAgICogU2VlIHRoZSBzdHJpbmcgZW51bSBFdmVudFR5cGUgZm9yIGEgZnVsbCBsaXN0IG9mIGV2ZW50IHR5cGVzLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBldmVudHM6IE9ic2VydmFibGU8T0F1dGhFdmVudD47XHJcblxyXG4gIC8qKlxyXG4gICAqIFRoZSByZWNlaXZlZCAocGFzc2VkIGFyb3VuZCkgc3RhdGUsIHdoZW4gbG9nZ2luZ1xyXG4gICAqIGluIHdpdGggaW1wbGljaXQgZmxvdy5cclxuICAgKi9cclxuICBwdWJsaWMgc3RhdGU/ID0gJyc7XHJcblxyXG4gIHByb3RlY3RlZCBldmVudHNTdWJqZWN0OiBTdWJqZWN0PE9BdXRoRXZlbnQ+ID0gbmV3IFN1YmplY3Q8T0F1dGhFdmVudD4oKTtcclxuICBwcm90ZWN0ZWQgZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWRTdWJqZWN0OiBTdWJqZWN0PFxyXG4gICAgT2lkY0Rpc2NvdmVyeURvY1xyXG4gID4gPSBuZXcgU3ViamVjdDxPaWRjRGlzY292ZXJ5RG9jPigpO1xyXG4gIHByb3RlY3RlZCBzaWxlbnRSZWZyZXNoUG9zdE1lc3NhZ2VFdmVudExpc3RlbmVyOiBFdmVudExpc3RlbmVyO1xyXG4gIHByb3RlY3RlZCBncmFudFR5cGVzU3VwcG9ydGVkOiBBcnJheTxzdHJpbmc+ID0gW107XHJcbiAgcHJvdGVjdGVkIF9zdG9yYWdlOiBPQXV0aFN0b3JhZ2U7XHJcbiAgcHJvdGVjdGVkIGFjY2Vzc1Rva2VuVGltZW91dFN1YnNjcmlwdGlvbjogU3Vic2NyaXB0aW9uO1xyXG4gIHByb3RlY3RlZCBpZFRva2VuVGltZW91dFN1YnNjcmlwdGlvbjogU3Vic2NyaXB0aW9uO1xyXG4gIHByb3RlY3RlZCB0b2tlblJlY2VpdmVkU3Vic2NyaXB0aW9uOiBTdWJzY3JpcHRpb247XHJcbiAgcHJvdGVjdGVkIHNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXI6IEV2ZW50TGlzdGVuZXI7XHJcbiAgcHJvdGVjdGVkIGp3a3NVcmk6IHN0cmluZztcclxuICBwcm90ZWN0ZWQgc2Vzc2lvbkNoZWNrVGltZXI6IGFueTtcclxuICBwcm90ZWN0ZWQgc2lsZW50UmVmcmVzaFN1YmplY3Q6IHN0cmluZztcclxuICBwcm90ZWN0ZWQgaW5JbXBsaWNpdEZsb3cgPSBmYWxzZTtcclxuXHJcbiAgcHJvdGVjdGVkIHNhdmVOb25jZXNJbkxvY2FsU3RvcmFnZSA9IGZhbHNlO1xyXG5cclxuICBjb25zdHJ1Y3RvcihcclxuICAgIHByb3RlY3RlZCBuZ1pvbmU6IE5nWm9uZSxcclxuICAgIHByb3RlY3RlZCBodHRwOiBIdHRwQ2xpZW50LFxyXG4gICAgQE9wdGlvbmFsKCkgc3RvcmFnZTogT0F1dGhTdG9yYWdlLFxyXG4gICAgQE9wdGlvbmFsKCkgdG9rZW5WYWxpZGF0aW9uSGFuZGxlcjogVmFsaWRhdGlvbkhhbmRsZXIsXHJcbiAgICBAT3B0aW9uYWwoKSBwcm90ZWN0ZWQgY29uZmlnOiBBdXRoQ29uZmlnLFxyXG4gICAgcHJvdGVjdGVkIHVybEhlbHBlcjogVXJsSGVscGVyU2VydmljZSxcclxuICAgIHByb3RlY3RlZCBsb2dnZXI6IE9BdXRoTG9nZ2VyLFxyXG4gICAgQE9wdGlvbmFsKCkgcHJvdGVjdGVkIGNyeXB0bzogSGFzaEhhbmRsZXIsXHJcbiAgICBASW5qZWN0KERPQ1VNRU5UKSBwcml2YXRlIGRvY3VtZW50OiBEb2N1bWVudFxyXG4gICkge1xyXG4gICAgc3VwZXIoKTtcclxuXHJcbiAgICB0aGlzLmRlYnVnKCdhbmd1bGFyLW9hdXRoMi1vaWRjIHY4LWJldGEnKTtcclxuXHJcbiAgICB0aGlzLmRpc2NvdmVyeURvY3VtZW50TG9hZGVkJCA9IHRoaXMuZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWRTdWJqZWN0LmFzT2JzZXJ2YWJsZSgpO1xyXG4gICAgdGhpcy5ldmVudHMgPSB0aGlzLmV2ZW50c1N1YmplY3QuYXNPYnNlcnZhYmxlKCk7XHJcblxyXG4gICAgaWYgKHRva2VuVmFsaWRhdGlvbkhhbmRsZXIpIHtcclxuICAgICAgdGhpcy50b2tlblZhbGlkYXRpb25IYW5kbGVyID0gdG9rZW5WYWxpZGF0aW9uSGFuZGxlcjtcclxuICAgIH1cclxuXHJcbiAgICBpZiAoY29uZmlnKSB7XHJcbiAgICAgIHRoaXMuY29uZmlndXJlKGNvbmZpZyk7XHJcbiAgICB9XHJcblxyXG4gICAgdHJ5IHtcclxuICAgICAgaWYgKHN0b3JhZ2UpIHtcclxuICAgICAgICB0aGlzLnNldFN0b3JhZ2Uoc3RvcmFnZSk7XHJcbiAgICAgIH0gZWxzZSBpZiAodHlwZW9mIHNlc3Npb25TdG9yYWdlICE9PSAndW5kZWZpbmVkJykge1xyXG4gICAgICAgIHRoaXMuc2V0U3RvcmFnZShzZXNzaW9uU3RvcmFnZSk7XHJcbiAgICAgIH1cclxuICAgIH0gY2F0Y2ggKGUpIHtcclxuICAgICAgY29uc29sZS5lcnJvcihcclxuICAgICAgICAnTm8gT0F1dGhTdG9yYWdlIHByb3ZpZGVkIGFuZCBjYW5ub3QgYWNjZXNzIGRlZmF1bHQgKHNlc3Npb25TdG9yYWdlKS4nICtcclxuICAgICAgICAgICdDb25zaWRlciBwcm92aWRpbmcgYSBjdXN0b20gT0F1dGhTdG9yYWdlIGltcGxlbWVudGF0aW9uIGluIHlvdXIgbW9kdWxlLicsXHJcbiAgICAgICAgZVxyXG4gICAgICApO1xyXG4gICAgfVxyXG5cclxuICAgIC8vIGluIElFLCBzZXNzaW9uU3RvcmFnZSBkb2VzIG5vdCBhbHdheXMgc3Vydml2ZSBhIHJlZGlyZWN0XHJcbiAgICBpZiAoXHJcbiAgICAgIHR5cGVvZiB3aW5kb3cgIT09ICd1bmRlZmluZWQnICYmXHJcbiAgICAgIHR5cGVvZiB3aW5kb3dbJ2xvY2FsU3RvcmFnZSddICE9PSAndW5kZWZpbmVkJ1xyXG4gICAgKSB7XHJcbiAgICAgIGNvbnN0IHVhID0gd2luZG93Py5uYXZpZ2F0b3I/LnVzZXJBZ2VudDtcclxuICAgICAgY29uc3QgbXNpZSA9IHVhPy5pbmNsdWRlcygnTVNJRSAnKSB8fCB1YT8uaW5jbHVkZXMoJ1RyaWRlbnQnKTtcclxuXHJcbiAgICAgIGlmIChtc2llKSB7XHJcbiAgICAgICAgdGhpcy5zYXZlTm9uY2VzSW5Mb2NhbFN0b3JhZ2UgPSB0cnVlO1xyXG4gICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgdGhpcy5zZXR1cFJlZnJlc2hUaW1lcigpO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogVXNlIHRoaXMgbWV0aG9kIHRvIGNvbmZpZ3VyZSB0aGUgc2VydmljZVxyXG4gICAqIEBwYXJhbSBjb25maWcgdGhlIGNvbmZpZ3VyYXRpb25cclxuICAgKi9cclxuICBwdWJsaWMgY29uZmlndXJlKGNvbmZpZzogQXV0aENvbmZpZyk6IHZvaWQge1xyXG4gICAgLy8gRm9yIHRoZSBzYWtlIG9mIGRvd253YXJkIGNvbXBhdGliaWxpdHkgd2l0aFxyXG4gICAgLy8gb3JpZ2luYWwgY29uZmlndXJhdGlvbiBBUElcclxuICAgIE9iamVjdC5hc3NpZ24odGhpcywgbmV3IEF1dGhDb25maWcoKSwgY29uZmlnKTtcclxuXHJcbiAgICB0aGlzLmNvbmZpZyA9IE9iamVjdC5hc3NpZ24oe30gYXMgQXV0aENvbmZpZywgbmV3IEF1dGhDb25maWcoKSwgY29uZmlnKTtcclxuXHJcbiAgICBpZiAodGhpcy5zZXNzaW9uQ2hlY2tzRW5hYmxlZCkge1xyXG4gICAgICB0aGlzLnNldHVwU2Vzc2lvbkNoZWNrKCk7XHJcbiAgICB9XHJcblxyXG4gICAgdGhpcy5jb25maWdDaGFuZ2VkKCk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgY29uZmlnQ2hhbmdlZCgpOiB2b2lkIHtcclxuICAgIHRoaXMuc2V0dXBSZWZyZXNoVGltZXIoKTtcclxuICB9XHJcblxyXG4gIHB1YmxpYyByZXN0YXJ0U2Vzc2lvbkNoZWNrc0lmU3RpbGxMb2dnZWRJbigpOiB2b2lkIHtcclxuICAgIGlmICh0aGlzLmhhc1ZhbGlkSWRUb2tlbigpKSB7XHJcbiAgICAgIHRoaXMuaW5pdFNlc3Npb25DaGVjaygpO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHJlc3RhcnRSZWZyZXNoVGltZXJJZlN0aWxsTG9nZ2VkSW4oKTogdm9pZCB7XHJcbiAgICB0aGlzLnNldHVwRXhwaXJhdGlvblRpbWVycygpO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHNldHVwU2Vzc2lvbkNoZWNrKCk6IHZvaWQge1xyXG4gICAgdGhpcy5ldmVudHMucGlwZShmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICd0b2tlbl9yZWNlaXZlZCcpKS5zdWJzY3JpYmUoZSA9PiB7XHJcbiAgICAgIHRoaXMuaW5pdFNlc3Npb25DaGVjaygpO1xyXG4gICAgfSk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBXaWxsIHNldHVwIHVwIHNpbGVudCByZWZyZXNoaW5nIGZvciB3aGVuIHRoZSB0b2tlbiBpc1xyXG4gICAqIGFib3V0IHRvIGV4cGlyZS4gV2hlbiB0aGUgdXNlciBpcyBsb2dnZWQgb3V0IHZpYSB0aGlzLmxvZ091dCBtZXRob2QsIHRoZVxyXG4gICAqIHNpbGVudCByZWZyZXNoaW5nIHdpbGwgcGF1c2UgYW5kIG5vdCByZWZyZXNoIHRoZSB0b2tlbnMgdW50aWwgdGhlIHVzZXIgaXNcclxuICAgKiBsb2dnZWQgYmFjayBpbiB2aWEgcmVjZWl2aW5nIGEgbmV3IHRva2VuLlxyXG4gICAqIEBwYXJhbSBwYXJhbXMgQWRkaXRpb25hbCBwYXJhbWV0ZXIgdG8gcGFzc1xyXG4gICAqIEBwYXJhbSBsaXN0ZW5UbyBTZXR1cCBhdXRvbWF0aWMgcmVmcmVzaCBvZiBhIHNwZWNpZmljIHRva2VuIHR5cGVcclxuICAgKi9cclxuICBwdWJsaWMgc2V0dXBBdXRvbWF0aWNTaWxlbnRSZWZyZXNoKFxyXG4gICAgcGFyYW1zOiBvYmplY3QgPSB7fSxcclxuICAgIGxpc3RlblRvPzogJ2FjY2Vzc190b2tlbicgfCAnaWRfdG9rZW4nIHwgJ2FueScsXHJcbiAgICBub1Byb21wdCA9IHRydWVcclxuICApOiB2b2lkIHtcclxuICAgIGxldCBzaG91bGRSdW5TaWxlbnRSZWZyZXNoID0gdHJ1ZTtcclxuICAgIHRoaXMuZXZlbnRzXHJcbiAgICAgIC5waXBlKFxyXG4gICAgICAgIHRhcChlID0+IHtcclxuICAgICAgICAgIGlmIChlLnR5cGUgPT09ICd0b2tlbl9yZWNlaXZlZCcpIHtcclxuICAgICAgICAgICAgc2hvdWxkUnVuU2lsZW50UmVmcmVzaCA9IHRydWU7XHJcbiAgICAgICAgICB9IGVsc2UgaWYgKGUudHlwZSA9PT0gJ2xvZ291dCcpIHtcclxuICAgICAgICAgICAgc2hvdWxkUnVuU2lsZW50UmVmcmVzaCA9IGZhbHNlO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgIH0pLFxyXG4gICAgICAgIGZpbHRlcihlID0+IGUudHlwZSA9PT0gJ3Rva2VuX2V4cGlyZXMnKSxcclxuICAgICAgICBkZWJvdW5jZVRpbWUoMTAwMClcclxuICAgICAgKVxyXG4gICAgICAuc3Vic2NyaWJlKGUgPT4ge1xyXG4gICAgICAgIGNvbnN0IGV2ZW50ID0gZSBhcyBPQXV0aEluZm9FdmVudDtcclxuICAgICAgICBpZiAoXHJcbiAgICAgICAgICAobGlzdGVuVG8gPT0gbnVsbCB8fCBsaXN0ZW5UbyA9PT0gJ2FueScgfHwgZXZlbnQuaW5mbyA9PT0gbGlzdGVuVG8pICYmXHJcbiAgICAgICAgICBzaG91bGRSdW5TaWxlbnRSZWZyZXNoXHJcbiAgICAgICAgKSB7XHJcbiAgICAgICAgICAvLyB0aGlzLnNpbGVudFJlZnJlc2gocGFyYW1zLCBub1Byb21wdCkuY2F0Y2goXyA9PiB7XHJcbiAgICAgICAgICB0aGlzLnJlZnJlc2hJbnRlcm5hbChwYXJhbXMsIG5vUHJvbXB0KS5jYXRjaChfID0+IHtcclxuICAgICAgICAgICAgdGhpcy5kZWJ1ZygnQXV0b21hdGljIHNpbGVudCByZWZyZXNoIGRpZCBub3Qgd29yaycpO1xyXG4gICAgICAgICAgfSk7XHJcbiAgICAgICAgfVxyXG4gICAgICB9KTtcclxuXHJcbiAgICB0aGlzLnJlc3RhcnRSZWZyZXNoVGltZXJJZlN0aWxsTG9nZ2VkSW4oKTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCByZWZyZXNoSW50ZXJuYWwoXHJcbiAgICBwYXJhbXMsXHJcbiAgICBub1Byb21wdFxyXG4gICk6IFByb21pc2U8VG9rZW5SZXNwb25zZSB8IE9BdXRoRXZlbnQ+IHtcclxuICAgIGlmICghdGhpcy51c2VTaWxlbnRSZWZyZXNoICYmIHRoaXMucmVzcG9uc2VUeXBlID09PSAnY29kZScpIHtcclxuICAgICAgcmV0dXJuIHRoaXMucmVmcmVzaFRva2VuKCk7XHJcbiAgICB9IGVsc2Uge1xyXG4gICAgICByZXR1cm4gdGhpcy5zaWxlbnRSZWZyZXNoKHBhcmFtcywgbm9Qcm9tcHQpO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogQ29udmVuaWVuY2UgbWV0aG9kIHRoYXQgZmlyc3QgY2FsbHMgYGxvYWREaXNjb3ZlcnlEb2N1bWVudCguLi4pYCBhbmRcclxuICAgKiBkaXJlY3RseSBjaGFpbnMgdXNpbmcgdGhlIGB0aGVuKC4uLilgIHBhcnQgb2YgdGhlIHByb21pc2UgdG8gY2FsbFxyXG4gICAqIHRoZSBgdHJ5TG9naW4oLi4uKWAgbWV0aG9kLlxyXG4gICAqXHJcbiAgICogQHBhcmFtIG9wdGlvbnMgTG9naW5PcHRpb25zIHRvIHBhc3MgdGhyb3VnaCB0byBgdHJ5TG9naW4oLi4uKWBcclxuICAgKi9cclxuICBwdWJsaWMgbG9hZERpc2NvdmVyeURvY3VtZW50QW5kVHJ5TG9naW4oXHJcbiAgICBvcHRpb25zOiBMb2dpbk9wdGlvbnMgPSBudWxsXHJcbiAgKTogUHJvbWlzZTxib29sZWFuPiB7XHJcbiAgICByZXR1cm4gdGhpcy5sb2FkRGlzY292ZXJ5RG9jdW1lbnQoKS50aGVuKGRvYyA9PiB7XHJcbiAgICAgIHJldHVybiB0aGlzLnRyeUxvZ2luKG9wdGlvbnMpO1xyXG4gICAgfSk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBDb252ZW5pZW5jZSBtZXRob2QgdGhhdCBmaXJzdCBjYWxscyBgbG9hZERpc2NvdmVyeURvY3VtZW50QW5kVHJ5TG9naW4oLi4uKWBcclxuICAgKiBhbmQgaWYgdGhlbiBjaGFpbnMgdG8gYGluaXRMb2dpbkZsb3coKWAsIGJ1dCBvbmx5IGlmIHRoZXJlIGlzIG5vIHZhbGlkXHJcbiAgICogSWRUb2tlbiBvciBubyB2YWxpZCBBY2Nlc3NUb2tlbi5cclxuICAgKlxyXG4gICAqIEBwYXJhbSBvcHRpb25zIExvZ2luT3B0aW9ucyB0byBwYXNzIHRocm91Z2ggdG8gYHRyeUxvZ2luKC4uLilgXHJcbiAgICovXHJcbiAgcHVibGljIGxvYWREaXNjb3ZlcnlEb2N1bWVudEFuZExvZ2luKFxyXG4gICAgb3B0aW9uczogTG9naW5PcHRpb25zICYgeyBzdGF0ZT86IHN0cmluZyB9ID0gbnVsbFxyXG4gICk6IFByb21pc2U8Ym9vbGVhbj4ge1xyXG4gICAgaWYgKCFvcHRpb25zKSB7XHJcbiAgICAgIG9wdGlvbnMgPSB7IHN0YXRlOiAnJyB9O1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIHRoaXMubG9hZERpc2NvdmVyeURvY3VtZW50QW5kVHJ5TG9naW4ob3B0aW9ucykudGhlbihfID0+IHtcclxuICAgICAgaWYgKCF0aGlzLmhhc1ZhbGlkSWRUb2tlbigpIHx8ICF0aGlzLmhhc1ZhbGlkQWNjZXNzVG9rZW4oKSkge1xyXG4gICAgICAgIGlmICh0aGlzLnJlc3BvbnNlVHlwZSA9PT0gJ2NvZGUnKSB7XHJcbiAgICAgICAgICB0aGlzLmluaXRDb2RlRmxvdyhvcHRpb25zLnN0YXRlKTtcclxuICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgdGhpcy5pbml0SW1wbGljaXRGbG93KG9wdGlvbnMuc3RhdGUpO1xyXG4gICAgICAgIH1cclxuICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICAgIH1cclxuICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGRlYnVnKC4uLmFyZ3MpOiB2b2lkIHtcclxuICAgIGlmICh0aGlzLnNob3dEZWJ1Z0luZm9ybWF0aW9uKSB7XHJcbiAgICAgIHRoaXMubG9nZ2VyLmRlYnVnLmFwcGx5KHRoaXMubG9nZ2VyLCBhcmdzKTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCB2YWxpZGF0ZVVybEZyb21EaXNjb3ZlcnlEb2N1bWVudCh1cmw6IHN0cmluZyk6IHN0cmluZ1tdIHtcclxuICAgIGNvbnN0IGVycm9yczogc3RyaW5nW10gPSBbXTtcclxuICAgIGNvbnN0IGh0dHBzQ2hlY2sgPSB0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModXJsKTtcclxuICAgIGNvbnN0IGlzc3VlckNoZWNrID0gdGhpcy52YWxpZGF0ZVVybEFnYWluc3RJc3N1ZXIodXJsKTtcclxuXHJcbiAgICBpZiAoIWh0dHBzQ2hlY2spIHtcclxuICAgICAgZXJyb3JzLnB1c2goXHJcbiAgICAgICAgJ2h0dHBzIGZvciBhbGwgdXJscyByZXF1aXJlZC4gQWxzbyBmb3IgdXJscyByZWNlaXZlZCBieSBkaXNjb3ZlcnkuJ1xyXG4gICAgICApO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICghaXNzdWVyQ2hlY2spIHtcclxuICAgICAgZXJyb3JzLnB1c2goXHJcbiAgICAgICAgJ0V2ZXJ5IHVybCBpbiBkaXNjb3ZlcnkgZG9jdW1lbnQgaGFzIHRvIHN0YXJ0IHdpdGggdGhlIGlzc3VlciB1cmwuJyArXHJcbiAgICAgICAgICAnQWxzbyBzZWUgcHJvcGVydHkgc3RyaWN0RGlzY292ZXJ5RG9jdW1lbnRWYWxpZGF0aW9uLidcclxuICAgICAgKTtcclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gZXJyb3JzO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHZhbGlkYXRlVXJsRm9ySHR0cHModXJsOiBzdHJpbmcpOiBib29sZWFuIHtcclxuICAgIGlmICghdXJsKSB7XHJcbiAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgfVxyXG5cclxuICAgIGNvbnN0IGxjVXJsID0gdXJsLnRvTG93ZXJDYXNlKCk7XHJcblxyXG4gICAgaWYgKHRoaXMucmVxdWlyZUh0dHBzID09PSBmYWxzZSkge1xyXG4gICAgICByZXR1cm4gdHJ1ZTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAoXHJcbiAgICAgIChsY1VybC5tYXRjaCgvXmh0dHA6XFwvXFwvbG9jYWxob3N0KCR8WzpcXC9dKS8pIHx8XHJcbiAgICAgICAgbGNVcmwubWF0Y2goL15odHRwOlxcL1xcL2xvY2FsaG9zdCgkfFs6XFwvXSkvKSkgJiZcclxuICAgICAgdGhpcy5yZXF1aXJlSHR0cHMgPT09ICdyZW1vdGVPbmx5J1xyXG4gICAgKSB7XHJcbiAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiBsY1VybC5zdGFydHNXaXRoKCdodHRwczovLycpO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGFzc2VydFVybE5vdE51bGxBbmRDb3JyZWN0UHJvdG9jb2woXHJcbiAgICB1cmw6IHN0cmluZyB8IHVuZGVmaW5lZCxcclxuICAgIGRlc2NyaXB0aW9uOiBzdHJpbmdcclxuICApIHtcclxuICAgIGlmICghdXJsKSB7XHJcbiAgICAgIHRocm93IG5ldyBFcnJvcihgJyR7ZGVzY3JpcHRpb259JyBzaG91bGQgbm90IGJlIG51bGxgKTtcclxuICAgIH1cclxuICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHVybCkpIHtcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKFxyXG4gICAgICAgIGAnJHtkZXNjcmlwdGlvbn0nIG11c3QgdXNlIEhUVFBTICh3aXRoIFRMUyksIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgJ3JlcXVpcmVIdHRwcycgbXVzdCBiZSBzZXQgdG8gJ2ZhbHNlJyBhbmQgYWxsb3cgSFRUUCAod2l0aG91dCBUTFMpLmBcclxuICAgICAgKTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCB2YWxpZGF0ZVVybEFnYWluc3RJc3N1ZXIodXJsOiBzdHJpbmcpIHtcclxuICAgIGlmICghdGhpcy5zdHJpY3REaXNjb3ZlcnlEb2N1bWVudFZhbGlkYXRpb24pIHtcclxuICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICB9XHJcbiAgICBpZiAoIXVybCkge1xyXG4gICAgICByZXR1cm4gdHJ1ZTtcclxuICAgIH1cclxuICAgIHJldHVybiB1cmwudG9Mb3dlckNhc2UoKS5zdGFydHNXaXRoKHRoaXMuaXNzdWVyLnRvTG93ZXJDYXNlKCkpO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHNldHVwUmVmcmVzaFRpbWVyKCk6IHZvaWQge1xyXG4gICAgaWYgKHR5cGVvZiB3aW5kb3cgPT09ICd1bmRlZmluZWQnKSB7XHJcbiAgICAgIHRoaXMuZGVidWcoJ3RpbWVyIG5vdCBzdXBwb3J0ZWQgb24gdGhpcyBwbGF0dGZvcm0nKTtcclxuICAgICAgcmV0dXJuO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICh0aGlzLmhhc1ZhbGlkSWRUb2tlbigpIHx8IHRoaXMuaGFzVmFsaWRBY2Nlc3NUb2tlbigpKSB7XHJcbiAgICAgIHRoaXMuY2xlYXJBY2Nlc3NUb2tlblRpbWVyKCk7XHJcbiAgICAgIHRoaXMuY2xlYXJJZFRva2VuVGltZXIoKTtcclxuICAgICAgdGhpcy5zZXR1cEV4cGlyYXRpb25UaW1lcnMoKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAodGhpcy50b2tlblJlY2VpdmVkU3Vic2NyaXB0aW9uKVxyXG4gICAgICB0aGlzLnRva2VuUmVjZWl2ZWRTdWJzY3JpcHRpb24udW5zdWJzY3JpYmUoKTtcclxuXHJcbiAgICB0aGlzLnRva2VuUmVjZWl2ZWRTdWJzY3JpcHRpb24gPSB0aGlzLmV2ZW50c1xyXG4gICAgICAucGlwZShmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICd0b2tlbl9yZWNlaXZlZCcpKVxyXG4gICAgICAuc3Vic2NyaWJlKF8gPT4ge1xyXG4gICAgICAgIHRoaXMuY2xlYXJBY2Nlc3NUb2tlblRpbWVyKCk7XHJcbiAgICAgICAgdGhpcy5jbGVhcklkVG9rZW5UaW1lcigpO1xyXG4gICAgICAgIHRoaXMuc2V0dXBFeHBpcmF0aW9uVGltZXJzKCk7XHJcbiAgICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHNldHVwRXhwaXJhdGlvblRpbWVycygpOiB2b2lkIHtcclxuICAgIGlmICh0aGlzLmhhc1ZhbGlkQWNjZXNzVG9rZW4oKSkge1xyXG4gICAgICB0aGlzLnNldHVwQWNjZXNzVG9rZW5UaW1lcigpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICh0aGlzLmhhc1ZhbGlkSWRUb2tlbigpKSB7XHJcbiAgICAgIHRoaXMuc2V0dXBJZFRva2VuVGltZXIoKTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBzZXR1cEFjY2Vzc1Rva2VuVGltZXIoKTogdm9pZCB7XHJcbiAgICBjb25zdCBleHBpcmF0aW9uID0gdGhpcy5nZXRBY2Nlc3NUb2tlbkV4cGlyYXRpb24oKTtcclxuICAgIGNvbnN0IHN0b3JlZEF0ID0gdGhpcy5nZXRBY2Nlc3NUb2tlblN0b3JlZEF0KCk7XHJcbiAgICBjb25zdCB0aW1lb3V0ID0gdGhpcy5jYWxjVGltZW91dChzdG9yZWRBdCwgZXhwaXJhdGlvbik7XHJcblxyXG4gICAgdGhpcy5uZ1pvbmUucnVuT3V0c2lkZUFuZ3VsYXIoKCkgPT4ge1xyXG4gICAgICB0aGlzLmFjY2Vzc1Rva2VuVGltZW91dFN1YnNjcmlwdGlvbiA9IG9mKFxyXG4gICAgICAgIG5ldyBPQXV0aEluZm9FdmVudCgndG9rZW5fZXhwaXJlcycsICdhY2Nlc3NfdG9rZW4nKVxyXG4gICAgICApXHJcbiAgICAgICAgLnBpcGUoZGVsYXkodGltZW91dCkpXHJcbiAgICAgICAgLnN1YnNjcmliZShlID0+IHtcclxuICAgICAgICAgIHRoaXMubmdab25lLnJ1bigoKSA9PiB7XHJcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGUpO1xyXG4gICAgICAgICAgfSk7XHJcbiAgICAgICAgfSk7XHJcbiAgICB9KTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBzZXR1cElkVG9rZW5UaW1lcigpOiB2b2lkIHtcclxuICAgIGNvbnN0IGV4cGlyYXRpb24gPSB0aGlzLmdldElkVG9rZW5FeHBpcmF0aW9uKCk7XHJcbiAgICBjb25zdCBzdG9yZWRBdCA9IHRoaXMuZ2V0SWRUb2tlblN0b3JlZEF0KCk7XHJcbiAgICBjb25zdCB0aW1lb3V0ID0gdGhpcy5jYWxjVGltZW91dChzdG9yZWRBdCwgZXhwaXJhdGlvbik7XHJcblxyXG4gICAgdGhpcy5uZ1pvbmUucnVuT3V0c2lkZUFuZ3VsYXIoKCkgPT4ge1xyXG4gICAgICB0aGlzLmlkVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uID0gb2YoXHJcbiAgICAgICAgbmV3IE9BdXRoSW5mb0V2ZW50KCd0b2tlbl9leHBpcmVzJywgJ2lkX3Rva2VuJylcclxuICAgICAgKVxyXG4gICAgICAgIC5waXBlKGRlbGF5KHRpbWVvdXQpKVxyXG4gICAgICAgIC5zdWJzY3JpYmUoZSA9PiB7XHJcbiAgICAgICAgICB0aGlzLm5nWm9uZS5ydW4oKCkgPT4ge1xyXG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlKTtcclxuICAgICAgICAgIH0pO1xyXG4gICAgICAgIH0pO1xyXG4gICAgfSk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBTdG9wcyB0aW1lcnMgZm9yIGF1dG9tYXRpYyByZWZyZXNoLlxyXG4gICAqIFRvIHJlc3RhcnQgaXQsIGNhbGwgc2V0dXBBdXRvbWF0aWNTaWxlbnRSZWZyZXNoIGFnYWluLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBzdG9wQXV0b21hdGljUmVmcmVzaCgpIHtcclxuICAgIHRoaXMuY2xlYXJBY2Nlc3NUb2tlblRpbWVyKCk7XHJcbiAgICB0aGlzLmNsZWFySWRUb2tlblRpbWVyKCk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgY2xlYXJBY2Nlc3NUb2tlblRpbWVyKCk6IHZvaWQge1xyXG4gICAgaWYgKHRoaXMuYWNjZXNzVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uKSB7XHJcbiAgICAgIHRoaXMuYWNjZXNzVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uLnVuc3Vic2NyaWJlKCk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgY2xlYXJJZFRva2VuVGltZXIoKTogdm9pZCB7XHJcbiAgICBpZiAodGhpcy5pZFRva2VuVGltZW91dFN1YnNjcmlwdGlvbikge1xyXG4gICAgICB0aGlzLmlkVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uLnVuc3Vic2NyaWJlKCk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgY2FsY1RpbWVvdXQoc3RvcmVkQXQ6IG51bWJlciwgZXhwaXJhdGlvbjogbnVtYmVyKTogbnVtYmVyIHtcclxuICAgIGNvbnN0IG5vdyA9IERhdGUubm93KCk7XHJcbiAgICBjb25zdCBkZWx0YSA9XHJcbiAgICAgIChleHBpcmF0aW9uIC0gc3RvcmVkQXQpICogdGhpcy50aW1lb3V0RmFjdG9yIC0gKG5vdyAtIHN0b3JlZEF0KTtcclxuICAgIHJldHVybiBNYXRoLm1heCgwLCBkZWx0YSk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBERVBSRUNBVEVELiBVc2UgYSBwcm92aWRlciBmb3IgT0F1dGhTdG9yYWdlIGluc3RlYWQ6XHJcbiAgICpcclxuICAgKiB7IHByb3ZpZGU6IE9BdXRoU3RvcmFnZSwgdXNlRmFjdG9yeTogb0F1dGhTdG9yYWdlRmFjdG9yeSB9XHJcbiAgICogZXhwb3J0IGZ1bmN0aW9uIG9BdXRoU3RvcmFnZUZhY3RvcnkoKTogT0F1dGhTdG9yYWdlIHsgcmV0dXJuIGxvY2FsU3RvcmFnZTsgfVxyXG4gICAqIFNldHMgYSBjdXN0b20gc3RvcmFnZSB1c2VkIHRvIHN0b3JlIHRoZSByZWNlaXZlZFxyXG4gICAqIHRva2VucyBvbiBjbGllbnQgc2lkZS4gQnkgZGVmYXVsdCwgdGhlIGJyb3dzZXInc1xyXG4gICAqIHNlc3Npb25TdG9yYWdlIGlzIHVzZWQuXHJcbiAgICogQGlnbm9yZVxyXG4gICAqXHJcbiAgICogQHBhcmFtIHN0b3JhZ2VcclxuICAgKi9cclxuICBwdWJsaWMgc2V0U3RvcmFnZShzdG9yYWdlOiBPQXV0aFN0b3JhZ2UpOiB2b2lkIHtcclxuICAgIHRoaXMuX3N0b3JhZ2UgPSBzdG9yYWdlO1xyXG4gICAgdGhpcy5jb25maWdDaGFuZ2VkKCk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBMb2FkcyB0aGUgZGlzY292ZXJ5IGRvY3VtZW50IHRvIGNvbmZpZ3VyZSBtb3N0XHJcbiAgICogcHJvcGVydGllcyBvZiB0aGlzIHNlcnZpY2UuIFRoZSB1cmwgb2YgdGhlIGRpc2NvdmVyeVxyXG4gICAqIGRvY3VtZW50IGlzIGluZmVyZWQgZnJvbSB0aGUgaXNzdWVyJ3MgdXJsIGFjY29yZGluZ1xyXG4gICAqIHRvIHRoZSBPcGVuSWQgQ29ubmVjdCBzcGVjLiBUbyB1c2UgYW5vdGhlciB1cmwgeW91XHJcbiAgICogY2FuIHBhc3MgaXQgdG8gdG8gb3B0aW9uYWwgcGFyYW1ldGVyIGZ1bGxVcmwuXHJcbiAgICpcclxuICAgKiBAcGFyYW0gZnVsbFVybFxyXG4gICAqL1xyXG4gIHB1YmxpYyBsb2FkRGlzY292ZXJ5RG9jdW1lbnQoXHJcbiAgICBmdWxsVXJsOiBzdHJpbmcgPSBudWxsXHJcbiAgKTogUHJvbWlzZTxPQXV0aFN1Y2Nlc3NFdmVudD4ge1xyXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcclxuICAgICAgaWYgKCFmdWxsVXJsKSB7XHJcbiAgICAgICAgZnVsbFVybCA9IHRoaXMuaXNzdWVyIHx8ICcnO1xyXG4gICAgICAgIGlmICghZnVsbFVybC5lbmRzV2l0aCgnLycpKSB7XHJcbiAgICAgICAgICBmdWxsVXJsICs9ICcvJztcclxuICAgICAgICB9XHJcbiAgICAgICAgZnVsbFVybCArPSAnLndlbGwta25vd24vb3BlbmlkLWNvbmZpZ3VyYXRpb24nO1xyXG4gICAgICB9XHJcblxyXG4gICAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyhmdWxsVXJsKSkge1xyXG4gICAgICAgIHJlamVjdChcclxuICAgICAgICAgIFwiaXNzdWVyICBtdXN0IHVzZSBIVFRQUyAod2l0aCBUTFMpLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5ICdyZXF1aXJlSHR0cHMnIG11c3QgYmUgc2V0IHRvICdmYWxzZScgYW5kIGFsbG93IEhUVFAgKHdpdGhvdXQgVExTKS5cIlxyXG4gICAgICAgICk7XHJcbiAgICAgICAgcmV0dXJuO1xyXG4gICAgICB9XHJcblxyXG4gICAgICB0aGlzLmh0dHAuZ2V0PE9pZGNEaXNjb3ZlcnlEb2M+KGZ1bGxVcmwpLnN1YnNjcmliZShcclxuICAgICAgICBkb2MgPT4ge1xyXG4gICAgICAgICAgaWYgKCF0aGlzLnZhbGlkYXRlRGlzY292ZXJ5RG9jdW1lbnQoZG9jKSkge1xyXG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcclxuICAgICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCdkaXNjb3ZlcnlfZG9jdW1lbnRfdmFsaWRhdGlvbl9lcnJvcicsIG51bGwpXHJcbiAgICAgICAgICAgICk7XHJcbiAgICAgICAgICAgIHJlamVjdCgnZGlzY292ZXJ5X2RvY3VtZW50X3ZhbGlkYXRpb25fZXJyb3InKTtcclxuICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgfVxyXG5cclxuICAgICAgICAgIHRoaXMubG9naW5VcmwgPSBkb2MuYXV0aG9yaXphdGlvbl9lbmRwb2ludDtcclxuICAgICAgICAgIHRoaXMubG9nb3V0VXJsID0gZG9jLmVuZF9zZXNzaW9uX2VuZHBvaW50IHx8IHRoaXMubG9nb3V0VXJsO1xyXG4gICAgICAgICAgdGhpcy5ncmFudFR5cGVzU3VwcG9ydGVkID0gZG9jLmdyYW50X3R5cGVzX3N1cHBvcnRlZDtcclxuICAgICAgICAgIHRoaXMuaXNzdWVyID0gZG9jLmlzc3VlcjtcclxuICAgICAgICAgIHRoaXMudG9rZW5FbmRwb2ludCA9IGRvYy50b2tlbl9lbmRwb2ludDtcclxuICAgICAgICAgIHRoaXMudXNlcmluZm9FbmRwb2ludCA9XHJcbiAgICAgICAgICAgIGRvYy51c2VyaW5mb19lbmRwb2ludCB8fCB0aGlzLnVzZXJpbmZvRW5kcG9pbnQ7XHJcbiAgICAgICAgICB0aGlzLmp3a3NVcmkgPSBkb2Muandrc191cmk7XHJcbiAgICAgICAgICB0aGlzLnNlc3Npb25DaGVja0lGcmFtZVVybCA9XHJcbiAgICAgICAgICAgIGRvYy5jaGVja19zZXNzaW9uX2lmcmFtZSB8fCB0aGlzLnNlc3Npb25DaGVja0lGcmFtZVVybDtcclxuXHJcbiAgICAgICAgICB0aGlzLmRpc2NvdmVyeURvY3VtZW50TG9hZGVkID0gdHJ1ZTtcclxuICAgICAgICAgIHRoaXMuZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWRTdWJqZWN0Lm5leHQoZG9jKTtcclxuICAgICAgICAgIHRoaXMucmV2b2NhdGlvbkVuZHBvaW50ID0gZG9jLnJldm9jYXRpb25fZW5kcG9pbnQ7XHJcblxyXG4gICAgICAgICAgaWYgKHRoaXMuc2Vzc2lvbkNoZWNrc0VuYWJsZWQpIHtcclxuICAgICAgICAgICAgdGhpcy5yZXN0YXJ0U2Vzc2lvbkNoZWNrc0lmU3RpbGxMb2dnZWRJbigpO1xyXG4gICAgICAgICAgfVxyXG5cclxuICAgICAgICAgIHRoaXMubG9hZEp3a3MoKVxyXG4gICAgICAgICAgICAudGhlbihqd2tzID0+IHtcclxuICAgICAgICAgICAgICBjb25zdCByZXN1bHQ6IG9iamVjdCA9IHtcclxuICAgICAgICAgICAgICAgIGRpc2NvdmVyeURvY3VtZW50OiBkb2MsXHJcbiAgICAgICAgICAgICAgICBqd2tzOiBqd2tzXHJcbiAgICAgICAgICAgICAgfTtcclxuXHJcbiAgICAgICAgICAgICAgY29uc3QgZXZlbnQgPSBuZXcgT0F1dGhTdWNjZXNzRXZlbnQoXHJcbiAgICAgICAgICAgICAgICAnZGlzY292ZXJ5X2RvY3VtZW50X2xvYWRlZCcsXHJcbiAgICAgICAgICAgICAgICByZXN1bHRcclxuICAgICAgICAgICAgICApO1xyXG4gICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGV2ZW50KTtcclxuICAgICAgICAgICAgICByZXNvbHZlKGV2ZW50KTtcclxuICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgIH0pXHJcbiAgICAgICAgICAgIC5jYXRjaChlcnIgPT4ge1xyXG4gICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxyXG4gICAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgnZGlzY292ZXJ5X2RvY3VtZW50X2xvYWRfZXJyb3InLCBlcnIpXHJcbiAgICAgICAgICAgICAgKTtcclxuICAgICAgICAgICAgICByZWplY3QoZXJyKTtcclxuICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgIH0pO1xyXG4gICAgICAgIH0sXHJcbiAgICAgICAgZXJyID0+IHtcclxuICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdlcnJvciBsb2FkaW5nIGRpc2NvdmVyeSBkb2N1bWVudCcsIGVycik7XHJcbiAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcclxuICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgnZGlzY292ZXJ5X2RvY3VtZW50X2xvYWRfZXJyb3InLCBlcnIpXHJcbiAgICAgICAgICApO1xyXG4gICAgICAgICAgcmVqZWN0KGVycik7XHJcbiAgICAgICAgfVxyXG4gICAgICApO1xyXG4gICAgfSk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgbG9hZEp3a3MoKTogUHJvbWlzZTxvYmplY3Q+IHtcclxuICAgIHJldHVybiBuZXcgUHJvbWlzZTxvYmplY3Q+KChyZXNvbHZlLCByZWplY3QpID0+IHtcclxuICAgICAgaWYgKHRoaXMuandrc1VyaSkge1xyXG4gICAgICAgIHRoaXMuaHR0cC5nZXQodGhpcy5qd2tzVXJpKS5zdWJzY3JpYmUoXHJcbiAgICAgICAgICBqd2tzID0+IHtcclxuICAgICAgICAgICAgdGhpcy5qd2tzID0gandrcztcclxuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXHJcbiAgICAgICAgICAgICAgbmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZGVkJylcclxuICAgICAgICAgICAgKTtcclxuICAgICAgICAgICAgcmVzb2x2ZShqd2tzKTtcclxuICAgICAgICAgIH0sXHJcbiAgICAgICAgICBlcnIgPT4ge1xyXG4gICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcignZXJyb3IgbG9hZGluZyBqd2tzJywgZXJyKTtcclxuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXHJcbiAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgnandrc19sb2FkX2Vycm9yJywgZXJyKVxyXG4gICAgICAgICAgICApO1xyXG4gICAgICAgICAgICByZWplY3QoZXJyKTtcclxuICAgICAgICAgIH1cclxuICAgICAgICApO1xyXG4gICAgICB9IGVsc2Uge1xyXG4gICAgICAgIHJlc29sdmUobnVsbCk7XHJcbiAgICAgIH1cclxuICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHZhbGlkYXRlRGlzY292ZXJ5RG9jdW1lbnQoZG9jOiBPaWRjRGlzY292ZXJ5RG9jKTogYm9vbGVhbiB7XHJcbiAgICBsZXQgZXJyb3JzOiBzdHJpbmdbXTtcclxuXHJcbiAgICBpZiAoIXRoaXMuc2tpcElzc3VlckNoZWNrICYmIGRvYy5pc3N1ZXIgIT09IHRoaXMuaXNzdWVyKSB7XHJcbiAgICAgIHRoaXMubG9nZ2VyLmVycm9yKFxyXG4gICAgICAgICdpbnZhbGlkIGlzc3VlciBpbiBkaXNjb3ZlcnkgZG9jdW1lbnQnLFxyXG4gICAgICAgICdleHBlY3RlZDogJyArIHRoaXMuaXNzdWVyLFxyXG4gICAgICAgICdjdXJyZW50OiAnICsgZG9jLmlzc3VlclxyXG4gICAgICApO1xyXG4gICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICB9XHJcblxyXG4gICAgZXJyb3JzID0gdGhpcy52YWxpZGF0ZVVybEZyb21EaXNjb3ZlcnlEb2N1bWVudChkb2MuYXV0aG9yaXphdGlvbl9lbmRwb2ludCk7XHJcbiAgICBpZiAoZXJyb3JzLmxlbmd0aCA+IDApIHtcclxuICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoXHJcbiAgICAgICAgJ2Vycm9yIHZhbGlkYXRpbmcgYXV0aG9yaXphdGlvbl9lbmRwb2ludCBpbiBkaXNjb3ZlcnkgZG9jdW1lbnQnLFxyXG4gICAgICAgIGVycm9yc1xyXG4gICAgICApO1xyXG4gICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICB9XHJcblxyXG4gICAgZXJyb3JzID0gdGhpcy52YWxpZGF0ZVVybEZyb21EaXNjb3ZlcnlEb2N1bWVudChkb2MuZW5kX3Nlc3Npb25fZW5kcG9pbnQpO1xyXG4gICAgaWYgKGVycm9ycy5sZW5ndGggPiAwKSB7XHJcbiAgICAgIHRoaXMubG9nZ2VyLmVycm9yKFxyXG4gICAgICAgICdlcnJvciB2YWxpZGF0aW5nIGVuZF9zZXNzaW9uX2VuZHBvaW50IGluIGRpc2NvdmVyeSBkb2N1bWVudCcsXHJcbiAgICAgICAgZXJyb3JzXHJcbiAgICAgICk7XHJcbiAgICAgIHJldHVybiBmYWxzZTtcclxuICAgIH1cclxuXHJcbiAgICBlcnJvcnMgPSB0aGlzLnZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KGRvYy50b2tlbl9lbmRwb2ludCk7XHJcbiAgICBpZiAoZXJyb3JzLmxlbmd0aCA+IDApIHtcclxuICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoXHJcbiAgICAgICAgJ2Vycm9yIHZhbGlkYXRpbmcgdG9rZW5fZW5kcG9pbnQgaW4gZGlzY292ZXJ5IGRvY3VtZW50JyxcclxuICAgICAgICBlcnJvcnNcclxuICAgICAgKTtcclxuICAgIH1cclxuXHJcbiAgICBlcnJvcnMgPSB0aGlzLnZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KGRvYy5yZXZvY2F0aW9uX2VuZHBvaW50KTtcclxuICAgIGlmIChlcnJvcnMubGVuZ3RoID4gMCkge1xyXG4gICAgICB0aGlzLmxvZ2dlci5lcnJvcihcclxuICAgICAgICAnZXJyb3IgdmFsaWRhdGluZyByZXZvY2F0aW9uX2VuZHBvaW50IGluIGRpc2NvdmVyeSBkb2N1bWVudCcsXHJcbiAgICAgICAgZXJyb3JzXHJcbiAgICAgICk7XHJcbiAgICB9XHJcblxyXG4gICAgZXJyb3JzID0gdGhpcy52YWxpZGF0ZVVybEZyb21EaXNjb3ZlcnlEb2N1bWVudChkb2MudXNlcmluZm9fZW5kcG9pbnQpO1xyXG4gICAgaWYgKGVycm9ycy5sZW5ndGggPiAwKSB7XHJcbiAgICAgIHRoaXMubG9nZ2VyLmVycm9yKFxyXG4gICAgICAgICdlcnJvciB2YWxpZGF0aW5nIHVzZXJpbmZvX2VuZHBvaW50IGluIGRpc2NvdmVyeSBkb2N1bWVudCcsXHJcbiAgICAgICAgZXJyb3JzXHJcbiAgICAgICk7XHJcbiAgICAgIHJldHVybiBmYWxzZTtcclxuICAgIH1cclxuXHJcbiAgICBlcnJvcnMgPSB0aGlzLnZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KGRvYy5qd2tzX3VyaSk7XHJcbiAgICBpZiAoZXJyb3JzLmxlbmd0aCA+IDApIHtcclxuICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoXHJcbiAgICAgICAgJ2Vycm9yIHZhbGlkYXRpbmcgandrc191cmkgaW4gZGlzY292ZXJ5IGRvY3VtZW50JyxcclxuICAgICAgICBlcnJvcnNcclxuICAgICAgKTtcclxuICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICh0aGlzLnNlc3Npb25DaGVja3NFbmFibGVkICYmICFkb2MuY2hlY2tfc2Vzc2lvbl9pZnJhbWUpIHtcclxuICAgICAgdGhpcy5sb2dnZXIud2FybihcclxuICAgICAgICAnc2Vzc2lvbkNoZWNrc0VuYWJsZWQgaXMgYWN0aXZhdGVkIGJ1dCBkaXNjb3ZlcnkgZG9jdW1lbnQnICtcclxuICAgICAgICAgICcgZG9lcyBub3QgY29udGFpbiBhIGNoZWNrX3Nlc3Npb25faWZyYW1lIGZpZWxkJ1xyXG4gICAgICApO1xyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiB0cnVlO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogVXNlcyBwYXNzd29yZCBmbG93IHRvIGV4Y2hhbmdlIHVzZXJOYW1lIGFuZCBwYXNzd29yZCBmb3IgYW5cclxuICAgKiBhY2Nlc3NfdG9rZW4uIEFmdGVyIHJlY2VpdmluZyB0aGUgYWNjZXNzX3Rva2VuLCB0aGlzIG1ldGhvZFxyXG4gICAqIHVzZXMgaXQgdG8gcXVlcnkgdGhlIHVzZXJpbmZvIGVuZHBvaW50IGluIG9yZGVyIHRvIGdldCBpbmZvcm1hdGlvblxyXG4gICAqIGFib3V0IHRoZSB1c2VyIGluIHF1ZXN0aW9uLlxyXG4gICAqXHJcbiAgICogV2hlbiB1c2luZyB0aGlzLCBtYWtlIHN1cmUgdGhhdCB0aGUgcHJvcGVydHkgb2lkYyBpcyBzZXQgdG8gZmFsc2UuXHJcbiAgICogT3RoZXJ3aXNlIHN0cmljdGVyIHZhbGlkYXRpb25zIHRha2UgcGxhY2UgdGhhdCBtYWtlIHRoaXMgb3BlcmF0aW9uXHJcbiAgICogZmFpbC5cclxuICAgKlxyXG4gICAqIEBwYXJhbSB1c2VyTmFtZVxyXG4gICAqIEBwYXJhbSBwYXNzd29yZFxyXG4gICAqIEBwYXJhbSBoZWFkZXJzIE9wdGlvbmFsIGFkZGl0aW9uYWwgaHR0cC1oZWFkZXJzLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBmZXRjaFRva2VuVXNpbmdQYXNzd29yZEZsb3dBbmRMb2FkVXNlclByb2ZpbGUoXHJcbiAgICB1c2VyTmFtZTogc3RyaW5nLFxyXG4gICAgcGFzc3dvcmQ6IHN0cmluZyxcclxuICAgIGhlYWRlcnM6IEh0dHBIZWFkZXJzID0gbmV3IEh0dHBIZWFkZXJzKClcclxuICApOiBQcm9taXNlPFVzZXJJbmZvPiB7XHJcbiAgICByZXR1cm4gdGhpcy5mZXRjaFRva2VuVXNpbmdQYXNzd29yZEZsb3coXHJcbiAgICAgIHVzZXJOYW1lLFxyXG4gICAgICBwYXNzd29yZCxcclxuICAgICAgaGVhZGVyc1xyXG4gICAgKS50aGVuKCgpID0+IHRoaXMubG9hZFVzZXJQcm9maWxlKCkpO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogTG9hZHMgdGhlIHVzZXIgcHJvZmlsZSBieSBhY2Nlc3NpbmcgdGhlIHVzZXIgaW5mbyBlbmRwb2ludCBkZWZpbmVkIGJ5IE9wZW5JZCBDb25uZWN0LlxyXG4gICAqXHJcbiAgICogV2hlbiB1c2luZyB0aGlzIHdpdGggT0F1dGgyIHBhc3N3b3JkIGZsb3csIG1ha2Ugc3VyZSB0aGF0IHRoZSBwcm9wZXJ0eSBvaWRjIGlzIHNldCB0byBmYWxzZS5cclxuICAgKiBPdGhlcndpc2Ugc3RyaWN0ZXIgdmFsaWRhdGlvbnMgdGFrZSBwbGFjZSB0aGF0IG1ha2UgdGhpcyBvcGVyYXRpb24gZmFpbC5cclxuICAgKi9cclxuICBwdWJsaWMgbG9hZFVzZXJQcm9maWxlKCk6IFByb21pc2U8VXNlckluZm8+IHtcclxuICAgIGlmICghdGhpcy5oYXNWYWxpZEFjY2Vzc1Rva2VuKCkpIHtcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKCdDYW4gbm90IGxvYWQgVXNlciBQcm9maWxlIHdpdGhvdXQgYWNjZXNzX3Rva2VuJyk7XHJcbiAgICB9XHJcbiAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh0aGlzLnVzZXJpbmZvRW5kcG9pbnQpKSB7XHJcbiAgICAgIHRocm93IG5ldyBFcnJvcihcclxuICAgICAgICBcInVzZXJpbmZvRW5kcG9pbnQgbXVzdCB1c2UgSFRUUFMgKHdpdGggVExTKSwgb3IgY29uZmlnIHZhbHVlIGZvciBwcm9wZXJ0eSAncmVxdWlyZUh0dHBzJyBtdXN0IGJlIHNldCB0byAnZmFsc2UnIGFuZCBhbGxvdyBIVFRQICh3aXRob3V0IFRMUykuXCJcclxuICAgICAgKTtcclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xyXG4gICAgICBjb25zdCBoZWFkZXJzID0gbmV3IEh0dHBIZWFkZXJzKCkuc2V0KFxyXG4gICAgICAgICdBdXRob3JpemF0aW9uJyxcclxuICAgICAgICAnQmVhcmVyICcgKyB0aGlzLmdldEFjY2Vzc1Rva2VuKClcclxuICAgICAgKTtcclxuXHJcbiAgICAgIHRoaXMuaHR0cFxyXG4gICAgICAgIC5nZXQ8VXNlckluZm8+KHRoaXMudXNlcmluZm9FbmRwb2ludCwgeyBoZWFkZXJzIH0pXHJcbiAgICAgICAgLnN1YnNjcmliZShcclxuICAgICAgICAgIGluZm8gPT4ge1xyXG4gICAgICAgICAgICB0aGlzLmRlYnVnKCd1c2VyaW5mbyByZWNlaXZlZCcsIGluZm8pO1xyXG5cclxuICAgICAgICAgICAgY29uc3QgZXhpc3RpbmdDbGFpbXMgPSB0aGlzLmdldElkZW50aXR5Q2xhaW1zKCkgfHwge307XHJcblxyXG4gICAgICAgICAgICBpZiAoIXRoaXMuc2tpcFN1YmplY3RDaGVjaykge1xyXG4gICAgICAgICAgICAgIGlmIChcclxuICAgICAgICAgICAgICAgIHRoaXMub2lkYyAmJlxyXG4gICAgICAgICAgICAgICAgKCFleGlzdGluZ0NsYWltc1snc3ViJ10gfHwgaW5mby5zdWIgIT09IGV4aXN0aW5nQ2xhaW1zWydzdWInXSlcclxuICAgICAgICAgICAgICApIHtcclxuICAgICAgICAgICAgICAgIGNvbnN0IGVyciA9XHJcbiAgICAgICAgICAgICAgICAgICdpZiBwcm9wZXJ0eSBvaWRjIGlzIHRydWUsIHRoZSByZWNlaXZlZCB1c2VyLWlkIChzdWIpIGhhcyB0byBiZSB0aGUgdXNlci1pZCAnICtcclxuICAgICAgICAgICAgICAgICAgJ29mIHRoZSB1c2VyIHRoYXQgaGFzIGxvZ2dlZCBpbiB3aXRoIG9pZGMuXFxuJyArXHJcbiAgICAgICAgICAgICAgICAgICdpZiB5b3UgYXJlIG5vdCB1c2luZyBvaWRjIGJ1dCBqdXN0IG9hdXRoMiBwYXNzd29yZCBmbG93IHNldCBvaWRjIHRvIGZhbHNlJztcclxuXHJcbiAgICAgICAgICAgICAgICByZWplY3QoZXJyKTtcclxuICAgICAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIGluZm8gPSBPYmplY3QuYXNzaWduKHt9LCBleGlzdGluZ0NsYWltcywgaW5mbyk7XHJcblxyXG4gICAgICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2lkX3Rva2VuX2NsYWltc19vYmonLCBKU09OLnN0cmluZ2lmeShpbmZvKSk7XHJcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxyXG4gICAgICAgICAgICAgIG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndXNlcl9wcm9maWxlX2xvYWRlZCcpXHJcbiAgICAgICAgICAgICk7XHJcbiAgICAgICAgICAgIHJlc29sdmUoaW5mbyk7XHJcbiAgICAgICAgICB9LFxyXG4gICAgICAgICAgZXJyID0+IHtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ2Vycm9yIGxvYWRpbmcgdXNlciBpbmZvJywgZXJyKTtcclxuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXHJcbiAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgndXNlcl9wcm9maWxlX2xvYWRfZXJyb3InLCBlcnIpXHJcbiAgICAgICAgICAgICk7XHJcbiAgICAgICAgICAgIHJlamVjdChlcnIpO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICk7XHJcbiAgICB9KTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFVzZXMgcGFzc3dvcmQgZmxvdyB0byBleGNoYW5nZSB1c2VyTmFtZSBhbmQgcGFzc3dvcmQgZm9yIGFuIGFjY2Vzc190b2tlbi5cclxuICAgKiBAcGFyYW0gdXNlck5hbWVcclxuICAgKiBAcGFyYW0gcGFzc3dvcmRcclxuICAgKiBAcGFyYW0gaGVhZGVycyBPcHRpb25hbCBhZGRpdGlvbmFsIGh0dHAtaGVhZGVycy5cclxuICAgKi9cclxuICBwdWJsaWMgZmV0Y2hUb2tlblVzaW5nUGFzc3dvcmRGbG93KFxyXG4gICAgdXNlck5hbWU6IHN0cmluZyxcclxuICAgIHBhc3N3b3JkOiBzdHJpbmcsXHJcbiAgICBoZWFkZXJzOiBIdHRwSGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpXHJcbiAgKTogUHJvbWlzZTxUb2tlblJlc3BvbnNlPiB7XHJcbiAgICB0aGlzLmFzc2VydFVybE5vdE51bGxBbmRDb3JyZWN0UHJvdG9jb2woXHJcbiAgICAgIHRoaXMudG9rZW5FbmRwb2ludCxcclxuICAgICAgJ3Rva2VuRW5kcG9pbnQnXHJcbiAgICApO1xyXG5cclxuICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XHJcbiAgICAgIC8qKlxyXG4gICAgICAgKiBBIGBIdHRwUGFyYW1ldGVyQ29kZWNgIHRoYXQgdXNlcyBgZW5jb2RlVVJJQ29tcG9uZW50YCBhbmQgYGRlY29kZVVSSUNvbXBvbmVudGAgdG9cclxuICAgICAgICogc2VyaWFsaXplIGFuZCBwYXJzZSBVUkwgcGFyYW1ldGVyIGtleXMgYW5kIHZhbHVlcy5cclxuICAgICAgICpcclxuICAgICAgICogQHN0YWJsZVxyXG4gICAgICAgKi9cclxuICAgICAgbGV0IHBhcmFtcyA9IG5ldyBIdHRwUGFyYW1zKHsgZW5jb2RlcjogbmV3IFdlYkh0dHBVcmxFbmNvZGluZ0NvZGVjKCkgfSlcclxuICAgICAgICAuc2V0KCdncmFudF90eXBlJywgJ3Bhc3N3b3JkJylcclxuICAgICAgICAuc2V0KCdzY29wZScsIHRoaXMuc2NvcGUpXHJcbiAgICAgICAgLnNldCgndXNlcm5hbWUnLCB1c2VyTmFtZSlcclxuICAgICAgICAuc2V0KCdwYXNzd29yZCcsIHBhc3N3b3JkKTtcclxuXHJcbiAgICAgIGlmICh0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcclxuICAgICAgICBjb25zdCBoZWFkZXIgPSBidG9hKGAke3RoaXMuY2xpZW50SWR9OiR7dGhpcy5kdW1teUNsaWVudFNlY3JldH1gKTtcclxuICAgICAgICBoZWFkZXJzID0gaGVhZGVycy5zZXQoJ0F1dGhvcml6YXRpb24nLCAnQmFzaWMgJyArIGhlYWRlcik7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIGlmICghdGhpcy51c2VIdHRwQmFzaWNBdXRoKSB7XHJcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY2xpZW50X2lkJywgdGhpcy5jbGllbnRJZCk7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIGlmICghdGhpcy51c2VIdHRwQmFzaWNBdXRoICYmIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpIHtcclxuICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdjbGllbnRfc2VjcmV0JywgdGhpcy5kdW1teUNsaWVudFNlY3JldCk7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIGlmICh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSB7XHJcbiAgICAgICAgZm9yIChjb25zdCBrZXkgb2YgT2JqZWN0LmdldE93blByb3BlcnR5TmFtZXModGhpcy5jdXN0b21RdWVyeVBhcmFtcykpIHtcclxuICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoa2V5LCB0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zW2tleV0pO1xyXG4gICAgICAgIH1cclxuICAgICAgfVxyXG5cclxuICAgICAgaGVhZGVycyA9IGhlYWRlcnMuc2V0KFxyXG4gICAgICAgICdDb250ZW50LVR5cGUnLFxyXG4gICAgICAgICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnXHJcbiAgICAgICk7XHJcblxyXG4gICAgICB0aGlzLmh0dHBcclxuICAgICAgICAucG9zdDxUb2tlblJlc3BvbnNlPih0aGlzLnRva2VuRW5kcG9pbnQsIHBhcmFtcywgeyBoZWFkZXJzIH0pXHJcbiAgICAgICAgLnN1YnNjcmliZShcclxuICAgICAgICAgIHRva2VuUmVzcG9uc2UgPT4ge1xyXG4gICAgICAgICAgICB0aGlzLmRlYnVnKCd0b2tlblJlc3BvbnNlJywgdG9rZW5SZXNwb25zZSk7XHJcbiAgICAgICAgICAgIHRoaXMuc3RvcmVBY2Nlc3NUb2tlblJlc3BvbnNlKFxyXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuYWNjZXNzX3Rva2VuLFxyXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UucmVmcmVzaF90b2tlbixcclxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmV4cGlyZXNfaW4gfHxcclxuICAgICAgICAgICAgICAgIHRoaXMuZmFsbGJhY2tBY2Nlc3NUb2tlbkV4cGlyYXRpb25UaW1lSW5TZWMsXHJcbiAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5zY29wZSxcclxuICAgICAgICAgICAgICB0aGlzLmV4dHJhY3RSZWNvZ25pemVkQ3VzdG9tUGFyYW1ldGVycyh0b2tlblJlc3BvbnNlKVxyXG4gICAgICAgICAgICApO1xyXG5cclxuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWNlaXZlZCcpKTtcclxuICAgICAgICAgICAgcmVzb2x2ZSh0b2tlblJlc3BvbnNlKTtcclxuICAgICAgICAgIH0sXHJcbiAgICAgICAgICBlcnIgPT4ge1xyXG4gICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcignRXJyb3IgcGVyZm9ybWluZyBwYXNzd29yZCBmbG93JywgZXJyKTtcclxuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoRXJyb3JFdmVudCgndG9rZW5fZXJyb3InLCBlcnIpKTtcclxuICAgICAgICAgICAgcmVqZWN0KGVycik7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgKTtcclxuICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogUmVmcmVzaGVzIHRoZSB0b2tlbiB1c2luZyBhIHJlZnJlc2hfdG9rZW4uXHJcbiAgICogVGhpcyBkb2VzIG5vdCB3b3JrIGZvciBpbXBsaWNpdCBmbG93LCBiL2NcclxuICAgKiB0aGVyZSBpcyBubyByZWZyZXNoX3Rva2VuIGluIHRoaXMgZmxvdy5cclxuICAgKiBBIHNvbHV0aW9uIGZvciB0aGlzIGlzIHByb3ZpZGVkIGJ5IHRoZVxyXG4gICAqIG1ldGhvZCBzaWxlbnRSZWZyZXNoLlxyXG4gICAqL1xyXG4gIHB1YmxpYyByZWZyZXNoVG9rZW4oKTogUHJvbWlzZTxUb2tlblJlc3BvbnNlPiB7XHJcbiAgICB0aGlzLmFzc2VydFVybE5vdE51bGxBbmRDb3JyZWN0UHJvdG9jb2woXHJcbiAgICAgIHRoaXMudG9rZW5FbmRwb2ludCxcclxuICAgICAgJ3Rva2VuRW5kcG9pbnQnXHJcbiAgICApO1xyXG5cclxuICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XHJcbiAgICAgIGxldCBwYXJhbXMgPSBuZXcgSHR0cFBhcmFtcygpXHJcbiAgICAgICAgLnNldCgnZ3JhbnRfdHlwZScsICdyZWZyZXNoX3Rva2VuJylcclxuICAgICAgICAuc2V0KCdzY29wZScsIHRoaXMuc2NvcGUpXHJcbiAgICAgICAgLnNldCgncmVmcmVzaF90b2tlbicsIHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgncmVmcmVzaF90b2tlbicpKTtcclxuXHJcbiAgICAgIGxldCBoZWFkZXJzID0gbmV3IEh0dHBIZWFkZXJzKCkuc2V0KFxyXG4gICAgICAgICdDb250ZW50LVR5cGUnLFxyXG4gICAgICAgICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnXHJcbiAgICAgICk7XHJcblxyXG4gICAgICBpZiAodGhpcy51c2VIdHRwQmFzaWNBdXRoKSB7XHJcbiAgICAgICAgY29uc3QgaGVhZGVyID0gYnRvYShgJHt0aGlzLmNsaWVudElkfToke3RoaXMuZHVtbXlDbGllbnRTZWNyZXR9YCk7XHJcbiAgICAgICAgaGVhZGVycyA9IGhlYWRlcnMuc2V0KCdBdXRob3JpemF0aW9uJywgJ0Jhc2ljICcgKyBoZWFkZXIpO1xyXG4gICAgICB9XHJcblxyXG4gICAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCkge1xyXG4gICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9pZCcsIHRoaXMuY2xpZW50SWQpO1xyXG4gICAgICB9XHJcblxyXG4gICAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCAmJiB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KSB7XHJcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY2xpZW50X3NlY3JldCcsIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpO1xyXG4gICAgICB9XHJcblxyXG4gICAgICBpZiAodGhpcy5jdXN0b21RdWVyeVBhcmFtcykge1xyXG4gICAgICAgIGZvciAoY29uc3Qga2V5IG9mIE9iamVjdC5nZXRPd25Qcm9wZXJ0eU5hbWVzKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpKSB7XHJcbiAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KGtleSwgdGhpcy5jdXN0b21RdWVyeVBhcmFtc1trZXldKTtcclxuICAgICAgICB9XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIHRoaXMuaHR0cFxyXG4gICAgICAgIC5wb3N0PFRva2VuUmVzcG9uc2U+KHRoaXMudG9rZW5FbmRwb2ludCwgcGFyYW1zLCB7IGhlYWRlcnMgfSlcclxuICAgICAgICAucGlwZShcclxuICAgICAgICAgIHN3aXRjaE1hcCh0b2tlblJlc3BvbnNlID0+IHtcclxuICAgICAgICAgICAgaWYgKHRva2VuUmVzcG9uc2UuaWRfdG9rZW4pIHtcclxuICAgICAgICAgICAgICByZXR1cm4gZnJvbShcclxuICAgICAgICAgICAgICAgIHRoaXMucHJvY2Vzc0lkVG9rZW4oXHJcbiAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuaWRfdG9rZW4sXHJcbiAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuYWNjZXNzX3Rva2VuLFxyXG4gICAgICAgICAgICAgICAgICB0cnVlXHJcbiAgICAgICAgICAgICAgICApXHJcbiAgICAgICAgICAgICAgKS5waXBlKFxyXG4gICAgICAgICAgICAgICAgdGFwKHJlc3VsdCA9PiB0aGlzLnN0b3JlSWRUb2tlbihyZXN1bHQpKSxcclxuICAgICAgICAgICAgICAgIG1hcChfID0+IHRva2VuUmVzcG9uc2UpXHJcbiAgICAgICAgICAgICAgKTtcclxuICAgICAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgICByZXR1cm4gb2YodG9rZW5SZXNwb25zZSk7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgIH0pXHJcbiAgICAgICAgKVxyXG4gICAgICAgIC5zdWJzY3JpYmUoXHJcbiAgICAgICAgICB0b2tlblJlc3BvbnNlID0+IHtcclxuICAgICAgICAgICAgdGhpcy5kZWJ1ZygncmVmcmVzaCB0b2tlblJlc3BvbnNlJywgdG9rZW5SZXNwb25zZSk7XHJcbiAgICAgICAgICAgIHRoaXMuc3RvcmVBY2Nlc3NUb2tlblJlc3BvbnNlKFxyXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuYWNjZXNzX3Rva2VuLFxyXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UucmVmcmVzaF90b2tlbixcclxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmV4cGlyZXNfaW4gfHxcclxuICAgICAgICAgICAgICAgIHRoaXMuZmFsbGJhY2tBY2Nlc3NUb2tlbkV4cGlyYXRpb25UaW1lSW5TZWMsXHJcbiAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5zY29wZSxcclxuICAgICAgICAgICAgICB0aGlzLmV4dHJhY3RSZWNvZ25pemVkQ3VzdG9tUGFyYW1ldGVycyh0b2tlblJlc3BvbnNlKVxyXG4gICAgICAgICAgICApO1xyXG5cclxuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWNlaXZlZCcpKTtcclxuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWZyZXNoZWQnKSk7XHJcbiAgICAgICAgICAgIHJlc29sdmUodG9rZW5SZXNwb25zZSk7XHJcbiAgICAgICAgICB9LFxyXG4gICAgICAgICAgZXJyID0+IHtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ0Vycm9yIHJlZnJlc2hpbmcgdG9rZW4nLCBlcnIpO1xyXG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcclxuICAgICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl9yZWZyZXNoX2Vycm9yJywgZXJyKVxyXG4gICAgICAgICAgICApO1xyXG4gICAgICAgICAgICByZWplY3QoZXJyKTtcclxuICAgICAgICAgIH1cclxuICAgICAgICApO1xyXG4gICAgfSk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgcmVtb3ZlU2lsZW50UmVmcmVzaEV2ZW50TGlzdGVuZXIoKTogdm9pZCB7XHJcbiAgICBpZiAodGhpcy5zaWxlbnRSZWZyZXNoUG9zdE1lc3NhZ2VFdmVudExpc3RlbmVyKSB7XHJcbiAgICAgIHdpbmRvdy5yZW1vdmVFdmVudExpc3RlbmVyKFxyXG4gICAgICAgICdtZXNzYWdlJyxcclxuICAgICAgICB0aGlzLnNpbGVudFJlZnJlc2hQb3N0TWVzc2FnZUV2ZW50TGlzdGVuZXJcclxuICAgICAgKTtcclxuICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoUG9zdE1lc3NhZ2VFdmVudExpc3RlbmVyID0gbnVsbDtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBzZXR1cFNpbGVudFJlZnJlc2hFdmVudExpc3RlbmVyKCk6IHZvaWQge1xyXG4gICAgdGhpcy5yZW1vdmVTaWxlbnRSZWZyZXNoRXZlbnRMaXN0ZW5lcigpO1xyXG5cclxuICAgIHRoaXMuc2lsZW50UmVmcmVzaFBvc3RNZXNzYWdlRXZlbnRMaXN0ZW5lciA9IChlOiBNZXNzYWdlRXZlbnQpID0+IHtcclxuICAgICAgY29uc3QgbWVzc2FnZSA9IHRoaXMucHJvY2Vzc01lc3NhZ2VFdmVudE1lc3NhZ2UoZSk7XHJcblxyXG4gICAgICB0aGlzLnRyeUxvZ2luKHtcclxuICAgICAgICBjdXN0b21IYXNoRnJhZ21lbnQ6IG1lc3NhZ2UsXHJcbiAgICAgICAgcHJldmVudENsZWFySGFzaEFmdGVyTG9naW46IHRydWUsXHJcbiAgICAgICAgY3VzdG9tUmVkaXJlY3RVcmk6IHRoaXMuc2lsZW50UmVmcmVzaFJlZGlyZWN0VXJpIHx8IHRoaXMucmVkaXJlY3RVcmlcclxuICAgICAgfSkuY2F0Y2goZXJyID0+IHRoaXMuZGVidWcoJ3RyeUxvZ2luIGR1cmluZyBzaWxlbnQgcmVmcmVzaCBmYWlsZWQnLCBlcnIpKTtcclxuICAgIH07XHJcblxyXG4gICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoXHJcbiAgICAgICdtZXNzYWdlJyxcclxuICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoUG9zdE1lc3NhZ2VFdmVudExpc3RlbmVyXHJcbiAgICApO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogUGVyZm9ybXMgYSBzaWxlbnQgcmVmcmVzaCBmb3IgaW1wbGljaXQgZmxvdy5cclxuICAgKiBVc2UgdGhpcyBtZXRob2QgdG8gZ2V0IG5ldyB0b2tlbnMgd2hlbi9iZWZvcmVcclxuICAgKiB0aGUgZXhpc3RpbmcgdG9rZW5zIGV4cGlyZS5cclxuICAgKi9cclxuICBwdWJsaWMgc2lsZW50UmVmcmVzaChcclxuICAgIHBhcmFtczogb2JqZWN0ID0ge30sXHJcbiAgICBub1Byb21wdCA9IHRydWVcclxuICApOiBQcm9taXNlPE9BdXRoRXZlbnQ+IHtcclxuICAgIGNvbnN0IGNsYWltczogb2JqZWN0ID0gdGhpcy5nZXRJZGVudGl0eUNsYWltcygpIHx8IHt9O1xyXG5cclxuICAgIGlmICh0aGlzLnVzZUlkVG9rZW5IaW50Rm9yU2lsZW50UmVmcmVzaCAmJiB0aGlzLmhhc1ZhbGlkSWRUb2tlbigpKSB7XHJcbiAgICAgIHBhcmFtc1snaWRfdG9rZW5faGludCddID0gdGhpcy5nZXRJZFRva2VuKCk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModGhpcy5sb2dpblVybCkpIHtcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKFxyXG4gICAgICAgIFwibG9naW5VcmwgIG11c3QgdXNlIEhUVFBTICh3aXRoIFRMUyksIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgJ3JlcXVpcmVIdHRwcycgbXVzdCBiZSBzZXQgdG8gJ2ZhbHNlJyBhbmQgYWxsb3cgSFRUUCAod2l0aG91dCBUTFMpLlwiXHJcbiAgICAgICk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHR5cGVvZiBkb2N1bWVudCA9PT0gJ3VuZGVmaW5lZCcpIHtcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKCdzaWxlbnQgcmVmcmVzaCBpcyBub3Qgc3VwcG9ydGVkIG9uIHRoaXMgcGxhdGZvcm0nKTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBleGlzdGluZ0lmcmFtZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFxyXG4gICAgICB0aGlzLnNpbGVudFJlZnJlc2hJRnJhbWVOYW1lXHJcbiAgICApO1xyXG5cclxuICAgIGlmIChleGlzdGluZ0lmcmFtZSkge1xyXG4gICAgICBkb2N1bWVudC5ib2R5LnJlbW92ZUNoaWxkKGV4aXN0aW5nSWZyYW1lKTtcclxuICAgIH1cclxuXHJcbiAgICB0aGlzLnNpbGVudFJlZnJlc2hTdWJqZWN0ID0gY2xhaW1zWydzdWInXTtcclxuXHJcbiAgICBjb25zdCBpZnJhbWUgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdpZnJhbWUnKTtcclxuICAgIGlmcmFtZS5pZCA9IHRoaXMuc2lsZW50UmVmcmVzaElGcmFtZU5hbWU7XHJcblxyXG4gICAgdGhpcy5zZXR1cFNpbGVudFJlZnJlc2hFdmVudExpc3RlbmVyKCk7XHJcblxyXG4gICAgY29uc3QgcmVkaXJlY3RVcmkgPSB0aGlzLnNpbGVudFJlZnJlc2hSZWRpcmVjdFVyaSB8fCB0aGlzLnJlZGlyZWN0VXJpO1xyXG4gICAgdGhpcy5jcmVhdGVMb2dpblVybChudWxsLCBudWxsLCByZWRpcmVjdFVyaSwgbm9Qcm9tcHQsIHBhcmFtcykudGhlbih1cmwgPT4ge1xyXG4gICAgICBpZnJhbWUuc2V0QXR0cmlidXRlKCdzcmMnLCB1cmwpO1xyXG5cclxuICAgICAgaWYgKCF0aGlzLnNpbGVudFJlZnJlc2hTaG93SUZyYW1lKSB7XHJcbiAgICAgICAgaWZyYW1lLnN0eWxlWydkaXNwbGF5J10gPSAnbm9uZSc7XHJcbiAgICAgIH1cclxuICAgICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChpZnJhbWUpO1xyXG4gICAgfSk7XHJcblxyXG4gICAgY29uc3QgZXJyb3JzID0gdGhpcy5ldmVudHMucGlwZShcclxuICAgICAgZmlsdGVyKGUgPT4gZSBpbnN0YW5jZW9mIE9BdXRoRXJyb3JFdmVudCksXHJcbiAgICAgIGZpcnN0KClcclxuICAgICk7XHJcbiAgICBjb25zdCBzdWNjZXNzID0gdGhpcy5ldmVudHMucGlwZShcclxuICAgICAgZmlsdGVyKGUgPT4gZS50eXBlID09PSAndG9rZW5fcmVjZWl2ZWQnKSxcclxuICAgICAgZmlyc3QoKVxyXG4gICAgKTtcclxuICAgIGNvbnN0IHRpbWVvdXQgPSBvZihcclxuICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgnc2lsZW50X3JlZnJlc2hfdGltZW91dCcsIG51bGwpXHJcbiAgICApLnBpcGUoZGVsYXkodGhpcy5zaWxlbnRSZWZyZXNoVGltZW91dCkpO1xyXG5cclxuICAgIHJldHVybiByYWNlKFtlcnJvcnMsIHN1Y2Nlc3MsIHRpbWVvdXRdKVxyXG4gICAgICAucGlwZShcclxuICAgICAgICBtYXAoZSA9PiB7XHJcbiAgICAgICAgICBpZiAoZSBpbnN0YW5jZW9mIE9BdXRoRXJyb3JFdmVudCkge1xyXG4gICAgICAgICAgICBpZiAoZS50eXBlID09PSAnc2lsZW50X3JlZnJlc2hfdGltZW91dCcpIHtcclxuICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlKTtcclxuICAgICAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgICBlID0gbmV3IE9BdXRoRXJyb3JFdmVudCgnc2lsZW50X3JlZnJlc2hfZXJyb3InLCBlKTtcclxuICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICB0aHJvdyBlO1xyXG4gICAgICAgICAgfSBlbHNlIGlmIChlLnR5cGUgPT09ICd0b2tlbl9yZWNlaXZlZCcpIHtcclxuICAgICAgICAgICAgZSA9IG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgnc2lsZW50bHlfcmVmcmVzaGVkJyk7XHJcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGUpO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgcmV0dXJuIGU7XHJcbiAgICAgICAgfSlcclxuICAgICAgKVxyXG4gICAgICAudG9Qcm9taXNlKCk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBUaGlzIG1ldGhvZCBleGlzdHMgZm9yIGJhY2t3YXJkcyBjb21wYXRpYmlsaXR5LlxyXG4gICAqIHtAbGluayBPQXV0aFNlcnZpY2UjaW5pdExvZ2luRmxvd0luUG9wdXB9IGhhbmRsZXMgYm90aCBjb2RlXHJcbiAgICogYW5kIGltcGxpY2l0IGZsb3dzLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBpbml0SW1wbGljaXRGbG93SW5Qb3B1cChvcHRpb25zPzoge1xyXG4gICAgaGVpZ2h0PzogbnVtYmVyO1xyXG4gICAgd2lkdGg/OiBudW1iZXI7XHJcbiAgfSkge1xyXG4gICAgcmV0dXJuIHRoaXMuaW5pdExvZ2luRmxvd0luUG9wdXAob3B0aW9ucyk7XHJcbiAgfVxyXG5cclxuICBwdWJsaWMgaW5pdExvZ2luRmxvd0luUG9wdXAob3B0aW9ucz86IHsgaGVpZ2h0PzogbnVtYmVyOyB3aWR0aD86IG51bWJlciB9KSB7XHJcbiAgICBvcHRpb25zID0gb3B0aW9ucyB8fCB7fTtcclxuICAgIHJldHVybiB0aGlzLmNyZWF0ZUxvZ2luVXJsKFxyXG4gICAgICBudWxsLFxyXG4gICAgICBudWxsLFxyXG4gICAgICB0aGlzLnNpbGVudFJlZnJlc2hSZWRpcmVjdFVyaSxcclxuICAgICAgZmFsc2UsXHJcbiAgICAgIHtcclxuICAgICAgICBkaXNwbGF5OiAncG9wdXAnXHJcbiAgICAgIH1cclxuICAgICkudGhlbih1cmwgPT4ge1xyXG4gICAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xyXG4gICAgICAgIC8qKlxyXG4gICAgICAgICAqIEVycm9yIGhhbmRsaW5nIHNlY3Rpb25cclxuICAgICAgICAgKi9cclxuICAgICAgICBjb25zdCBjaGVja0ZvclBvcHVwQ2xvc2VkSW50ZXJ2YWwgPSA1MDA7XHJcbiAgICAgICAgbGV0IHdpbmRvd1JlZiA9IHdpbmRvdy5vcGVuKFxyXG4gICAgICAgICAgdXJsLFxyXG4gICAgICAgICAgJ19ibGFuaycsXHJcbiAgICAgICAgICB0aGlzLmNhbGN1bGF0ZVBvcHVwRmVhdHVyZXMob3B0aW9ucylcclxuICAgICAgICApO1xyXG4gICAgICAgIGxldCBjaGVja0ZvclBvcHVwQ2xvc2VkVGltZXI6IGFueTtcclxuICAgICAgICBjb25zdCBjaGVja0ZvclBvcHVwQ2xvc2VkID0gKCkgPT4ge1xyXG4gICAgICAgICAgaWYgKCF3aW5kb3dSZWYgfHwgd2luZG93UmVmLmNsb3NlZCkge1xyXG4gICAgICAgICAgICBjbGVhbnVwKCk7XHJcbiAgICAgICAgICAgIHJlamVjdChuZXcgT0F1dGhFcnJvckV2ZW50KCdwb3B1cF9jbG9zZWQnLCB7fSkpO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgIH07XHJcbiAgICAgICAgaWYgKCF3aW5kb3dSZWYpIHtcclxuICAgICAgICAgIHJlamVjdChuZXcgT0F1dGhFcnJvckV2ZW50KCdwb3B1cF9ibG9ja2VkJywge30pKTtcclxuICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgY2hlY2tGb3JQb3B1cENsb3NlZFRpbWVyID0gd2luZG93LnNldEludGVydmFsKFxyXG4gICAgICAgICAgICBjaGVja0ZvclBvcHVwQ2xvc2VkLFxyXG4gICAgICAgICAgICBjaGVja0ZvclBvcHVwQ2xvc2VkSW50ZXJ2YWxcclxuICAgICAgICAgICk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBjb25zdCBjbGVhbnVwID0gKCkgPT4ge1xyXG4gICAgICAgICAgd2luZG93LmNsZWFySW50ZXJ2YWwoY2hlY2tGb3JQb3B1cENsb3NlZFRpbWVyKTtcclxuICAgICAgICAgIHdpbmRvdy5yZW1vdmVFdmVudExpc3RlbmVyKCdtZXNzYWdlJywgbGlzdGVuZXIpO1xyXG4gICAgICAgICAgaWYgKHdpbmRvd1JlZiAhPT0gbnVsbCkge1xyXG4gICAgICAgICAgICB3aW5kb3dSZWYuY2xvc2UoKTtcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIHdpbmRvd1JlZiA9IG51bGw7XHJcbiAgICAgICAgfTtcclxuXHJcbiAgICAgICAgY29uc3QgbGlzdGVuZXIgPSAoZTogTWVzc2FnZUV2ZW50KSA9PiB7XHJcbiAgICAgICAgICBjb25zdCBtZXNzYWdlID0gdGhpcy5wcm9jZXNzTWVzc2FnZUV2ZW50TWVzc2FnZShlKTtcclxuXHJcbiAgICAgICAgICBpZiAobWVzc2FnZSAmJiBtZXNzYWdlICE9PSBudWxsKSB7XHJcbiAgICAgICAgICAgIHRoaXMudHJ5TG9naW4oe1xyXG4gICAgICAgICAgICAgIGN1c3RvbUhhc2hGcmFnbWVudDogbWVzc2FnZSxcclxuICAgICAgICAgICAgICBwcmV2ZW50Q2xlYXJIYXNoQWZ0ZXJMb2dpbjogdHJ1ZSxcclxuICAgICAgICAgICAgICBjdXN0b21SZWRpcmVjdFVyaTogdGhpcy5zaWxlbnRSZWZyZXNoUmVkaXJlY3RVcmlcclxuICAgICAgICAgICAgfSkudGhlbihcclxuICAgICAgICAgICAgICAoKSA9PiB7XHJcbiAgICAgICAgICAgICAgICBjbGVhbnVwKCk7XHJcbiAgICAgICAgICAgICAgICByZXNvbHZlKCk7XHJcbiAgICAgICAgICAgICAgfSxcclxuICAgICAgICAgICAgICBlcnIgPT4ge1xyXG4gICAgICAgICAgICAgICAgY2xlYW51cCgpO1xyXG4gICAgICAgICAgICAgICAgcmVqZWN0KGVycik7XHJcbiAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICApO1xyXG4gICAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgY29uc29sZS5sb2coJ2ZhbHNlIGV2ZW50IGZpcmluZycpO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgIH07XHJcblxyXG4gICAgICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKCdtZXNzYWdlJywgbGlzdGVuZXIpO1xyXG4gICAgICB9KTtcclxuICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGNhbGN1bGF0ZVBvcHVwRmVhdHVyZXMob3B0aW9uczoge1xyXG4gICAgaGVpZ2h0PzogbnVtYmVyO1xyXG4gICAgd2lkdGg/OiBudW1iZXI7XHJcbiAgfSk6IHN0cmluZyB7XHJcbiAgICAvLyBTcGVjaWZ5IGFuIHN0YXRpYyBoZWlnaHQgYW5kIHdpZHRoIGFuZCBjYWxjdWxhdGUgY2VudGVyZWQgcG9zaXRpb25cclxuXHJcbiAgICBjb25zdCBoZWlnaHQgPSBvcHRpb25zLmhlaWdodCB8fCA0NzA7XHJcbiAgICBjb25zdCB3aWR0aCA9IG9wdGlvbnMud2lkdGggfHwgNTAwO1xyXG4gICAgY29uc3QgbGVmdCA9IHdpbmRvdy5zY3JlZW5MZWZ0ICsgKHdpbmRvdy5vdXRlcldpZHRoIC0gd2lkdGgpIC8gMjtcclxuICAgIGNvbnN0IHRvcCA9IHdpbmRvdy5zY3JlZW5Ub3AgKyAod2luZG93Lm91dGVySGVpZ2h0IC0gaGVpZ2h0KSAvIDI7XHJcbiAgICByZXR1cm4gYGxvY2F0aW9uPW5vLHRvb2xiYXI9bm8sd2lkdGg9JHt3aWR0aH0saGVpZ2h0PSR7aGVpZ2h0fSx0b3A9JHt0b3B9LGxlZnQ9JHtsZWZ0fWA7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgcHJvY2Vzc01lc3NhZ2VFdmVudE1lc3NhZ2UoZTogTWVzc2FnZUV2ZW50KTogc3RyaW5nIHtcclxuICAgIGxldCBleHBlY3RlZFByZWZpeCA9ICcjJztcclxuXHJcbiAgICBpZiAodGhpcy5zaWxlbnRSZWZyZXNoTWVzc2FnZVByZWZpeCkge1xyXG4gICAgICBleHBlY3RlZFByZWZpeCArPSB0aGlzLnNpbGVudFJlZnJlc2hNZXNzYWdlUHJlZml4O1xyXG4gICAgfVxyXG5cclxuICAgIGlmICghZSB8fCAhZS5kYXRhIHx8IHR5cGVvZiBlLmRhdGEgIT09ICdzdHJpbmcnKSB7XHJcbiAgICAgIHJldHVybjtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBwcmVmaXhlZE1lc3NhZ2U6IHN0cmluZyA9IGUuZGF0YTtcclxuXHJcbiAgICBpZiAoIXByZWZpeGVkTWVzc2FnZS5zdGFydHNXaXRoKGV4cGVjdGVkUHJlZml4KSkge1xyXG4gICAgICByZXR1cm47XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuICcjJyArIHByZWZpeGVkTWVzc2FnZS5zdWJzdHIoZXhwZWN0ZWRQcmVmaXgubGVuZ3RoKTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBjYW5QZXJmb3JtU2Vzc2lvbkNoZWNrKCk6IGJvb2xlYW4ge1xyXG4gICAgaWYgKCF0aGlzLnNlc3Npb25DaGVja3NFbmFibGVkKSB7XHJcbiAgICAgIHJldHVybiBmYWxzZTtcclxuICAgIH1cclxuICAgIGlmICghdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVVcmwpIHtcclxuICAgICAgY29uc29sZS53YXJuKFxyXG4gICAgICAgICdzZXNzaW9uQ2hlY2tzRW5hYmxlZCBpcyBhY3RpdmF0ZWQgYnV0IHRoZXJlIGlzIG5vIHNlc3Npb25DaGVja0lGcmFtZVVybCdcclxuICAgICAgKTtcclxuICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgfVxyXG4gICAgY29uc3Qgc2Vzc2lvblN0YXRlID0gdGhpcy5nZXRTZXNzaW9uU3RhdGUoKTtcclxuICAgIGlmICghc2Vzc2lvblN0YXRlKSB7XHJcbiAgICAgIGNvbnNvbGUud2FybihcclxuICAgICAgICAnc2Vzc2lvbkNoZWNrc0VuYWJsZWQgaXMgYWN0aXZhdGVkIGJ1dCB0aGVyZSBpcyBubyBzZXNzaW9uX3N0YXRlJ1xyXG4gICAgICApO1xyXG4gICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICB9XHJcbiAgICBpZiAodHlwZW9mIGRvY3VtZW50ID09PSAndW5kZWZpbmVkJykge1xyXG4gICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIHRydWU7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgc2V0dXBTZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKCk6IHZvaWQge1xyXG4gICAgdGhpcy5yZW1vdmVTZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKCk7XHJcblxyXG4gICAgdGhpcy5zZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyID0gKGU6IE1lc3NhZ2VFdmVudCkgPT4ge1xyXG4gICAgICBjb25zdCBvcmlnaW4gPSBlLm9yaWdpbi50b0xvd2VyQ2FzZSgpO1xyXG4gICAgICBjb25zdCBpc3N1ZXIgPSB0aGlzLmlzc3Vlci50b0xvd2VyQ2FzZSgpO1xyXG5cclxuICAgICAgdGhpcy5kZWJ1Zygnc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcicpO1xyXG5cclxuICAgICAgaWYgKCFpc3N1ZXIuc3RhcnRzV2l0aChvcmlnaW4pKSB7XHJcbiAgICAgICAgdGhpcy5kZWJ1ZyhcclxuICAgICAgICAgICdzZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyJyxcclxuICAgICAgICAgICd3cm9uZyBvcmlnaW4nLFxyXG4gICAgICAgICAgb3JpZ2luLFxyXG4gICAgICAgICAgJ2V4cGVjdGVkJyxcclxuICAgICAgICAgIGlzc3VlcixcclxuICAgICAgICAgICdldmVudCcsXHJcbiAgICAgICAgICBlXHJcbiAgICAgICAgKTtcclxuXHJcbiAgICAgICAgcmV0dXJuO1xyXG4gICAgICB9XHJcblxyXG4gICAgICAvLyBvbmx5IHJ1biBpbiBBbmd1bGFyIHpvbmUgaWYgaXQgaXMgJ2NoYW5nZWQnIG9yICdlcnJvcidcclxuICAgICAgc3dpdGNoIChlLmRhdGEpIHtcclxuICAgICAgICBjYXNlICd1bmNoYW5nZWQnOlxyXG4gICAgICAgICAgdGhpcy5oYW5kbGVTZXNzaW9uVW5jaGFuZ2VkKCk7XHJcbiAgICAgICAgICBicmVhaztcclxuICAgICAgICBjYXNlICdjaGFuZ2VkJzpcclxuICAgICAgICAgIHRoaXMubmdab25lLnJ1bigoKSA9PiB7XHJcbiAgICAgICAgICAgIHRoaXMuaGFuZGxlU2Vzc2lvbkNoYW5nZSgpO1xyXG4gICAgICAgICAgfSk7XHJcbiAgICAgICAgICBicmVhaztcclxuICAgICAgICBjYXNlICdlcnJvcic6XHJcbiAgICAgICAgICB0aGlzLm5nWm9uZS5ydW4oKCkgPT4ge1xyXG4gICAgICAgICAgICB0aGlzLmhhbmRsZVNlc3Npb25FcnJvcigpO1xyXG4gICAgICAgICAgfSk7XHJcbiAgICAgICAgICBicmVhaztcclxuICAgICAgfVxyXG5cclxuICAgICAgdGhpcy5kZWJ1ZygnZ290IGluZm8gZnJvbSBzZXNzaW9uIGNoZWNrIGluZnJhbWUnLCBlKTtcclxuICAgIH07XHJcblxyXG4gICAgLy8gcHJldmVudCBBbmd1bGFyIGZyb20gcmVmcmVzaGluZyB0aGUgdmlldyBvbiBldmVyeSBtZXNzYWdlIChydW5zIGluIGludGVydmFscylcclxuICAgIHRoaXMubmdab25lLnJ1bk91dHNpZGVBbmd1bGFyKCgpID0+IHtcclxuICAgICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoJ21lc3NhZ2UnLCB0aGlzLnNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIpO1xyXG4gICAgfSk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgaGFuZGxlU2Vzc2lvblVuY2hhbmdlZCgpOiB2b2lkIHtcclxuICAgIHRoaXMuZGVidWcoJ3Nlc3Npb24gY2hlY2snLCAnc2Vzc2lvbiB1bmNoYW5nZWQnKTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBoYW5kbGVTZXNzaW9uQ2hhbmdlKCk6IHZvaWQge1xyXG4gICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoSW5mb0V2ZW50KCdzZXNzaW9uX2NoYW5nZWQnKSk7XHJcbiAgICB0aGlzLnN0b3BTZXNzaW9uQ2hlY2tUaW1lcigpO1xyXG5cclxuICAgIGlmICghdGhpcy51c2VTaWxlbnRSZWZyZXNoICYmIHRoaXMucmVzcG9uc2VUeXBlID09PSAnY29kZScpIHtcclxuICAgICAgdGhpcy5yZWZyZXNoVG9rZW4oKVxyXG4gICAgICAgIC50aGVuKF8gPT4ge1xyXG4gICAgICAgICAgdGhpcy5kZWJ1ZygndG9rZW4gcmVmcmVzaCBhZnRlciBzZXNzaW9uIGNoYW5nZSB3b3JrZWQnKTtcclxuICAgICAgICB9KVxyXG4gICAgICAgIC5jYXRjaChfID0+IHtcclxuICAgICAgICAgIHRoaXMuZGVidWcoJ3Rva2VuIHJlZnJlc2ggZGlkIG5vdCB3b3JrIGFmdGVyIHNlc3Npb24gY2hhbmdlZCcpO1xyXG4gICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoSW5mb0V2ZW50KCdzZXNzaW9uX3Rlcm1pbmF0ZWQnKSk7XHJcbiAgICAgICAgICB0aGlzLmxvZ091dCh0cnVlKTtcclxuICAgICAgICB9KTtcclxuICAgIH0gZWxzZSBpZiAodGhpcy5zaWxlbnRSZWZyZXNoUmVkaXJlY3RVcmkpIHtcclxuICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoKCkuY2F0Y2goXyA9PlxyXG4gICAgICAgIHRoaXMuZGVidWcoJ3NpbGVudCByZWZyZXNoIGZhaWxlZCBhZnRlciBzZXNzaW9uIGNoYW5nZWQnKVxyXG4gICAgICApO1xyXG4gICAgICB0aGlzLndhaXRGb3JTaWxlbnRSZWZyZXNoQWZ0ZXJTZXNzaW9uQ2hhbmdlKCk7XHJcbiAgICB9IGVsc2Uge1xyXG4gICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhJbmZvRXZlbnQoJ3Nlc3Npb25fdGVybWluYXRlZCcpKTtcclxuICAgICAgdGhpcy5sb2dPdXQodHJ1ZSk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgd2FpdEZvclNpbGVudFJlZnJlc2hBZnRlclNlc3Npb25DaGFuZ2UoKTogdm9pZCB7XHJcbiAgICB0aGlzLmV2ZW50c1xyXG4gICAgICAucGlwZShcclxuICAgICAgICBmaWx0ZXIoXHJcbiAgICAgICAgICAoZTogT0F1dGhFdmVudCkgPT5cclxuICAgICAgICAgICAgZS50eXBlID09PSAnc2lsZW50bHlfcmVmcmVzaGVkJyB8fFxyXG4gICAgICAgICAgICBlLnR5cGUgPT09ICdzaWxlbnRfcmVmcmVzaF90aW1lb3V0JyB8fFxyXG4gICAgICAgICAgICBlLnR5cGUgPT09ICdzaWxlbnRfcmVmcmVzaF9lcnJvcidcclxuICAgICAgICApLFxyXG4gICAgICAgIGZpcnN0KClcclxuICAgICAgKVxyXG4gICAgICAuc3Vic2NyaWJlKGUgPT4ge1xyXG4gICAgICAgIGlmIChlLnR5cGUgIT09ICdzaWxlbnRseV9yZWZyZXNoZWQnKSB7XHJcbiAgICAgICAgICB0aGlzLmRlYnVnKCdzaWxlbnQgcmVmcmVzaCBkaWQgbm90IHdvcmsgYWZ0ZXIgc2Vzc2lvbiBjaGFuZ2VkJyk7XHJcbiAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhJbmZvRXZlbnQoJ3Nlc3Npb25fdGVybWluYXRlZCcpKTtcclxuICAgICAgICAgIHRoaXMubG9nT3V0KHRydWUpO1xyXG4gICAgICAgIH1cclxuICAgICAgfSk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgaGFuZGxlU2Vzc2lvbkVycm9yKCk6IHZvaWQge1xyXG4gICAgdGhpcy5zdG9wU2Vzc2lvbkNoZWNrVGltZXIoKTtcclxuICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aEluZm9FdmVudCgnc2Vzc2lvbl9lcnJvcicpKTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCByZW1vdmVTZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKCk6IHZvaWQge1xyXG4gICAgaWYgKHRoaXMuc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcikge1xyXG4gICAgICB3aW5kb3cucmVtb3ZlRXZlbnRMaXN0ZW5lcignbWVzc2FnZScsIHRoaXMuc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcik7XHJcbiAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lciA9IG51bGw7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgaW5pdFNlc3Npb25DaGVjaygpOiB2b2lkIHtcclxuICAgIGlmICghdGhpcy5jYW5QZXJmb3JtU2Vzc2lvbkNoZWNrKCkpIHtcclxuICAgICAgcmV0dXJuO1xyXG4gICAgfVxyXG5cclxuICAgIGNvbnN0IGV4aXN0aW5nSWZyYW1lID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQodGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVOYW1lKTtcclxuICAgIGlmIChleGlzdGluZ0lmcmFtZSkge1xyXG4gICAgICBkb2N1bWVudC5ib2R5LnJlbW92ZUNoaWxkKGV4aXN0aW5nSWZyYW1lKTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBpZnJhbWUgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdpZnJhbWUnKTtcclxuICAgIGlmcmFtZS5pZCA9IHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lTmFtZTtcclxuXHJcbiAgICB0aGlzLnNldHVwU2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcigpO1xyXG5cclxuICAgIGNvbnN0IHVybCA9IHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lVXJsO1xyXG4gICAgaWZyYW1lLnNldEF0dHJpYnV0ZSgnc3JjJywgdXJsKTtcclxuICAgIGlmcmFtZS5zdHlsZS5kaXNwbGF5ID0gJ25vbmUnO1xyXG4gICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChpZnJhbWUpO1xyXG5cclxuICAgIHRoaXMuc3RhcnRTZXNzaW9uQ2hlY2tUaW1lcigpO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHN0YXJ0U2Vzc2lvbkNoZWNrVGltZXIoKTogdm9pZCB7XHJcbiAgICB0aGlzLnN0b3BTZXNzaW9uQ2hlY2tUaW1lcigpO1xyXG4gICAgdGhpcy5uZ1pvbmUucnVuT3V0c2lkZUFuZ3VsYXIoKCkgPT4ge1xyXG4gICAgICB0aGlzLnNlc3Npb25DaGVja1RpbWVyID0gc2V0SW50ZXJ2YWwoXHJcbiAgICAgICAgdGhpcy5jaGVja1Nlc3Npb24uYmluZCh0aGlzKSxcclxuICAgICAgICB0aGlzLnNlc3Npb25DaGVja0ludGVydmFsbFxyXG4gICAgICApO1xyXG4gICAgfSk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgc3RvcFNlc3Npb25DaGVja1RpbWVyKCk6IHZvaWQge1xyXG4gICAgaWYgKHRoaXMuc2Vzc2lvbkNoZWNrVGltZXIpIHtcclxuICAgICAgY2xlYXJJbnRlcnZhbCh0aGlzLnNlc3Npb25DaGVja1RpbWVyKTtcclxuICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tUaW1lciA9IG51bGw7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBwdWJsaWMgY2hlY2tTZXNzaW9uKCk6IHZvaWQge1xyXG4gICAgY29uc3QgaWZyYW1lOiBhbnkgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCh0aGlzLnNlc3Npb25DaGVja0lGcmFtZU5hbWUpO1xyXG5cclxuICAgIGlmICghaWZyYW1lKSB7XHJcbiAgICAgIHRoaXMubG9nZ2VyLndhcm4oXHJcbiAgICAgICAgJ2NoZWNrU2Vzc2lvbiBkaWQgbm90IGZpbmQgaWZyYW1lJyxcclxuICAgICAgICB0aGlzLnNlc3Npb25DaGVja0lGcmFtZU5hbWVcclxuICAgICAgKTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBzZXNzaW9uU3RhdGUgPSB0aGlzLmdldFNlc3Npb25TdGF0ZSgpO1xyXG5cclxuICAgIGlmICghc2Vzc2lvblN0YXRlKSB7XHJcbiAgICAgIHRoaXMuc3RvcFNlc3Npb25DaGVja1RpbWVyKCk7XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3QgbWVzc2FnZSA9IHRoaXMuY2xpZW50SWQgKyAnICcgKyBzZXNzaW9uU3RhdGU7XHJcbiAgICBpZnJhbWUuY29udGVudFdpbmRvdy5wb3N0TWVzc2FnZShtZXNzYWdlLCB0aGlzLmlzc3Vlcik7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgYXN5bmMgY3JlYXRlTG9naW5VcmwoXHJcbiAgICBzdGF0ZSA9ICcnLFxyXG4gICAgbG9naW5IaW50ID0gJycsXHJcbiAgICBjdXN0b21SZWRpcmVjdFVyaSA9ICcnLFxyXG4gICAgbm9Qcm9tcHQgPSBmYWxzZSxcclxuICAgIHBhcmFtczogb2JqZWN0ID0ge31cclxuICApOiBQcm9taXNlPHN0cmluZz4ge1xyXG4gICAgY29uc3QgdGhhdCA9IHRoaXM7XHJcblxyXG4gICAgbGV0IHJlZGlyZWN0VXJpOiBzdHJpbmc7XHJcblxyXG4gICAgaWYgKGN1c3RvbVJlZGlyZWN0VXJpKSB7XHJcbiAgICAgIHJlZGlyZWN0VXJpID0gY3VzdG9tUmVkaXJlY3RVcmk7XHJcbiAgICB9IGVsc2Uge1xyXG4gICAgICByZWRpcmVjdFVyaSA9IHRoaXMucmVkaXJlY3RVcmk7XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3Qgbm9uY2UgPSBhd2FpdCB0aGlzLmNyZWF0ZUFuZFNhdmVOb25jZSgpO1xyXG5cclxuICAgIGlmIChzdGF0ZSkge1xyXG4gICAgICBzdGF0ZSA9XHJcbiAgICAgICAgbm9uY2UgKyB0aGlzLmNvbmZpZy5ub25jZVN0YXRlU2VwYXJhdG9yICsgZW5jb2RlVVJJQ29tcG9uZW50KHN0YXRlKTtcclxuICAgIH0gZWxzZSB7XHJcbiAgICAgIHN0YXRlID0gbm9uY2U7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKCF0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhdGhpcy5vaWRjKSB7XHJcbiAgICAgIHRocm93IG5ldyBFcnJvcignRWl0aGVyIHJlcXVlc3RBY2Nlc3NUb2tlbiBvciBvaWRjIG9yIGJvdGggbXVzdCBiZSB0cnVlJyk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHRoaXMuY29uZmlnLnJlc3BvbnNlVHlwZSkge1xyXG4gICAgICB0aGlzLnJlc3BvbnNlVHlwZSA9IHRoaXMuY29uZmlnLnJlc3BvbnNlVHlwZTtcclxuICAgIH0gZWxzZSB7XHJcbiAgICAgIGlmICh0aGlzLm9pZGMgJiYgdGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4pIHtcclxuICAgICAgICB0aGlzLnJlc3BvbnNlVHlwZSA9ICdpZF90b2tlbiB0b2tlbic7XHJcbiAgICAgIH0gZWxzZSBpZiAodGhpcy5vaWRjICYmICF0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbikge1xyXG4gICAgICAgIHRoaXMucmVzcG9uc2VUeXBlID0gJ2lkX3Rva2VuJztcclxuICAgICAgfSBlbHNlIHtcclxuICAgICAgICB0aGlzLnJlc3BvbnNlVHlwZSA9ICd0b2tlbic7XHJcbiAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBzZXBlcmF0aW9uQ2hhciA9IHRoYXQubG9naW5VcmwuaW5kZXhPZignPycpID4gLTEgPyAnJicgOiAnPyc7XHJcblxyXG4gICAgbGV0IHNjb3BlID0gdGhhdC5zY29wZTtcclxuXHJcbiAgICBpZiAodGhpcy5vaWRjICYmICFzY29wZS5tYXRjaCgvKF58XFxzKW9wZW5pZCgkfFxccykvKSkge1xyXG4gICAgICBzY29wZSA9ICdvcGVuaWQgJyArIHNjb3BlO1xyXG4gICAgfVxyXG5cclxuICAgIGxldCB1cmwgPVxyXG4gICAgICB0aGF0LmxvZ2luVXJsICtcclxuICAgICAgc2VwZXJhdGlvbkNoYXIgK1xyXG4gICAgICAncmVzcG9uc2VfdHlwZT0nICtcclxuICAgICAgZW5jb2RlVVJJQ29tcG9uZW50KHRoYXQucmVzcG9uc2VUeXBlKSArXHJcbiAgICAgICcmY2xpZW50X2lkPScgK1xyXG4gICAgICBlbmNvZGVVUklDb21wb25lbnQodGhhdC5jbGllbnRJZCkgK1xyXG4gICAgICAnJnN0YXRlPScgK1xyXG4gICAgICBlbmNvZGVVUklDb21wb25lbnQoc3RhdGUpICtcclxuICAgICAgJyZyZWRpcmVjdF91cmk9JyArXHJcbiAgICAgIGVuY29kZVVSSUNvbXBvbmVudChyZWRpcmVjdFVyaSkgK1xyXG4gICAgICAnJnNjb3BlPScgK1xyXG4gICAgICBlbmNvZGVVUklDb21wb25lbnQoc2NvcGUpO1xyXG5cclxuICAgIGlmICh0aGlzLnJlc3BvbnNlVHlwZSA9PT0gJ2NvZGUnICYmICF0aGlzLmRpc2FibGVQS0NFKSB7XHJcbiAgICAgIGNvbnN0IFtcclxuICAgICAgICBjaGFsbGVuZ2UsXHJcbiAgICAgICAgdmVyaWZpZXJcclxuICAgICAgXSA9IGF3YWl0IHRoaXMuY3JlYXRlQ2hhbGxhbmdlVmVyaWZpZXJQYWlyRm9yUEtDRSgpO1xyXG5cclxuICAgICAgaWYgKFxyXG4gICAgICAgIHRoaXMuc2F2ZU5vbmNlc0luTG9jYWxTdG9yYWdlICYmXHJcbiAgICAgICAgdHlwZW9mIHdpbmRvd1snbG9jYWxTdG9yYWdlJ10gIT09ICd1bmRlZmluZWQnXHJcbiAgICAgICkge1xyXG4gICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCdQS0NJX3ZlcmlmaWVyJywgdmVyaWZpZXIpO1xyXG4gICAgICB9IGVsc2Uge1xyXG4gICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnUEtDSV92ZXJpZmllcicsIHZlcmlmaWVyKTtcclxuICAgICAgfVxyXG5cclxuICAgICAgdXJsICs9ICcmY29kZV9jaGFsbGVuZ2U9JyArIGNoYWxsZW5nZTtcclxuICAgICAgdXJsICs9ICcmY29kZV9jaGFsbGVuZ2VfbWV0aG9kPVMyNTYnO1xyXG4gICAgfVxyXG5cclxuICAgIGlmIChsb2dpbkhpbnQpIHtcclxuICAgICAgdXJsICs9ICcmbG9naW5faGludD0nICsgZW5jb2RlVVJJQ29tcG9uZW50KGxvZ2luSGludCk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHRoYXQucmVzb3VyY2UpIHtcclxuICAgICAgdXJsICs9ICcmcmVzb3VyY2U9JyArIGVuY29kZVVSSUNvbXBvbmVudCh0aGF0LnJlc291cmNlKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAodGhhdC5vaWRjKSB7XHJcbiAgICAgIHVybCArPSAnJm5vbmNlPScgKyBlbmNvZGVVUklDb21wb25lbnQobm9uY2UpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmIChub1Byb21wdCkge1xyXG4gICAgICB1cmwgKz0gJyZwcm9tcHQ9bm9uZSc7XHJcbiAgICB9XHJcblxyXG4gICAgZm9yIChjb25zdCBrZXkgb2YgT2JqZWN0LmtleXMocGFyYW1zKSkge1xyXG4gICAgICB1cmwgKz1cclxuICAgICAgICAnJicgKyBlbmNvZGVVUklDb21wb25lbnQoa2V5KSArICc9JyArIGVuY29kZVVSSUNvbXBvbmVudChwYXJhbXNba2V5XSk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpIHtcclxuICAgICAgZm9yIChjb25zdCBrZXkgb2YgT2JqZWN0LmdldE93blByb3BlcnR5TmFtZXModGhpcy5jdXN0b21RdWVyeVBhcmFtcykpIHtcclxuICAgICAgICB1cmwgKz1cclxuICAgICAgICAgICcmJyArIGtleSArICc9JyArIGVuY29kZVVSSUNvbXBvbmVudCh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zW2tleV0pO1xyXG4gICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIHVybDtcclxuICB9XHJcblxyXG4gIGluaXRJbXBsaWNpdEZsb3dJbnRlcm5hbChcclxuICAgIGFkZGl0aW9uYWxTdGF0ZSA9ICcnLFxyXG4gICAgcGFyYW1zOiBzdHJpbmcgfCBvYmplY3QgPSAnJ1xyXG4gICk6IHZvaWQge1xyXG4gICAgaWYgKHRoaXMuaW5JbXBsaWNpdEZsb3cpIHtcclxuICAgICAgcmV0dXJuO1xyXG4gICAgfVxyXG5cclxuICAgIHRoaXMuaW5JbXBsaWNpdEZsb3cgPSB0cnVlO1xyXG5cclxuICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHRoaXMubG9naW5VcmwpKSB7XHJcbiAgICAgIHRocm93IG5ldyBFcnJvcihcclxuICAgICAgICBcImxvZ2luVXJsICBtdXN0IHVzZSBIVFRQUyAod2l0aCBUTFMpLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5ICdyZXF1aXJlSHR0cHMnIG11c3QgYmUgc2V0IHRvICdmYWxzZScgYW5kIGFsbG93IEhUVFAgKHdpdGhvdXQgVExTKS5cIlxyXG4gICAgICApO1xyXG4gICAgfVxyXG5cclxuICAgIGxldCBhZGRQYXJhbXM6IG9iamVjdCA9IHt9O1xyXG4gICAgbGV0IGxvZ2luSGludDogc3RyaW5nID0gbnVsbDtcclxuXHJcbiAgICBpZiAodHlwZW9mIHBhcmFtcyA9PT0gJ3N0cmluZycpIHtcclxuICAgICAgbG9naW5IaW50ID0gcGFyYW1zO1xyXG4gICAgfSBlbHNlIGlmICh0eXBlb2YgcGFyYW1zID09PSAnb2JqZWN0Jykge1xyXG4gICAgICBhZGRQYXJhbXMgPSBwYXJhbXM7XHJcbiAgICB9XHJcblxyXG4gICAgdGhpcy5jcmVhdGVMb2dpblVybChhZGRpdGlvbmFsU3RhdGUsIGxvZ2luSGludCwgbnVsbCwgZmFsc2UsIGFkZFBhcmFtcylcclxuICAgICAgLnRoZW4odGhpcy5jb25maWcub3BlblVyaSlcclxuICAgICAgLmNhdGNoKGVycm9yID0+IHtcclxuICAgICAgICBjb25zb2xlLmVycm9yKCdFcnJvciBpbiBpbml0SW1wbGljaXRGbG93JywgZXJyb3IpO1xyXG4gICAgICAgIHRoaXMuaW5JbXBsaWNpdEZsb3cgPSBmYWxzZTtcclxuICAgICAgfSk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBTdGFydHMgdGhlIGltcGxpY2l0IGZsb3cgYW5kIHJlZGlyZWN0cyB0byB1c2VyIHRvXHJcbiAgICogdGhlIGF1dGggc2VydmVycycgbG9naW4gdXJsLlxyXG4gICAqXHJcbiAgICogQHBhcmFtIGFkZGl0aW9uYWxTdGF0ZSBPcHRpb25hbCBzdGF0ZSB0aGF0IGlzIHBhc3NlZCBhcm91bmQuXHJcbiAgICogIFlvdSdsbCBmaW5kIHRoaXMgc3RhdGUgaW4gdGhlIHByb3BlcnR5IGBzdGF0ZWAgYWZ0ZXIgYHRyeUxvZ2luYCBsb2dnZWQgaW4gdGhlIHVzZXIuXHJcbiAgICogQHBhcmFtIHBhcmFtcyBIYXNoIHdpdGggYWRkaXRpb25hbCBwYXJhbWV0ZXIuIElmIGl0IGlzIGEgc3RyaW5nLCBpdCBpcyB1c2VkIGZvciB0aGVcclxuICAgKiAgICAgICAgICAgICAgIHBhcmFtZXRlciBsb2dpbkhpbnQgKGZvciB0aGUgc2FrZSBvZiBjb21wYXRpYmlsaXR5IHdpdGggZm9ybWVyIHZlcnNpb25zKVxyXG4gICAqL1xyXG4gIHB1YmxpYyBpbml0SW1wbGljaXRGbG93KFxyXG4gICAgYWRkaXRpb25hbFN0YXRlID0gJycsXHJcbiAgICBwYXJhbXM6IHN0cmluZyB8IG9iamVjdCA9ICcnXHJcbiAgKTogdm9pZCB7XHJcbiAgICBpZiAodGhpcy5sb2dpblVybCAhPT0gJycpIHtcclxuICAgICAgdGhpcy5pbml0SW1wbGljaXRGbG93SW50ZXJuYWwoYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpO1xyXG4gICAgfSBlbHNlIHtcclxuICAgICAgdGhpcy5ldmVudHNcclxuICAgICAgICAucGlwZShmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZGVkJykpXHJcbiAgICAgICAgLnN1YnNjcmliZShfID0+IHRoaXMuaW5pdEltcGxpY2l0Rmxvd0ludGVybmFsKGFkZGl0aW9uYWxTdGF0ZSwgcGFyYW1zKSk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBSZXNldCBjdXJyZW50IGltcGxpY2l0IGZsb3dcclxuICAgKlxyXG4gICAqIEBkZXNjcmlwdGlvbiBUaGlzIG1ldGhvZCBhbGxvd3MgcmVzZXR0aW5nIHRoZSBjdXJyZW50IGltcGxpY3QgZmxvdyBpbiBvcmRlciB0byBiZSBpbml0aWFsaXplZCBhZ2Fpbi5cclxuICAgKi9cclxuICBwdWJsaWMgcmVzZXRJbXBsaWNpdEZsb3coKTogdm9pZCB7XHJcbiAgICB0aGlzLmluSW1wbGljaXRGbG93ID0gZmFsc2U7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgY2FsbE9uVG9rZW5SZWNlaXZlZElmRXhpc3RzKG9wdGlvbnM6IExvZ2luT3B0aW9ucyk6IHZvaWQge1xyXG4gICAgY29uc3QgdGhhdCA9IHRoaXM7XHJcbiAgICBpZiAob3B0aW9ucy5vblRva2VuUmVjZWl2ZWQpIHtcclxuICAgICAgY29uc3QgdG9rZW5QYXJhbXMgPSB7XHJcbiAgICAgICAgaWRDbGFpbXM6IHRoYXQuZ2V0SWRlbnRpdHlDbGFpbXMoKSxcclxuICAgICAgICBpZFRva2VuOiB0aGF0LmdldElkVG9rZW4oKSxcclxuICAgICAgICBhY2Nlc3NUb2tlbjogdGhhdC5nZXRBY2Nlc3NUb2tlbigpLFxyXG4gICAgICAgIHN0YXRlOiB0aGF0LnN0YXRlXHJcbiAgICAgIH07XHJcbiAgICAgIG9wdGlvbnMub25Ub2tlblJlY2VpdmVkKHRva2VuUGFyYW1zKTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBzdG9yZUFjY2Vzc1Rva2VuUmVzcG9uc2UoXHJcbiAgICBhY2Nlc3NUb2tlbjogc3RyaW5nLFxyXG4gICAgcmVmcmVzaFRva2VuOiBzdHJpbmcsXHJcbiAgICBleHBpcmVzSW46IG51bWJlcixcclxuICAgIGdyYW50ZWRTY29wZXM6IFN0cmluZyxcclxuICAgIGN1c3RvbVBhcmFtZXRlcnM/OiBNYXA8c3RyaW5nLCBzdHJpbmc+XHJcbiAgKTogdm9pZCB7XHJcbiAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2FjY2Vzc190b2tlbicsIGFjY2Vzc1Rva2VuKTtcclxuICAgIGlmIChncmFudGVkU2NvcGVzICYmICFBcnJheS5pc0FycmF5KGdyYW50ZWRTY29wZXMpKSB7XHJcbiAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbShcclxuICAgICAgICAnZ3JhbnRlZF9zY29wZXMnLFxyXG4gICAgICAgIEpTT04uc3RyaW5naWZ5KGdyYW50ZWRTY29wZXMuc3BsaXQoJysnKSlcclxuICAgICAgKTtcclxuICAgIH0gZWxzZSBpZiAoZ3JhbnRlZFNjb3BlcyAmJiBBcnJheS5pc0FycmF5KGdyYW50ZWRTY29wZXMpKSB7XHJcbiAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnZ3JhbnRlZF9zY29wZXMnLCBKU09OLnN0cmluZ2lmeShncmFudGVkU2NvcGVzKSk7XHJcbiAgICB9XHJcblxyXG4gICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdhY2Nlc3NfdG9rZW5fc3RvcmVkX2F0JywgJycgKyBEYXRlLm5vdygpKTtcclxuICAgIGlmIChleHBpcmVzSW4pIHtcclxuICAgICAgY29uc3QgZXhwaXJlc0luTWlsbGlTZWNvbmRzID0gZXhwaXJlc0luICogMTAwMDtcclxuICAgICAgY29uc3Qgbm93ID0gbmV3IERhdGUoKTtcclxuICAgICAgY29uc3QgZXhwaXJlc0F0ID0gbm93LmdldFRpbWUoKSArIGV4cGlyZXNJbk1pbGxpU2Vjb25kcztcclxuICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdleHBpcmVzX2F0JywgJycgKyBleHBpcmVzQXQpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmIChyZWZyZXNoVG9rZW4pIHtcclxuICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdyZWZyZXNoX3Rva2VuJywgcmVmcmVzaFRva2VuKTtcclxuICAgIH1cclxuICAgIGlmIChjdXN0b21QYXJhbWV0ZXJzKSB7XHJcbiAgICAgIGN1c3RvbVBhcmFtZXRlcnMuZm9yRWFjaCgodmFsdWU6IHN0cmluZywga2V5OiBzdHJpbmcpID0+IHtcclxuICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oa2V5LCB2YWx1ZSk7XHJcbiAgICAgIH0pO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogRGVsZWdhdGVzIHRvIHRyeUxvZ2luSW1wbGljaXRGbG93IGZvciB0aGUgc2FrZSBvZiBjb21wZXRhYmlsaXR5XHJcbiAgICogQHBhcmFtIG9wdGlvbnMgT3B0aW9uYWwgb3B0aW9ucy5cclxuICAgKi9cclxuICBwdWJsaWMgdHJ5TG9naW4ob3B0aW9uczogTG9naW5PcHRpb25zID0gbnVsbCk6IFByb21pc2U8Ym9vbGVhbj4ge1xyXG4gICAgaWYgKHRoaXMuY29uZmlnLnJlc3BvbnNlVHlwZSA9PT0gJ2NvZGUnKSB7XHJcbiAgICAgIHJldHVybiB0aGlzLnRyeUxvZ2luQ29kZUZsb3cob3B0aW9ucykudGhlbihfID0+IHRydWUpO1xyXG4gICAgfSBlbHNlIHtcclxuICAgICAgcmV0dXJuIHRoaXMudHJ5TG9naW5JbXBsaWNpdEZsb3cob3B0aW9ucyk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBwcml2YXRlIHBhcnNlUXVlcnlTdHJpbmcocXVlcnlTdHJpbmc6IHN0cmluZyk6IG9iamVjdCB7XHJcbiAgICBpZiAoIXF1ZXJ5U3RyaW5nIHx8IHF1ZXJ5U3RyaW5nLmxlbmd0aCA9PT0gMCkge1xyXG4gICAgICByZXR1cm4ge307XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHF1ZXJ5U3RyaW5nLmNoYXJBdCgwKSA9PT0gJz8nKSB7XHJcbiAgICAgIHF1ZXJ5U3RyaW5nID0gcXVlcnlTdHJpbmcuc3Vic3RyKDEpO1xyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiB0aGlzLnVybEhlbHBlci5wYXJzZVF1ZXJ5U3RyaW5nKHF1ZXJ5U3RyaW5nKTtcclxuICB9XHJcblxyXG4gIHB1YmxpYyB0cnlMb2dpbkNvZGVGbG93KG9wdGlvbnM6IExvZ2luT3B0aW9ucyA9IG51bGwpOiBQcm9taXNlPHZvaWQ+IHtcclxuICAgIG9wdGlvbnMgPSBvcHRpb25zIHx8IHt9O1xyXG5cclxuICAgIGNvbnN0IHF1ZXJ5U291cmNlID0gb3B0aW9ucy5jdXN0b21IYXNoRnJhZ21lbnRcclxuICAgICAgPyBvcHRpb25zLmN1c3RvbUhhc2hGcmFnbWVudC5zdWJzdHJpbmcoMSlcclxuICAgICAgOiB3aW5kb3cubG9jYXRpb24uc2VhcmNoO1xyXG5cclxuICAgIGNvbnN0IHBhcnRzID0gdGhpcy5nZXRDb2RlUGFydHNGcm9tVXJsKHF1ZXJ5U291cmNlKTtcclxuXHJcbiAgICBjb25zdCBjb2RlID0gcGFydHNbJ2NvZGUnXTtcclxuICAgIGNvbnN0IHN0YXRlID0gcGFydHNbJ3N0YXRlJ107XHJcblxyXG4gICAgY29uc3Qgc2Vzc2lvblN0YXRlID0gcGFydHNbJ3Nlc3Npb25fc3RhdGUnXTtcclxuXHJcbiAgICBpZiAoIW9wdGlvbnMucHJldmVudENsZWFySGFzaEFmdGVyTG9naW4pIHtcclxuICAgICAgY29uc3QgaHJlZiA9IGxvY2F0aW9uLmhyZWZcclxuICAgICAgICAucmVwbGFjZSgvWyZcXD9dY29kZT1bXiZcXCRdKi8sICcnKVxyXG4gICAgICAgIC5yZXBsYWNlKC9bJlxcP11zY29wZT1bXiZcXCRdKi8sICcnKVxyXG4gICAgICAgIC5yZXBsYWNlKC9bJlxcP11zdGF0ZT1bXiZcXCRdKi8sICcnKVxyXG4gICAgICAgIC5yZXBsYWNlKC9bJlxcP11zZXNzaW9uX3N0YXRlPVteJlxcJF0qLywgJycpO1xyXG5cclxuICAgICAgaGlzdG9yeS5yZXBsYWNlU3RhdGUobnVsbCwgd2luZG93Lm5hbWUsIGhyZWYpO1xyXG4gICAgfVxyXG5cclxuICAgIGxldCBbbm9uY2VJblN0YXRlLCB1c2VyU3RhdGVdID0gdGhpcy5wYXJzZVN0YXRlKHN0YXRlKTtcclxuICAgIHRoaXMuc3RhdGUgPSB1c2VyU3RhdGU7XHJcblxyXG4gICAgaWYgKHBhcnRzWydlcnJvciddKSB7XHJcbiAgICAgIHRoaXMuZGVidWcoJ2Vycm9yIHRyeWluZyB0byBsb2dpbicpO1xyXG4gICAgICB0aGlzLmhhbmRsZUxvZ2luRXJyb3Ioe30sIHBhcnRzKTtcclxuICAgICAgY29uc3QgZXJyID0gbmV3IE9BdXRoRXJyb3JFdmVudCgnY29kZV9lcnJvcicsIHt9LCBwYXJ0cyk7XHJcbiAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGVycik7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xyXG4gICAgfVxyXG4gICAgbm9uY2VJblN0YXRlID0gc2Vzc2lvblN0b3JhZ2UuZ2V0SXRlbSgnbm9uY2UnKTtcclxuICAgIGlmICghbm9uY2VJblN0YXRlKSB7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBzdWNjZXNzID0gdGhpcy52YWxpZGF0ZU5vbmNlKG5vbmNlSW5TdGF0ZSk7XHJcbiAgICBpZiAoIXN1Y2Nlc3MpIHtcclxuICAgICAgY29uc3QgZXZlbnQgPSBuZXcgT0F1dGhFcnJvckV2ZW50KCdpbnZhbGlkX25vbmNlX2luX3N0YXRlJywgbnVsbCk7XHJcbiAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGV2ZW50KTtcclxuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGV2ZW50KTtcclxuICAgIH1cclxuXHJcbiAgICB0aGlzLnN0b3JlU2Vzc2lvblN0YXRlKHNlc3Npb25TdGF0ZSk7XHJcblxyXG4gICAgaWYgKGNvZGUpIHtcclxuICAgICAgcmV0dXJuIHRoaXMuZ2V0VG9rZW5Gcm9tQ29kZShjb2RlLCBvcHRpb25zKS50aGVuKF8gPT4gbnVsbCk7XHJcbiAgICB9IGVsc2Uge1xyXG4gICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBSZXRyaWV2ZSB0aGUgcmV0dXJuZWQgYXV0aCBjb2RlIGZyb20gdGhlIHJlZGlyZWN0IHVyaSB0aGF0IGhhcyBiZWVuIGNhbGxlZC5cclxuICAgKiBJZiByZXF1aXJlZCBhbHNvIGNoZWNrIGhhc2gsIGFzIHdlIGNvdWxkIHVzZSBoYXNoIGxvY2F0aW9uIHN0cmF0ZWd5LlxyXG4gICAqL1xyXG4gIHByaXZhdGUgZ2V0Q29kZVBhcnRzRnJvbVVybChxdWVyeVN0cmluZzogc3RyaW5nKTogb2JqZWN0IHtcclxuICAgIGlmICghcXVlcnlTdHJpbmcgfHwgcXVlcnlTdHJpbmcubGVuZ3RoID09PSAwKSB7XHJcbiAgICAgIHJldHVybiB0aGlzLnVybEhlbHBlci5nZXRIYXNoRnJhZ21lbnRQYXJhbXMoKTtcclxuICAgIH1cclxuXHJcbiAgICAvLyBub3JtYWxpemUgcXVlcnkgc3RyaW5nXHJcbiAgICBpZiAocXVlcnlTdHJpbmcuY2hhckF0KDApID09PSAnPycpIHtcclxuICAgICAgcXVlcnlTdHJpbmcgPSBxdWVyeVN0cmluZy5zdWJzdHIoMSk7XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIHRoaXMudXJsSGVscGVyLnBhcnNlUXVlcnlTdHJpbmcocXVlcnlTdHJpbmcpO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogR2V0IHRva2VuIHVzaW5nIGFuIGludGVybWVkaWF0ZSBjb2RlLiBXb3JrcyBmb3IgdGhlIEF1dGhvcml6YXRpb24gQ29kZSBmbG93LlxyXG4gICAqL1xyXG4gIHByaXZhdGUgZ2V0VG9rZW5Gcm9tQ29kZShcclxuICAgIGNvZGU6IHN0cmluZyxcclxuICAgIG9wdGlvbnM6IExvZ2luT3B0aW9uc1xyXG4gICk6IFByb21pc2U8b2JqZWN0PiB7XHJcbiAgICBsZXQgcGFyYW1zID0gbmV3IEh0dHBQYXJhbXMoKVxyXG4gICAgICAuc2V0KCdncmFudF90eXBlJywgJ2F1dGhvcml6YXRpb25fY29kZScpXHJcbiAgICAgIC5zZXQoJ2NvZGUnLCBjb2RlKVxyXG4gICAgICAuc2V0KCdyZWRpcmVjdF91cmknLCBvcHRpb25zLmN1c3RvbVJlZGlyZWN0VXJpIHx8IHRoaXMucmVkaXJlY3RVcmkpO1xyXG5cclxuICAgIGlmICghdGhpcy5kaXNhYmxlUEtDRSkge1xyXG4gICAgICBsZXQgcGtjaVZlcmlmaWVyO1xyXG5cclxuICAgICAgaWYgKFxyXG4gICAgICAgIHRoaXMuc2F2ZU5vbmNlc0luTG9jYWxTdG9yYWdlICYmXHJcbiAgICAgICAgdHlwZW9mIHdpbmRvd1snbG9jYWxTdG9yYWdlJ10gIT09ICd1bmRlZmluZWQnXHJcbiAgICAgICkge1xyXG4gICAgICAgIHBrY2lWZXJpZmllciA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdQS0NJX3ZlcmlmaWVyJyk7XHJcbiAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgcGtjaVZlcmlmaWVyID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdQS0NJX3ZlcmlmaWVyJyk7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIGlmICghcGtjaVZlcmlmaWVyKSB7XHJcbiAgICAgICAgY29uc29sZS53YXJuKCdObyBQS0NJIHZlcmlmaWVyIGZvdW5kIGluIG9hdXRoIHN0b3JhZ2UhJyk7XHJcbiAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY29kZV92ZXJpZmllcicsIHBrY2lWZXJpZmllcik7XHJcbiAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gdGhpcy5mZXRjaEFuZFByb2Nlc3NUb2tlbihwYXJhbXMpO1xyXG4gIH1cclxuXHJcbiAgcHJpdmF0ZSBmZXRjaEFuZFByb2Nlc3NUb2tlbihwYXJhbXM6IEh0dHBQYXJhbXMpOiBQcm9taXNlPFRva2VuUmVzcG9uc2U+IHtcclxuICAgIHRoaXMuYXNzZXJ0VXJsTm90TnVsbEFuZENvcnJlY3RQcm90b2NvbChcclxuICAgICAgdGhpcy50b2tlbkVuZHBvaW50LFxyXG4gICAgICAndG9rZW5FbmRwb2ludCdcclxuICAgICk7XHJcbiAgICBsZXQgaGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpLnNldChcclxuICAgICAgJ0NvbnRlbnQtVHlwZScsXHJcbiAgICAgICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnXHJcbiAgICApO1xyXG5cclxuICAgIGlmICh0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcclxuICAgICAgY29uc3QgaGVhZGVyID0gYnRvYShgJHt0aGlzLmNsaWVudElkfToke3RoaXMuZHVtbXlDbGllbnRTZWNyZXR9YCk7XHJcbiAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldCgnQXV0aG9yaXphdGlvbicsICdCYXNpYyAnICsgaGVhZGVyKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCkge1xyXG4gICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdjbGllbnRfaWQnLCB0aGlzLmNsaWVudElkKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCAmJiB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KSB7XHJcbiAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9zZWNyZXQnLCB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KTtcclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xyXG4gICAgICBpZiAodGhpcy5jdXN0b21RdWVyeVBhcmFtcykge1xyXG4gICAgICAgIGZvciAobGV0IGtleSBvZiBPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSkge1xyXG4gICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldChrZXksIHRoaXMuY3VzdG9tUXVlcnlQYXJhbXNba2V5XSk7XHJcbiAgICAgICAgfVxyXG4gICAgICB9XHJcblxyXG4gICAgICB0aGlzLmh0dHBcclxuICAgICAgICAucG9zdDxUb2tlblJlc3BvbnNlPih0aGlzLnRva2VuRW5kcG9pbnQsIHBhcmFtcywgeyBoZWFkZXJzIH0pXHJcbiAgICAgICAgLnN1YnNjcmliZShcclxuICAgICAgICAgIHRva2VuUmVzcG9uc2UgPT4ge1xyXG4gICAgICAgICAgICB0aGlzLmRlYnVnKCdyZWZyZXNoIHRva2VuUmVzcG9uc2UnLCB0b2tlblJlc3BvbnNlKTtcclxuICAgICAgICAgICAgdGhpcy5zdG9yZUFjY2Vzc1Rva2VuUmVzcG9uc2UoXHJcbiAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5hY2Nlc3NfdG9rZW4sXHJcbiAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5yZWZyZXNoX3Rva2VuLFxyXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuZXhwaXJlc19pbiB8fFxyXG4gICAgICAgICAgICAgICAgdGhpcy5mYWxsYmFja0FjY2Vzc1Rva2VuRXhwaXJhdGlvblRpbWVJblNlYyxcclxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLnNjb3BlLFxyXG4gICAgICAgICAgICAgIHRoaXMuZXh0cmFjdFJlY29nbml6ZWRDdXN0b21QYXJhbWV0ZXJzKHRva2VuUmVzcG9uc2UpXHJcbiAgICAgICAgICAgICk7XHJcblxyXG4gICAgICAgICAgICBpZiAodGhpcy5vaWRjICYmIHRva2VuUmVzcG9uc2UuaWRfdG9rZW4pIHtcclxuICAgICAgICAgICAgICB0aGlzLnByb2Nlc3NJZFRva2VuKFxyXG4gICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5pZF90b2tlbixcclxuICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuYWNjZXNzX3Rva2VuXHJcbiAgICAgICAgICAgICAgKVxyXG4gICAgICAgICAgICAgICAgLnRoZW4ocmVzdWx0ID0+IHtcclxuICAgICAgICAgICAgICAgICAgdGhpcy5zdG9yZUlkVG9rZW4ocmVzdWx0KTtcclxuXHJcbiAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxyXG4gICAgICAgICAgICAgICAgICAgIG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVjZWl2ZWQnKVxyXG4gICAgICAgICAgICAgICAgICApO1xyXG4gICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcclxuICAgICAgICAgICAgICAgICAgICBuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlZnJlc2hlZCcpXHJcbiAgICAgICAgICAgICAgICAgICk7XHJcblxyXG4gICAgICAgICAgICAgICAgICByZXNvbHZlKHRva2VuUmVzcG9uc2UpO1xyXG4gICAgICAgICAgICAgICAgfSlcclxuICAgICAgICAgICAgICAgIC5jYXRjaChyZWFzb24gPT4ge1xyXG4gICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcclxuICAgICAgICAgICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl92YWxpZGF0aW9uX2Vycm9yJywgcmVhc29uKVxyXG4gICAgICAgICAgICAgICAgICApO1xyXG4gICAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKCdFcnJvciB2YWxpZGF0aW5nIHRva2VucycpO1xyXG4gICAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKHJlYXNvbik7XHJcblxyXG4gICAgICAgICAgICAgICAgICByZWplY3QocmVhc29uKTtcclxuICAgICAgICAgICAgICAgIH0pO1xyXG4gICAgICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVjZWl2ZWQnKSk7XHJcbiAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWZyZXNoZWQnKSk7XHJcblxyXG4gICAgICAgICAgICAgIHJlc29sdmUodG9rZW5SZXNwb25zZSk7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgIH0sXHJcbiAgICAgICAgICBlcnIgPT4ge1xyXG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKCdFcnJvciBnZXR0aW5nIHRva2VuJywgZXJyKTtcclxuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXHJcbiAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgndG9rZW5fcmVmcmVzaF9lcnJvcicsIGVycilcclxuICAgICAgICAgICAgKTtcclxuICAgICAgICAgICAgcmVqZWN0KGVycik7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgKTtcclxuICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogQ2hlY2tzIHdoZXRoZXIgdGhlcmUgYXJlIHRva2VucyBpbiB0aGUgaGFzaCBmcmFnbWVudFxyXG4gICAqIGFzIGEgcmVzdWx0IG9mIHRoZSBpbXBsaWNpdCBmbG93LiBUaGVzZSB0b2tlbnMgYXJlXHJcbiAgICogcGFyc2VkLCB2YWxpZGF0ZWQgYW5kIHVzZWQgdG8gc2lnbiB0aGUgdXNlciBpbiB0byB0aGVcclxuICAgKiBjdXJyZW50IGNsaWVudC5cclxuICAgKlxyXG4gICAqIEBwYXJhbSBvcHRpb25zIE9wdGlvbmFsIG9wdGlvbnMuXHJcbiAgICovXHJcbiAgcHVibGljIHRyeUxvZ2luSW1wbGljaXRGbG93KG9wdGlvbnM6IExvZ2luT3B0aW9ucyA9IG51bGwpOiBQcm9taXNlPGJvb2xlYW4+IHtcclxuICAgIG9wdGlvbnMgPSBvcHRpb25zIHx8IHt9O1xyXG5cclxuICAgIGxldCBwYXJ0czogb2JqZWN0O1xyXG5cclxuICAgIGlmIChvcHRpb25zLmN1c3RvbUhhc2hGcmFnbWVudCkge1xyXG4gICAgICBwYXJ0cyA9IHRoaXMudXJsSGVscGVyLmdldEhhc2hGcmFnbWVudFBhcmFtcyhvcHRpb25zLmN1c3RvbUhhc2hGcmFnbWVudCk7XHJcbiAgICB9IGVsc2Uge1xyXG4gICAgICBwYXJ0cyA9IHRoaXMudXJsSGVscGVyLmdldEhhc2hGcmFnbWVudFBhcmFtcygpO1xyXG4gICAgfVxyXG5cclxuICAgIHRoaXMuZGVidWcoJ3BhcnNlZCB1cmwnLCBwYXJ0cyk7XHJcblxyXG4gICAgY29uc3Qgc3RhdGUgPSBwYXJ0c1snc3RhdGUnXTtcclxuXHJcbiAgICBsZXQgW25vbmNlSW5TdGF0ZSwgdXNlclN0YXRlXSA9IHRoaXMucGFyc2VTdGF0ZShzdGF0ZSk7XHJcbiAgICB0aGlzLnN0YXRlID0gdXNlclN0YXRlO1xyXG5cclxuICAgIGlmIChwYXJ0c1snZXJyb3InXSkge1xyXG4gICAgICB0aGlzLmRlYnVnKCdlcnJvciB0cnlpbmcgdG8gbG9naW4nKTtcclxuICAgICAgdGhpcy5oYW5kbGVMb2dpbkVycm9yKG9wdGlvbnMsIHBhcnRzKTtcclxuICAgICAgY29uc3QgZXJyID0gbmV3IE9BdXRoRXJyb3JFdmVudCgndG9rZW5fZXJyb3InLCB7fSwgcGFydHMpO1xyXG4gICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlcnIpO1xyXG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBhY2Nlc3NUb2tlbiA9IHBhcnRzWydhY2Nlc3NfdG9rZW4nXTtcclxuICAgIGNvbnN0IGlkVG9rZW4gPSBwYXJ0c1snaWRfdG9rZW4nXTtcclxuICAgIGNvbnN0IHNlc3Npb25TdGF0ZSA9IHBhcnRzWydzZXNzaW9uX3N0YXRlJ107XHJcbiAgICBjb25zdCBncmFudGVkU2NvcGVzID0gcGFydHNbJ3Njb3BlJ107XHJcblxyXG4gICAgaWYgKCF0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhdGhpcy5vaWRjKSB7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChcclxuICAgICAgICAnRWl0aGVyIHJlcXVlc3RBY2Nlc3NUb2tlbiBvciBvaWRjIChvciBib3RoKSBtdXN0IGJlIHRydWUuJ1xyXG4gICAgICApO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICh0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhYWNjZXNzVG9rZW4pIHtcclxuICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShmYWxzZSk7XHJcbiAgICB9XHJcbiAgICBpZiAodGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4gJiYgIW9wdGlvbnMuZGlzYWJsZU9BdXRoMlN0YXRlQ2hlY2sgJiYgIXN0YXRlKSB7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoZmFsc2UpO1xyXG4gICAgfVxyXG4gICAgaWYgKHRoaXMub2lkYyAmJiAhaWRUb2tlbikge1xyXG4gICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKGZhbHNlKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAodGhpcy5zZXNzaW9uQ2hlY2tzRW5hYmxlZCAmJiAhc2Vzc2lvblN0YXRlKSB7XHJcbiAgICAgIHRoaXMubG9nZ2VyLndhcm4oXHJcbiAgICAgICAgJ3Nlc3Npb24gY2hlY2tzIChTZXNzaW9uIFN0YXR1cyBDaGFuZ2UgTm90aWZpY2F0aW9uKSAnICtcclxuICAgICAgICAgICd3ZXJlIGFjdGl2YXRlZCBpbiB0aGUgY29uZmlndXJhdGlvbiBidXQgdGhlIGlkX3Rva2VuICcgK1xyXG4gICAgICAgICAgJ2RvZXMgbm90IGNvbnRhaW4gYSBzZXNzaW9uX3N0YXRlIGNsYWltJ1xyXG4gICAgICApO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICh0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhb3B0aW9ucy5kaXNhYmxlT0F1dGgyU3RhdGVDaGVjaykge1xyXG4gICAgICBjb25zdCBzdWNjZXNzID0gdGhpcy52YWxpZGF0ZU5vbmNlKG5vbmNlSW5TdGF0ZSk7XHJcblxyXG4gICAgICBpZiAoIXN1Y2Nlc3MpIHtcclxuICAgICAgICBjb25zdCBldmVudCA9IG5ldyBPQXV0aEVycm9yRXZlbnQoJ2ludmFsaWRfbm9uY2VfaW5fc3RhdGUnLCBudWxsKTtcclxuICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChldmVudCk7XHJcbiAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGV2ZW50KTtcclxuICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIGlmICh0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbikge1xyXG4gICAgICB0aGlzLnN0b3JlQWNjZXNzVG9rZW5SZXNwb25zZShcclxuICAgICAgICBhY2Nlc3NUb2tlbixcclxuICAgICAgICBudWxsLFxyXG4gICAgICAgIHBhcnRzWydleHBpcmVzX2luJ10gfHwgdGhpcy5mYWxsYmFja0FjY2Vzc1Rva2VuRXhwaXJhdGlvblRpbWVJblNlYyxcclxuICAgICAgICBncmFudGVkU2NvcGVzXHJcbiAgICAgICk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKCF0aGlzLm9pZGMpIHtcclxuICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWNlaXZlZCcpKTtcclxuICAgICAgaWYgKHRoaXMuY2xlYXJIYXNoQWZ0ZXJMb2dpbiAmJiAhb3B0aW9ucy5wcmV2ZW50Q2xlYXJIYXNoQWZ0ZXJMb2dpbikge1xyXG4gICAgICAgIGxvY2F0aW9uLmhhc2ggPSAnJztcclxuICAgICAgfVxyXG5cclxuICAgICAgdGhpcy5jYWxsT25Ub2tlblJlY2VpdmVkSWZFeGlzdHMob3B0aW9ucyk7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUodHJ1ZSk7XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIHRoaXMucHJvY2Vzc0lkVG9rZW4oaWRUb2tlbiwgYWNjZXNzVG9rZW4pXHJcbiAgICAgIC50aGVuKHJlc3VsdCA9PiB7XHJcbiAgICAgICAgaWYgKG9wdGlvbnMudmFsaWRhdGlvbkhhbmRsZXIpIHtcclxuICAgICAgICAgIHJldHVybiBvcHRpb25zXHJcbiAgICAgICAgICAgIC52YWxpZGF0aW9uSGFuZGxlcih7XHJcbiAgICAgICAgICAgICAgYWNjZXNzVG9rZW46IGFjY2Vzc1Rva2VuLFxyXG4gICAgICAgICAgICAgIGlkQ2xhaW1zOiByZXN1bHQuaWRUb2tlbkNsYWltcyxcclxuICAgICAgICAgICAgICBpZFRva2VuOiByZXN1bHQuaWRUb2tlbixcclxuICAgICAgICAgICAgICBzdGF0ZTogc3RhdGVcclxuICAgICAgICAgICAgfSlcclxuICAgICAgICAgICAgLnRoZW4oXyA9PiByZXN1bHQpO1xyXG4gICAgICAgIH1cclxuICAgICAgICByZXR1cm4gcmVzdWx0O1xyXG4gICAgICB9KVxyXG4gICAgICAudGhlbihyZXN1bHQgPT4ge1xyXG4gICAgICAgIHRoaXMuc3RvcmVJZFRva2VuKHJlc3VsdCk7XHJcbiAgICAgICAgdGhpcy5zdG9yZVNlc3Npb25TdGF0ZShzZXNzaW9uU3RhdGUpO1xyXG4gICAgICAgIGlmICh0aGlzLmNsZWFySGFzaEFmdGVyTG9naW4gJiYgIW9wdGlvbnMucHJldmVudENsZWFySGFzaEFmdGVyTG9naW4pIHtcclxuICAgICAgICAgIGxvY2F0aW9uLmhhc2ggPSAnJztcclxuICAgICAgICB9XHJcbiAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWNlaXZlZCcpKTtcclxuICAgICAgICB0aGlzLmNhbGxPblRva2VuUmVjZWl2ZWRJZkV4aXN0cyhvcHRpb25zKTtcclxuICAgICAgICB0aGlzLmluSW1wbGljaXRGbG93ID0gZmFsc2U7XHJcbiAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICAgIH0pXHJcbiAgICAgIC5jYXRjaChyZWFzb24gPT4ge1xyXG4gICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxyXG4gICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgndG9rZW5fdmFsaWRhdGlvbl9lcnJvcicsIHJlYXNvbilcclxuICAgICAgICApO1xyXG4gICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdFcnJvciB2YWxpZGF0aW5nIHRva2VucycpO1xyXG4gICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKHJlYXNvbik7XHJcbiAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KHJlYXNvbik7XHJcbiAgICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgcHJpdmF0ZSBwYXJzZVN0YXRlKHN0YXRlOiBzdHJpbmcpOiBbc3RyaW5nLCBzdHJpbmddIHtcclxuICAgIGxldCBub25jZSA9IHN0YXRlO1xyXG4gICAgbGV0IHVzZXJTdGF0ZSA9ICcnO1xyXG5cclxuICAgIGlmIChzdGF0ZSkge1xyXG4gICAgICBjb25zdCBpZHggPSBzdGF0ZS5pbmRleE9mKHRoaXMuY29uZmlnLm5vbmNlU3RhdGVTZXBhcmF0b3IpO1xyXG4gICAgICBpZiAoaWR4ID4gLTEpIHtcclxuICAgICAgICBub25jZSA9IHN0YXRlLnN1YnN0cigwLCBpZHgpO1xyXG4gICAgICAgIHVzZXJTdGF0ZSA9IHN0YXRlLnN1YnN0cihpZHggKyB0aGlzLmNvbmZpZy5ub25jZVN0YXRlU2VwYXJhdG9yLmxlbmd0aCk7XHJcbiAgICAgIH1cclxuICAgIH1cclxuICAgIHJldHVybiBbbm9uY2UsIHVzZXJTdGF0ZV07XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgdmFsaWRhdGVOb25jZShub25jZUluU3RhdGU6IHN0cmluZyk6IGJvb2xlYW4ge1xyXG4gICAgbGV0IHNhdmVkTm9uY2U7XHJcblxyXG4gICAgaWYgKFxyXG4gICAgICB0aGlzLnNhdmVOb25jZXNJbkxvY2FsU3RvcmFnZSAmJlxyXG4gICAgICB0eXBlb2Ygd2luZG93Wydsb2NhbFN0b3JhZ2UnXSAhPT0gJ3VuZGVmaW5lZCdcclxuICAgICkge1xyXG4gICAgICBzYXZlZE5vbmNlID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ25vbmNlJyk7XHJcbiAgICB9IGVsc2Uge1xyXG4gICAgICBzYXZlZE5vbmNlID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdub25jZScpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmIChzYXZlZE5vbmNlICE9PSBub25jZUluU3RhdGUpIHtcclxuICAgICAgY29uc3QgZXJyID0gJ1ZhbGlkYXRpbmcgYWNjZXNzX3Rva2VuIGZhaWxlZCwgd3Jvbmcgc3RhdGUvbm9uY2UuJztcclxuICAgICAgY29uc29sZS5lcnJvcihlcnIsIHNhdmVkTm9uY2UsIG5vbmNlSW5TdGF0ZSk7XHJcbiAgICAgIHJldHVybiBmYWxzZTtcclxuICAgIH1cclxuICAgIHJldHVybiB0cnVlO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHN0b3JlSWRUb2tlbihpZFRva2VuOiBQYXJzZWRJZFRva2VuKTogdm9pZCB7XHJcbiAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2lkX3Rva2VuJywgaWRUb2tlbi5pZFRva2VuKTtcclxuICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnaWRfdG9rZW5fY2xhaW1zX29iaicsIGlkVG9rZW4uaWRUb2tlbkNsYWltc0pzb24pO1xyXG4gICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdpZF90b2tlbl9leHBpcmVzX2F0JywgJycgKyBpZFRva2VuLmlkVG9rZW5FeHBpcmVzQXQpO1xyXG4gICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdpZF90b2tlbl9zdG9yZWRfYXQnLCAnJyArIERhdGUubm93KCkpO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHN0b3JlU2Vzc2lvblN0YXRlKHNlc3Npb25TdGF0ZTogc3RyaW5nKTogdm9pZCB7XHJcbiAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ3Nlc3Npb25fc3RhdGUnLCBzZXNzaW9uU3RhdGUpO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGdldFNlc3Npb25TdGF0ZSgpOiBzdHJpbmcge1xyXG4gICAgcmV0dXJuIHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnc2Vzc2lvbl9zdGF0ZScpO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGhhbmRsZUxvZ2luRXJyb3Iob3B0aW9uczogTG9naW5PcHRpb25zLCBwYXJ0czogb2JqZWN0KTogdm9pZCB7XHJcbiAgICBpZiAob3B0aW9ucy5vbkxvZ2luRXJyb3IpIHtcclxuICAgICAgb3B0aW9ucy5vbkxvZ2luRXJyb3IocGFydHMpO1xyXG4gICAgfVxyXG4gICAgaWYgKHRoaXMuY2xlYXJIYXNoQWZ0ZXJMb2dpbiAmJiAhb3B0aW9ucy5wcmV2ZW50Q2xlYXJIYXNoQWZ0ZXJMb2dpbikge1xyXG4gICAgICBsb2NhdGlvbi5oYXNoID0gJyc7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBAaWdub3JlXHJcbiAgICovXHJcbiAgcHVibGljIHByb2Nlc3NJZFRva2VuKFxyXG4gICAgaWRUb2tlbjogc3RyaW5nLFxyXG4gICAgYWNjZXNzVG9rZW46IHN0cmluZyxcclxuICAgIHNraXBOb25jZUNoZWNrID0gZmFsc2VcclxuICApOiBQcm9taXNlPFBhcnNlZElkVG9rZW4+IHtcclxuICAgIGNvbnN0IHRva2VuUGFydHMgPSBpZFRva2VuLnNwbGl0KCcuJyk7XHJcbiAgICBjb25zdCBoZWFkZXJCYXNlNjQgPSB0aGlzLnBhZEJhc2U2NCh0b2tlblBhcnRzWzBdKTtcclxuICAgIGNvbnN0IGhlYWRlckpzb24gPSBiNjREZWNvZGVVbmljb2RlKGhlYWRlckJhc2U2NCk7XHJcbiAgICBjb25zdCBoZWFkZXIgPSBKU09OLnBhcnNlKGhlYWRlckpzb24pO1xyXG4gICAgY29uc3QgY2xhaW1zQmFzZTY0ID0gdGhpcy5wYWRCYXNlNjQodG9rZW5QYXJ0c1sxXSk7XHJcbiAgICBjb25zdCBjbGFpbXNKc29uID0gYjY0RGVjb2RlVW5pY29kZShjbGFpbXNCYXNlNjQpO1xyXG4gICAgY29uc3QgY2xhaW1zID0gSlNPTi5wYXJzZShjbGFpbXNKc29uKTtcclxuXHJcbiAgICBsZXQgc2F2ZWROb25jZTtcclxuICAgIGlmIChcclxuICAgICAgdGhpcy5zYXZlTm9uY2VzSW5Mb2NhbFN0b3JhZ2UgJiZcclxuICAgICAgdHlwZW9mIHdpbmRvd1snbG9jYWxTdG9yYWdlJ10gIT09ICd1bmRlZmluZWQnXHJcbiAgICApIHtcclxuICAgICAgc2F2ZWROb25jZSA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdub25jZScpO1xyXG4gICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgnbm9uY2UnLGNsYWltcy5qdGkpO1xyXG4gICAgfSBlbHNlIHtcclxuICAgICAgc2F2ZWROb25jZSA9IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnbm9uY2UnKTtcclxuICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdub25jZScsY2xhaW1zLmp0aSlcclxuICAgIH1cclxuXHJcbiAgICBpZiAoQXJyYXkuaXNBcnJheShjbGFpbXMuYXVkKSkge1xyXG4gICAgICBpZiAoY2xhaW1zLmF1ZC5ldmVyeSh2ID0+IHYgIT09IHRoaXMuY2xpZW50SWQpKSB7XHJcbiAgICAgICAgY29uc3QgZXJyID0gJ1dyb25nIGF1ZGllbmNlOiAnICsgY2xhaW1zLmF1ZC5qb2luKCcsJyk7XHJcbiAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xyXG4gICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xyXG4gICAgICB9XHJcbiAgICB9IGVsc2Uge1xyXG4gICAgICBpZiAoY2xhaW1zLmF1ZCAhPT0gdGhpcy5jbGllbnRJZCkge1xyXG4gICAgICAgIGNvbnN0IGVyciA9ICdXcm9uZyBhdWRpZW5jZTogJyArIGNsYWltcy5hdWQ7XHJcbiAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xyXG4gICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xyXG4gICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKCFjbGFpbXMuc3ViKSB7XHJcbiAgICAgIGNvbnN0IGVyciA9ICdObyBzdWIgY2xhaW0gaW4gaWRfdG9rZW4nO1xyXG4gICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xyXG4gICAgfVxyXG5cclxuICAgIC8qIEZvciBub3csIHdlIG9ubHkgY2hlY2sgd2hldGhlciB0aGUgc3ViIGFnYWluc3RcclxuICAgICAqIHNpbGVudFJlZnJlc2hTdWJqZWN0IHdoZW4gc2Vzc2lvbkNoZWNrc0VuYWJsZWQgaXMgb25cclxuICAgICAqIFdlIHdpbGwgcmVjb25zaWRlciBpbiBhIGxhdGVyIHZlcnNpb24gdG8gZG8gdGhpc1xyXG4gICAgICogaW4gZXZlcnkgb3RoZXIgY2FzZSB0b28uXHJcbiAgICAgKi9cclxuICAgIGlmIChcclxuICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tzRW5hYmxlZCAmJlxyXG4gICAgICB0aGlzLnNpbGVudFJlZnJlc2hTdWJqZWN0ICYmXHJcbiAgICAgIHRoaXMuc2lsZW50UmVmcmVzaFN1YmplY3QgIT09IGNsYWltc1snc3ViJ11cclxuICAgICkge1xyXG4gICAgICBjb25zdCBlcnIgPVxyXG4gICAgICAgICdBZnRlciByZWZyZXNoaW5nLCB3ZSBnb3QgYW4gaWRfdG9rZW4gZm9yIGFub3RoZXIgdXNlciAoc3ViKS4gJyArXHJcbiAgICAgICAgYEV4cGVjdGVkIHN1YjogJHt0aGlzLnNpbGVudFJlZnJlc2hTdWJqZWN0fSwgcmVjZWl2ZWQgc3ViOiAke2NsYWltc1snc3ViJ119YDtcclxuXHJcbiAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcclxuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKCFjbGFpbXMuaWF0KSB7XHJcbiAgICAgIGNvbnN0IGVyciA9ICdObyBpYXQgY2xhaW0gaW4gaWRfdG9rZW4nO1xyXG4gICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICghdGhpcy5za2lwSXNzdWVyQ2hlY2sgJiYgY2xhaW1zLmlzcyAhPT0gdGhpcy5pc3N1ZXIpIHtcclxuICAgICAgY29uc3QgZXJyID0gJ1dyb25nIGlzc3VlcjogJyArIGNsYWltcy5pc3M7XHJcbiAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcclxuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XHJcbiAgICB9XHJcbiAgICAvLyBhdF9oYXNoIGlzIG5vdCBhcHBsaWNhYmxlIHRvIGF1dGhvcml6YXRpb24gY29kZSBmbG93XHJcbiAgICAvLyBhZGRyZXNzaW5nIGh0dHBzOi8vZ2l0aHViLmNvbS9tYW5mcmVkc3RleWVyL2FuZ3VsYXItb2F1dGgyLW9pZGMvaXNzdWVzLzY2MVxyXG4gICAgLy8gaS5lLiBCYXNlZCBvbiBzcGVjIHRoZSBhdF9oYXNoIGNoZWNrIGlzIG9ubHkgdHJ1ZSBmb3IgaW1wbGljaXQgY29kZSBmbG93IG9uIFBpbmcgRmVkZXJhdGVcclxuICAgIC8vIGh0dHBzOi8vd3d3LnBpbmdpZGVudGl0eS5jb20vZGV2ZWxvcGVyL2VuL3Jlc291cmNlcy9vcGVuaWQtY29ubmVjdC1kZXZlbG9wZXJzLWd1aWRlLmh0bWxcclxuICAgIGlmICh0aGlzLmhhc093blByb3BlcnR5KCdyZXNwb25zZVR5cGUnKSAmJiB0aGlzLnJlc3BvbnNlVHlwZSA9PT0gJ2NvZGUnKSB7XHJcbiAgICAgIHRoaXMuZGlzYWJsZUF0SGFzaENoZWNrID0gdHJ1ZTtcclxuICAgIH1cclxuICAgIGlmIChcclxuICAgICAgIXRoaXMuZGlzYWJsZUF0SGFzaENoZWNrICYmXHJcbiAgICAgIHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmXHJcbiAgICAgICFjbGFpbXNbJ2F0X2hhc2gnXVxyXG4gICAgKSB7XHJcbiAgICAgIGNvbnN0IGVyciA9ICdBbiBhdF9oYXNoIGlzIG5lZWRlZCEnO1xyXG4gICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xyXG4gICAgfVxyXG5cclxuICAgIGNvbnN0IG5vdyA9IERhdGUubm93KCk7XHJcbiAgICBjb25zdCBpc3N1ZWRBdE1TZWMgPSBjbGFpbXMuaWF0ICogMTAwMDtcclxuICAgIGNvbnN0IGV4cGlyZXNBdE1TZWMgPSBjbGFpbXMuZXhwICogMTAwMDtcclxuICAgIGNvbnN0IGNsb2NrU2tld0luTVNlYyA9ICh0aGlzLmNsb2NrU2tld0luU2VjIHx8IDYwMCkgKiAxMDAwO1xyXG5cclxuICAgIGlmIChcclxuICAgICAgaXNzdWVkQXRNU2VjIC0gY2xvY2tTa2V3SW5NU2VjID49IG5vdyB8fFxyXG4gICAgICBleHBpcmVzQXRNU2VjICsgY2xvY2tTa2V3SW5NU2VjIDw9IG5vd1xyXG4gICAgKSB7XHJcbiAgICAgIGNvbnN0IGVyciA9ICdUb2tlbiBoYXMgZXhwaXJlZCc7XHJcbiAgICAgIGNvbnNvbGUuZXJyb3IoZXJyKTtcclxuICAgICAgY29uc29sZS5lcnJvcih7XHJcbiAgICAgICAgbm93OiBub3csXHJcbiAgICAgICAgaXNzdWVkQXRNU2VjOiBpc3N1ZWRBdE1TZWMsXHJcbiAgICAgICAgZXhwaXJlc0F0TVNlYzogZXhwaXJlc0F0TVNlY1xyXG4gICAgICB9KTtcclxuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3QgdmFsaWRhdGlvblBhcmFtczogVmFsaWRhdGlvblBhcmFtcyA9IHtcclxuICAgICAgYWNjZXNzVG9rZW46IGFjY2Vzc1Rva2VuLFxyXG4gICAgICBpZFRva2VuOiBpZFRva2VuLFxyXG4gICAgICBqd2tzOiB0aGlzLmp3a3MsXHJcbiAgICAgIGlkVG9rZW5DbGFpbXM6IGNsYWltcyxcclxuICAgICAgaWRUb2tlbkhlYWRlcjogaGVhZGVyLFxyXG4gICAgICBsb2FkS2V5czogKCkgPT4gdGhpcy5sb2FkSndrcygpXHJcbiAgICB9O1xyXG5cclxuICAgIGlmICh0aGlzLmRpc2FibGVBdEhhc2hDaGVjaykge1xyXG4gICAgICByZXR1cm4gdGhpcy5jaGVja1NpZ25hdHVyZSh2YWxpZGF0aW9uUGFyYW1zKS50aGVuKF8gPT4ge1xyXG4gICAgICAgIGNvbnN0IHJlc3VsdDogUGFyc2VkSWRUb2tlbiA9IHtcclxuICAgICAgICAgIGlkVG9rZW46IGlkVG9rZW4sXHJcbiAgICAgICAgICBpZFRva2VuQ2xhaW1zOiBjbGFpbXMsXHJcbiAgICAgICAgICBpZFRva2VuQ2xhaW1zSnNvbjogY2xhaW1zSnNvbixcclxuICAgICAgICAgIGlkVG9rZW5IZWFkZXI6IGhlYWRlcixcclxuICAgICAgICAgIGlkVG9rZW5IZWFkZXJKc29uOiBoZWFkZXJKc29uLFxyXG4gICAgICAgICAgaWRUb2tlbkV4cGlyZXNBdDogZXhwaXJlc0F0TVNlY1xyXG4gICAgICAgIH07XHJcbiAgICAgICAgcmV0dXJuIHJlc3VsdDtcclxuICAgICAgfSk7XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIHRoaXMuY2hlY2tBdEhhc2godmFsaWRhdGlvblBhcmFtcykudGhlbihhdEhhc2hWYWxpZCA9PiB7XHJcbiAgICAgIGlmICghdGhpcy5kaXNhYmxlQXRIYXNoQ2hlY2sgJiYgdGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4gJiYgIWF0SGFzaFZhbGlkKSB7XHJcbiAgICAgICAgY29uc3QgZXJyID0gJ1dyb25nIGF0X2hhc2gnO1xyXG4gICAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcclxuICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcclxuICAgICAgfVxyXG5cclxuICAgICAgcmV0dXJuIHRoaXMuY2hlY2tTaWduYXR1cmUodmFsaWRhdGlvblBhcmFtcykudGhlbihfID0+IHtcclxuICAgICAgICBjb25zdCBhdEhhc2hDaGVja0VuYWJsZWQgPSAhdGhpcy5kaXNhYmxlQXRIYXNoQ2hlY2s7XHJcbiAgICAgICAgY29uc3QgcmVzdWx0OiBQYXJzZWRJZFRva2VuID0ge1xyXG4gICAgICAgICAgaWRUb2tlbjogaWRUb2tlbixcclxuICAgICAgICAgIGlkVG9rZW5DbGFpbXM6IGNsYWltcyxcclxuICAgICAgICAgIGlkVG9rZW5DbGFpbXNKc29uOiBjbGFpbXNKc29uLFxyXG4gICAgICAgICAgaWRUb2tlbkhlYWRlcjogaGVhZGVyLFxyXG4gICAgICAgICAgaWRUb2tlbkhlYWRlckpzb246IGhlYWRlckpzb24sXHJcbiAgICAgICAgICBpZFRva2VuRXhwaXJlc0F0OiBleHBpcmVzQXRNU2VjXHJcbiAgICAgICAgfTtcclxuICAgICAgICBpZiAoYXRIYXNoQ2hlY2tFbmFibGVkKSB7XHJcbiAgICAgICAgICByZXR1cm4gdGhpcy5jaGVja0F0SGFzaCh2YWxpZGF0aW9uUGFyYW1zKS50aGVuKGF0SGFzaFZhbGlkID0+IHtcclxuICAgICAgICAgICAgaWYgKHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmICFhdEhhc2hWYWxpZCkge1xyXG4gICAgICAgICAgICAgIGNvbnN0IGVyciA9ICdXcm9uZyBhdF9oYXNoJztcclxuICAgICAgICAgICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XHJcbiAgICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XHJcbiAgICAgICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICAgICAgcmV0dXJuIHJlc3VsdDtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgfSk7XHJcbiAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgIHJldHVybiByZXN1bHQ7XHJcbiAgICAgICAgfVxyXG4gICAgICB9KTtcclxuICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogUmV0dXJucyB0aGUgcmVjZWl2ZWQgY2xhaW1zIGFib3V0IHRoZSB1c2VyLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBnZXRJZGVudGl0eUNsYWltcygpOiBvYmplY3Qge1xyXG4gICAgY29uc3QgY2xhaW1zID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdpZF90b2tlbl9jbGFpbXNfb2JqJyk7XHJcbiAgICBpZiAoIWNsYWltcykge1xyXG4gICAgICByZXR1cm4gbnVsbDtcclxuICAgIH1cclxuICAgIHJldHVybiBKU09OLnBhcnNlKGNsYWltcyk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBSZXR1cm5zIHRoZSBncmFudGVkIHNjb3BlcyBmcm9tIHRoZSBzZXJ2ZXIuXHJcbiAgICovXHJcbiAgcHVibGljIGdldEdyYW50ZWRTY29wZXMoKTogb2JqZWN0IHtcclxuICAgIGNvbnN0IHNjb3BlcyA9IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnZ3JhbnRlZF9zY29wZXMnKTtcclxuICAgIGlmICghc2NvcGVzKSB7XHJcbiAgICAgIHJldHVybiBudWxsO1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIEpTT04ucGFyc2Uoc2NvcGVzKTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFJldHVybnMgdGhlIGN1cnJlbnQgaWRfdG9rZW4uXHJcbiAgICovXHJcbiAgcHVibGljIGdldElkVG9rZW4oKTogc3RyaW5nIHtcclxuICAgIHJldHVybiB0aGlzLl9zdG9yYWdlID8gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdpZF90b2tlbicpIDogbnVsbDtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBwYWRCYXNlNjQoYmFzZTY0ZGF0YSk6IHN0cmluZyB7XHJcbiAgICB3aGlsZSAoYmFzZTY0ZGF0YS5sZW5ndGggJSA0ICE9PSAwKSB7XHJcbiAgICAgIGJhc2U2NGRhdGEgKz0gJz0nO1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIGJhc2U2NGRhdGE7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBSZXR1cm5zIHRoZSBjdXJyZW50IGFjY2Vzc190b2tlbi5cclxuICAgKi9cclxuICBwdWJsaWMgZ2V0QWNjZXNzVG9rZW4oKTogc3RyaW5nIHtcclxuICAgIHJldHVybiB0aGlzLl9zdG9yYWdlID8gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdhY2Nlc3NfdG9rZW4nKSA6IG51bGw7XHJcbiAgfVxyXG5cclxuICBwdWJsaWMgZ2V0UmVmcmVzaFRva2VuKCk6IHN0cmluZyB7XHJcbiAgICByZXR1cm4gdGhpcy5fc3RvcmFnZSA/IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgncmVmcmVzaF90b2tlbicpIDogbnVsbDtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFJldHVybnMgdGhlIGV4cGlyYXRpb24gZGF0ZSBvZiB0aGUgYWNjZXNzX3Rva2VuXHJcbiAgICogYXMgbWlsbGlzZWNvbmRzIHNpbmNlIDE5NzAuXHJcbiAgICovXHJcbiAgcHVibGljIGdldEFjY2Vzc1Rva2VuRXhwaXJhdGlvbigpOiBudW1iZXIge1xyXG4gICAgaWYgKCF0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2V4cGlyZXNfYXQnKSkge1xyXG4gICAgICByZXR1cm4gbnVsbDtcclxuICAgIH1cclxuICAgIHJldHVybiBwYXJzZUludCh0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2V4cGlyZXNfYXQnKSwgMTApO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGdldEFjY2Vzc1Rva2VuU3RvcmVkQXQoKTogbnVtYmVyIHtcclxuICAgIHJldHVybiBwYXJzZUludCh0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2FjY2Vzc190b2tlbl9zdG9yZWRfYXQnKSwgMTApO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGdldElkVG9rZW5TdG9yZWRBdCgpOiBudW1iZXIge1xyXG4gICAgcmV0dXJuIHBhcnNlSW50KHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnaWRfdG9rZW5fc3RvcmVkX2F0JyksIDEwKTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFJldHVybnMgdGhlIGV4cGlyYXRpb24gZGF0ZSBvZiB0aGUgaWRfdG9rZW5cclxuICAgKiBhcyBtaWxsaXNlY29uZHMgc2luY2UgMTk3MC5cclxuICAgKi9cclxuICBwdWJsaWMgZ2V0SWRUb2tlbkV4cGlyYXRpb24oKTogbnVtYmVyIHtcclxuICAgIGlmICghdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdpZF90b2tlbl9leHBpcmVzX2F0JykpIHtcclxuICAgICAgcmV0dXJuIG51bGw7XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIHBhcnNlSW50KHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnaWRfdG9rZW5fZXhwaXJlc19hdCcpLCAxMCk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBDaGVja2VzLCB3aGV0aGVyIHRoZXJlIGlzIGEgdmFsaWQgYWNjZXNzX3Rva2VuLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBoYXNWYWxpZEFjY2Vzc1Rva2VuKCk6IGJvb2xlYW4ge1xyXG4gICAgaWYgKHRoaXMuZ2V0QWNjZXNzVG9rZW4oKSkge1xyXG4gICAgICBjb25zdCBleHBpcmVzQXQgPSB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2V4cGlyZXNfYXQnKTtcclxuICAgICAgY29uc3Qgbm93ID0gbmV3IERhdGUoKTtcclxuICAgICAgaWYgKGV4cGlyZXNBdCAmJiBwYXJzZUludChleHBpcmVzQXQsIDEwKSA8IG5vdy5nZXRUaW1lKCkpIHtcclxuICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiBmYWxzZTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIENoZWNrcyB3aGV0aGVyIHRoZXJlIGlzIGEgdmFsaWQgaWRfdG9rZW4uXHJcbiAgICovXHJcbiAgcHVibGljIGhhc1ZhbGlkSWRUb2tlbigpOiBib29sZWFuIHtcclxuICAgIGlmICh0aGlzLmdldElkVG9rZW4oKSkge1xyXG4gICAgICBjb25zdCBleHBpcmVzQXQgPSB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2lkX3Rva2VuX2V4cGlyZXNfYXQnKTtcclxuICAgICAgY29uc3Qgbm93ID0gbmV3IERhdGUoKTtcclxuICAgICAgaWYgKGV4cGlyZXNBdCAmJiBwYXJzZUludChleHBpcmVzQXQsIDEwKSA8IG5vdy5nZXRUaW1lKCkpIHtcclxuICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiBmYWxzZTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFJldHJpZXZlIGEgc2F2ZWQgY3VzdG9tIHByb3BlcnR5IG9mIHRoZSBUb2tlblJlcG9uc2Ugb2JqZWN0LiBPbmx5IGlmIHByZWRlZmluZWQgaW4gYXV0aGNvbmZpZy5cclxuICAgKi9cclxuICBwdWJsaWMgZ2V0Q3VzdG9tVG9rZW5SZXNwb25zZVByb3BlcnR5KHJlcXVlc3RlZFByb3BlcnR5OiBzdHJpbmcpOiBhbnkge1xyXG4gICAgcmV0dXJuIHRoaXMuX3N0b3JhZ2UgJiZcclxuICAgICAgdGhpcy5jb25maWcuY3VzdG9tVG9rZW5QYXJhbWV0ZXJzICYmXHJcbiAgICAgIHRoaXMuY29uZmlnLmN1c3RvbVRva2VuUGFyYW1ldGVycy5pbmRleE9mKHJlcXVlc3RlZFByb3BlcnR5KSA+PSAwICYmXHJcbiAgICAgIHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbShyZXF1ZXN0ZWRQcm9wZXJ0eSkgIT09IG51bGxcclxuICAgICAgPyBKU09OLnBhcnNlKHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbShyZXF1ZXN0ZWRQcm9wZXJ0eSkpXHJcbiAgICAgIDogbnVsbDtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFJldHVybnMgdGhlIGF1dGgtaGVhZGVyIHRoYXQgY2FuIGJlIHVzZWRcclxuICAgKiB0byB0cmFuc21pdCB0aGUgYWNjZXNzX3Rva2VuIHRvIGEgc2VydmljZVxyXG4gICAqL1xyXG4gIHB1YmxpYyBhdXRob3JpemF0aW9uSGVhZGVyKCk6IHN0cmluZyB7XHJcbiAgICByZXR1cm4gJ0JlYXJlciAnICsgdGhpcy5nZXRBY2Nlc3NUb2tlbigpO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogUmVtb3ZlcyBhbGwgdG9rZW5zIGFuZCBsb2dzIHRoZSB1c2VyIG91dC5cclxuICAgKiBJZiBhIGxvZ291dCB1cmwgaXMgY29uZmlndXJlZCwgdGhlIHVzZXIgaXNcclxuICAgKiByZWRpcmVjdGVkIHRvIGl0IHdpdGggb3B0aW9uYWwgc3RhdGUgcGFyYW1ldGVyLlxyXG4gICAqIEBwYXJhbSBub1JlZGlyZWN0VG9Mb2dvdXRVcmxcclxuICAgKiBAcGFyYW0gc3RhdGVcclxuICAgKi9cclxuICBwdWJsaWMgbG9nT3V0KG5vUmVkaXJlY3RUb0xvZ291dFVybCA9IGZhbHNlLCBzdGF0ZSA9ICcnKTogdm9pZCB7XHJcbiAgICBjb25zdCBpZF90b2tlbiA9IHRoaXMuZ2V0SWRUb2tlbigpO1xyXG4gICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdhY2Nlc3NfdG9rZW4nKTtcclxuICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnaWRfdG9rZW4nKTtcclxuICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgncmVmcmVzaF90b2tlbicpO1xyXG5cclxuICAgIGlmICh0aGlzLnNhdmVOb25jZXNJbkxvY2FsU3RvcmFnZSkge1xyXG4gICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgnbm9uY2UnKTtcclxuICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oJ1BLQ0lfdmVyaWZpZXInKTtcclxuICAgIH0gZWxzZSB7XHJcbiAgICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnbm9uY2UnKTtcclxuICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdQS0NJX3ZlcmlmaWVyJyk7XHJcbiAgICB9XHJcblxyXG4gICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdleHBpcmVzX2F0Jyk7XHJcbiAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2lkX3Rva2VuX2NsYWltc19vYmonKTtcclxuICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnaWRfdG9rZW5fZXhwaXJlc19hdCcpO1xyXG4gICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdpZF90b2tlbl9zdG9yZWRfYXQnKTtcclxuICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnYWNjZXNzX3Rva2VuX3N0b3JlZF9hdCcpO1xyXG4gICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdncmFudGVkX3Njb3BlcycpO1xyXG4gICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdzZXNzaW9uX3N0YXRlJyk7XHJcbiAgICBpZiAodGhpcy5jb25maWcuY3VzdG9tVG9rZW5QYXJhbWV0ZXJzKSB7XHJcbiAgICAgIHRoaXMuY29uZmlnLmN1c3RvbVRva2VuUGFyYW1ldGVycy5mb3JFYWNoKGN1c3RvbVBhcmFtID0+XHJcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKGN1c3RvbVBhcmFtKVxyXG4gICAgICApO1xyXG4gICAgfVxyXG4gICAgdGhpcy5zaWxlbnRSZWZyZXNoU3ViamVjdCA9IG51bGw7XHJcblxyXG4gICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoSW5mb0V2ZW50KCdsb2dvdXQnKSk7XHJcblxyXG4gICAgaWYgKCF0aGlzLmxvZ291dFVybCkge1xyXG4gICAgICByZXR1cm47XHJcbiAgICB9XHJcbiAgICBpZiAobm9SZWRpcmVjdFRvTG9nb3V0VXJsKSB7XHJcbiAgICAgIHJldHVybjtcclxuICAgIH1cclxuXHJcbiAgICBpZiAoIWlkX3Rva2VuICYmICF0aGlzLnBvc3RMb2dvdXRSZWRpcmVjdFVyaSkge1xyXG4gICAgICByZXR1cm47XHJcbiAgICB9XHJcblxyXG4gICAgbGV0IGxvZ291dFVybDogc3RyaW5nO1xyXG5cclxuICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHRoaXMubG9nb3V0VXJsKSkge1xyXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXHJcbiAgICAgICAgXCJsb2dvdXRVcmwgIG11c3QgdXNlIEhUVFBTICh3aXRoIFRMUyksIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgJ3JlcXVpcmVIdHRwcycgbXVzdCBiZSBzZXQgdG8gJ2ZhbHNlJyBhbmQgYWxsb3cgSFRUUCAod2l0aG91dCBUTFMpLlwiXHJcbiAgICAgICk7XHJcbiAgICB9XHJcblxyXG4gICAgLy8gRm9yIGJhY2t3YXJkIGNvbXBhdGliaWxpdHlcclxuICAgIGlmICh0aGlzLmxvZ291dFVybC5pbmRleE9mKCd7eycpID4gLTEpIHtcclxuICAgICAgbG9nb3V0VXJsID0gdGhpcy5sb2dvdXRVcmxcclxuICAgICAgICAucmVwbGFjZSgvXFx7XFx7aWRfdG9rZW5cXH1cXH0vLCBpZF90b2tlbilcclxuICAgICAgICAucmVwbGFjZSgvXFx7XFx7Y2xpZW50X2lkXFx9XFx9LywgdGhpcy5jbGllbnRJZCk7XHJcbiAgICB9IGVsc2Uge1xyXG4gICAgICBsZXQgcGFyYW1zID0gbmV3IEh0dHBQYXJhbXMoKTtcclxuXHJcbiAgICAgIGlmIChpZF90b2tlbikge1xyXG4gICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2lkX3Rva2VuX2hpbnQnLCBpZF90b2tlbik7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIGNvbnN0IHBvc3RMb2dvdXRVcmwgPSB0aGlzLnBvc3RMb2dvdXRSZWRpcmVjdFVyaSB8fCB0aGlzLnJlZGlyZWN0VXJpO1xyXG4gICAgICBpZiAocG9zdExvZ291dFVybCkge1xyXG4gICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ3Bvc3RfbG9nb3V0X3JlZGlyZWN0X3VyaScsIHBvc3RMb2dvdXRVcmwpO1xyXG5cclxuICAgICAgICBpZiAoc3RhdGUpIHtcclxuICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ3N0YXRlJywgc3RhdGUpO1xyXG4gICAgICAgIH1cclxuICAgICAgfVxyXG5cclxuICAgICAgbG9nb3V0VXJsID1cclxuICAgICAgICB0aGlzLmxvZ291dFVybCArXHJcbiAgICAgICAgKHRoaXMubG9nb3V0VXJsLmluZGV4T2YoJz8nKSA+IC0xID8gJyYnIDogJz8nKSArXHJcbiAgICAgICAgcGFyYW1zLnRvU3RyaW5nKCk7XHJcbiAgICB9XHJcbiAgICB0aGlzLmNvbmZpZy5vcGVuVXJpKGxvZ291dFVybCk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBAaWdub3JlXHJcbiAgICovXHJcbiAgcHVibGljIGNyZWF0ZUFuZFNhdmVOb25jZSgpOiBQcm9taXNlPHN0cmluZz4ge1xyXG4gICAgY29uc3QgdGhhdCA9IHRoaXM7XHJcbiAgICByZXR1cm4gdGhpcy5jcmVhdGVOb25jZSgpLnRoZW4oZnVuY3Rpb24obm9uY2U6IGFueSkge1xyXG4gICAgICAvLyBVc2UgbG9jYWxTdG9yYWdlIGZvciBub25jZSBpZiBwb3NzaWJsZVxyXG4gICAgICAvLyBsb2NhbFN0b3JhZ2UgaXMgdGhlIG9ubHkgc3RvcmFnZSB3aG8gc3Vydml2ZXMgYVxyXG4gICAgICAvLyByZWRpcmVjdCBpbiBBTEwgYnJvd3NlcnMgKGFsc28gSUUpXHJcbiAgICAgIC8vIE90aGVyd2llc2Ugd2UnZCBmb3JjZSB0ZWFtcyB3aG8gaGF2ZSB0byBzdXBwb3J0XHJcbiAgICAgIC8vIElFIGludG8gdXNpbmcgbG9jYWxTdG9yYWdlIGZvciBldmVyeXRoaW5nXHJcbiAgICAgIGlmIChcclxuICAgICAgICB0aGF0LnNhdmVOb25jZXNJbkxvY2FsU3RvcmFnZSAmJlxyXG4gICAgICAgIHR5cGVvZiB3aW5kb3dbJ2xvY2FsU3RvcmFnZSddICE9PSAndW5kZWZpbmVkJ1xyXG4gICAgICApIHtcclxuICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgnbm9uY2UnLCBub25jZSk7XHJcbiAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgdGhhdC5fc3RvcmFnZS5zZXRJdGVtKCdub25jZScsIG5vbmNlKTtcclxuICAgICAgfVxyXG4gICAgICByZXR1cm4gbm9uY2U7XHJcbiAgICB9KTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIEBpZ25vcmVcclxuICAgKi9cclxuICBwdWJsaWMgbmdPbkRlc3Ryb3koKTogdm9pZCB7XHJcbiAgICB0aGlzLmNsZWFyQWNjZXNzVG9rZW5UaW1lcigpO1xyXG4gICAgdGhpcy5jbGVhcklkVG9rZW5UaW1lcigpO1xyXG5cclxuICAgIHRoaXMucmVtb3ZlU2lsZW50UmVmcmVzaEV2ZW50TGlzdGVuZXIoKTtcclxuICAgIGNvbnN0IHNpbGVudFJlZnJlc2hGcmFtZSA9IHRoaXMuZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXHJcbiAgICAgIHRoaXMuc2lsZW50UmVmcmVzaElGcmFtZU5hbWVcclxuICAgICk7XHJcbiAgICBpZiAoc2lsZW50UmVmcmVzaEZyYW1lKSB7XHJcbiAgICAgIHNpbGVudFJlZnJlc2hGcmFtZS5yZW1vdmUoKTtcclxuICAgIH1cclxuXHJcbiAgICB0aGlzLnN0b3BTZXNzaW9uQ2hlY2tUaW1lcigpO1xyXG4gICAgdGhpcy5yZW1vdmVTZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKCk7XHJcbiAgICBjb25zdCBzZXNzaW9uQ2hlY2tGcmFtZSA9IHRoaXMuZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXHJcbiAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lTmFtZVxyXG4gICAgKTtcclxuICAgIGlmIChzZXNzaW9uQ2hlY2tGcmFtZSkge1xyXG4gICAgICBzZXNzaW9uQ2hlY2tGcmFtZS5yZW1vdmUoKTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBjcmVhdGVOb25jZSgpOiBQcm9taXNlPHN0cmluZz4ge1xyXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKHJlc29sdmUgPT4ge1xyXG4gICAgICBpZiAodGhpcy5ybmdVcmwpIHtcclxuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXHJcbiAgICAgICAgICAnY3JlYXRlTm9uY2Ugd2l0aCBybmctd2ViLWFwaSBoYXMgbm90IGJlZW4gaW1wbGVtZW50ZWQgc28gZmFyJ1xyXG4gICAgICAgICk7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIC8qXHJcbiAgICAgICAqIFRoaXMgYWxwaGFiZXQgaXMgZnJvbTpcclxuICAgICAgICogaHR0cHM6Ly90b29scy5pZXRmLm9yZy9odG1sL3JmYzc2MzYjc2VjdGlvbi00LjFcclxuICAgICAgICpcclxuICAgICAgICogW0EtWl0gLyBbYS16XSAvIFswLTldIC8gXCItXCIgLyBcIi5cIiAvIFwiX1wiIC8gXCJ+XCJcclxuICAgICAgICovXHJcbiAgICAgIGNvbnN0IHVucmVzZXJ2ZWQgPVxyXG4gICAgICAgICdBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OS0uX34nO1xyXG4gICAgICBsZXQgc2l6ZSA9IDQ1O1xyXG4gICAgICBsZXQgaWQgPSAnJztcclxuXHJcbiAgICAgIGNvbnN0IGNyeXB0byA9XHJcbiAgICAgICAgdHlwZW9mIHNlbGYgPT09ICd1bmRlZmluZWQnID8gbnVsbCA6IHNlbGYuY3J5cHRvIHx8IHNlbGZbJ21zQ3J5cHRvJ107XHJcbiAgICAgIGlmIChjcnlwdG8pIHtcclxuICAgICAgICBsZXQgYnl0ZXMgPSBuZXcgVWludDhBcnJheShzaXplKTtcclxuICAgICAgICBjcnlwdG8uZ2V0UmFuZG9tVmFsdWVzKGJ5dGVzKTtcclxuXHJcbiAgICAgICAgLy8gTmVlZGVkIGZvciBJRVxyXG4gICAgICAgIGlmICghYnl0ZXMubWFwKSB7XHJcbiAgICAgICAgICAoYnl0ZXMgYXMgYW55KS5tYXAgPSBBcnJheS5wcm90b3R5cGUubWFwO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgYnl0ZXMgPSBieXRlcy5tYXAoeCA9PiB1bnJlc2VydmVkLmNoYXJDb2RlQXQoeCAlIHVucmVzZXJ2ZWQubGVuZ3RoKSk7XHJcbiAgICAgICAgaWQgPSBTdHJpbmcuZnJvbUNoYXJDb2RlLmFwcGx5KG51bGwsIGJ5dGVzKTtcclxuICAgICAgfSBlbHNlIHtcclxuICAgICAgICB3aGlsZSAoMCA8IHNpemUtLSkge1xyXG4gICAgICAgICAgaWQgKz0gdW5yZXNlcnZlZFsoTWF0aC5yYW5kb20oKSAqIHVucmVzZXJ2ZWQubGVuZ3RoKSB8IDBdO1xyXG4gICAgICAgIH1cclxuICAgICAgfVxyXG5cclxuICAgICAgcmVzb2x2ZShiYXNlNjRVcmxFbmNvZGUoaWQpKTtcclxuICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGFzeW5jIGNoZWNrQXRIYXNoKHBhcmFtczogVmFsaWRhdGlvblBhcmFtcyk6IFByb21pc2U8Ym9vbGVhbj4ge1xyXG4gICAgaWYgKCF0aGlzLnRva2VuVmFsaWRhdGlvbkhhbmRsZXIpIHtcclxuICAgICAgdGhpcy5sb2dnZXIud2FybihcclxuICAgICAgICAnTm8gdG9rZW5WYWxpZGF0aW9uSGFuZGxlciBjb25maWd1cmVkLiBDYW5ub3QgY2hlY2sgYXRfaGFzaC4nXHJcbiAgICAgICk7XHJcbiAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIHRoaXMudG9rZW5WYWxpZGF0aW9uSGFuZGxlci52YWxpZGF0ZUF0SGFzaChwYXJhbXMpO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGNoZWNrU2lnbmF0dXJlKHBhcmFtczogVmFsaWRhdGlvblBhcmFtcyk6IFByb21pc2U8YW55PiB7XHJcbiAgICBpZiAoIXRoaXMudG9rZW5WYWxpZGF0aW9uSGFuZGxlcikge1xyXG4gICAgICB0aGlzLmxvZ2dlci53YXJuKFxyXG4gICAgICAgICdObyB0b2tlblZhbGlkYXRpb25IYW5kbGVyIGNvbmZpZ3VyZWQuIENhbm5vdCBjaGVjayBzaWduYXR1cmUuJ1xyXG4gICAgICApO1xyXG4gICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKG51bGwpO1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIHRoaXMudG9rZW5WYWxpZGF0aW9uSGFuZGxlci52YWxpZGF0ZVNpZ25hdHVyZShwYXJhbXMpO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogU3RhcnQgdGhlIGltcGxpY2l0IGZsb3cgb3IgdGhlIGNvZGUgZmxvdyxcclxuICAgKiBkZXBlbmRpbmcgb24geW91ciBjb25maWd1cmF0aW9uLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBpbml0TG9naW5GbG93KGFkZGl0aW9uYWxTdGF0ZSA9ICcnLCBwYXJhbXMgPSB7fSk6IHZvaWQge1xyXG4gICAgaWYgKHRoaXMucmVzcG9uc2VUeXBlID09PSAnY29kZScpIHtcclxuICAgICAgcmV0dXJuIHRoaXMuaW5pdENvZGVGbG93KGFkZGl0aW9uYWxTdGF0ZSwgcGFyYW1zKTtcclxuICAgIH0gZWxzZSB7XHJcbiAgICAgIHJldHVybiB0aGlzLmluaXRJbXBsaWNpdEZsb3coYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogU3RhcnRzIHRoZSBhdXRob3JpemF0aW9uIGNvZGUgZmxvdyBhbmQgcmVkaXJlY3RzIHRvIHVzZXIgdG9cclxuICAgKiB0aGUgYXV0aCBzZXJ2ZXJzIGxvZ2luIHVybC5cclxuICAgKi9cclxuICBwdWJsaWMgaW5pdENvZGVGbG93KGFkZGl0aW9uYWxTdGF0ZSA9ICcnLCBwYXJhbXMgPSB7fSk6IHZvaWQge1xyXG4gICAgaWYgKHRoaXMubG9naW5VcmwgIT09ICcnKSB7XHJcbiAgICAgIHRoaXMuaW5pdENvZGVGbG93SW50ZXJuYWwoYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpO1xyXG4gICAgfSBlbHNlIHtcclxuICAgICAgdGhpcy5ldmVudHNcclxuICAgICAgICAucGlwZShmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZGVkJykpXHJcbiAgICAgICAgLnN1YnNjcmliZShfID0+IHRoaXMuaW5pdENvZGVGbG93SW50ZXJuYWwoYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpKTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIHByaXZhdGUgaW5pdENvZGVGbG93SW50ZXJuYWwoYWRkaXRpb25hbFN0YXRlID0gJycsIHBhcmFtcyA9IHt9KTogdm9pZCB7XHJcbiAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh0aGlzLmxvZ2luVXJsKSkge1xyXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXHJcbiAgICAgICAgXCJsb2dpblVybCAgbXVzdCB1c2UgSFRUUFMgKHdpdGggVExTKSwgb3IgY29uZmlnIHZhbHVlIGZvciBwcm9wZXJ0eSAncmVxdWlyZUh0dHBzJyBtdXN0IGJlIHNldCB0byAnZmFsc2UnIGFuZCBhbGxvdyBIVFRQICh3aXRob3V0IFRMUykuXCJcclxuICAgICAgKTtcclxuICAgIH1cclxuXHJcbiAgICB0aGlzLmNyZWF0ZUxvZ2luVXJsKGFkZGl0aW9uYWxTdGF0ZSwgJycsIG51bGwsIGZhbHNlLCBwYXJhbXMpXHJcbiAgICAgIC50aGVuKHRoaXMuY29uZmlnLm9wZW5VcmkpXHJcbiAgICAgIC5jYXRjaChlcnJvciA9PiB7XHJcbiAgICAgICAgY29uc29sZS5lcnJvcignRXJyb3IgaW4gaW5pdEF1dGhvcml6YXRpb25Db2RlRmxvdycpO1xyXG4gICAgICAgIGNvbnNvbGUuZXJyb3IoZXJyb3IpO1xyXG4gICAgICB9KTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBhc3luYyBjcmVhdGVDaGFsbGFuZ2VWZXJpZmllclBhaXJGb3JQS0NFKCk6IFByb21pc2U8XHJcbiAgICBbc3RyaW5nLCBzdHJpbmddXHJcbiAgPiB7XHJcbiAgICBpZiAoIXRoaXMuY3J5cHRvKSB7XHJcbiAgICAgIHRocm93IG5ldyBFcnJvcihcclxuICAgICAgICAnUEtDRSBzdXBwb3J0IGZvciBjb2RlIGZsb3cgbmVlZHMgYSBDcnlwdG9IYW5kZXIuIERpZCB5b3UgaW1wb3J0IHRoZSBPQXV0aE1vZHVsZSB1c2luZyBmb3JSb290KCkgPydcclxuICAgICAgKTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCB2ZXJpZmllciA9IGF3YWl0IHRoaXMuY3JlYXRlTm9uY2UoKTtcclxuICAgIGNvbnN0IGNoYWxsZW5nZVJhdyA9IGF3YWl0IHRoaXMuY3J5cHRvLmNhbGNIYXNoKHZlcmlmaWVyLCAnc2hhLTI1NicpO1xyXG4gICAgY29uc3QgY2hhbGxlbmdlID0gYmFzZTY0VXJsRW5jb2RlKGNoYWxsZW5nZVJhdyk7XHJcblxyXG4gICAgcmV0dXJuIFtjaGFsbGVuZ2UsIHZlcmlmaWVyXTtcclxuICB9XHJcblxyXG4gIHByaXZhdGUgZXh0cmFjdFJlY29nbml6ZWRDdXN0b21QYXJhbWV0ZXJzKFxyXG4gICAgdG9rZW5SZXNwb25zZTogVG9rZW5SZXNwb25zZVxyXG4gICk6IE1hcDxzdHJpbmcsIHN0cmluZz4ge1xyXG4gICAgbGV0IGZvdW5kUGFyYW1ldGVyczogTWFwPHN0cmluZywgc3RyaW5nPiA9IG5ldyBNYXA8c3RyaW5nLCBzdHJpbmc+KCk7XHJcbiAgICBpZiAoIXRoaXMuY29uZmlnLmN1c3RvbVRva2VuUGFyYW1ldGVycykge1xyXG4gICAgICByZXR1cm4gZm91bmRQYXJhbWV0ZXJzO1xyXG4gICAgfVxyXG4gICAgdGhpcy5jb25maWcuY3VzdG9tVG9rZW5QYXJhbWV0ZXJzLmZvckVhY2goKHJlY29nbml6ZWRQYXJhbWV0ZXI6IHN0cmluZykgPT4ge1xyXG4gICAgICBpZiAodG9rZW5SZXNwb25zZVtyZWNvZ25pemVkUGFyYW1ldGVyXSkge1xyXG4gICAgICAgIGZvdW5kUGFyYW1ldGVycy5zZXQoXHJcbiAgICAgICAgICByZWNvZ25pemVkUGFyYW1ldGVyLFxyXG4gICAgICAgICAgSlNPTi5zdHJpbmdpZnkodG9rZW5SZXNwb25zZVtyZWNvZ25pemVkUGFyYW1ldGVyXSlcclxuICAgICAgICApO1xyXG4gICAgICB9XHJcbiAgICB9KTtcclxuICAgIHJldHVybiBmb3VuZFBhcmFtZXRlcnM7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBSZXZva2VzIHRoZSBhdXRoIHRva2VuIHRvIHNlY3VyZSB0aGUgdnVsbmFyYWJpbGl0eVxyXG4gICAqIG9mIHRoZSB0b2tlbiBpc3N1ZWQgYWxsb3dpbmcgdGhlIGF1dGhvcml6YXRpb24gc2VydmVyIHRvIGNsZWFuXHJcbiAgICogdXAgYW55IHNlY3VyaXR5IGNyZWRlbnRpYWxzIGFzc29jaWF0ZWQgd2l0aCB0aGUgYXV0aG9yaXphdGlvblxyXG4gICAqL1xyXG4gIHB1YmxpYyByZXZva2VUb2tlbkFuZExvZ291dCgpOiBQcm9taXNlPGFueT4ge1xyXG4gICAgbGV0IHJldm9rZUVuZHBvaW50ID0gdGhpcy5yZXZvY2F0aW9uRW5kcG9pbnQ7XHJcbiAgICBsZXQgYWNjZXNzVG9rZW4gPSB0aGlzLmdldEFjY2Vzc1Rva2VuKCk7XHJcbiAgICBsZXQgcmVmcmVzaFRva2VuID0gdGhpcy5nZXRSZWZyZXNoVG9rZW4oKTtcclxuXHJcbiAgICBpZiAoIWFjY2Vzc1Rva2VuKSB7XHJcbiAgICAgIHJldHVybjtcclxuICAgIH1cclxuXHJcbiAgICBsZXQgcGFyYW1zID0gbmV3IEh0dHBQYXJhbXMoKTtcclxuXHJcbiAgICBsZXQgaGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpLnNldChcclxuICAgICAgJ0NvbnRlbnQtVHlwZScsXHJcbiAgICAgICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnXHJcbiAgICApO1xyXG5cclxuICAgIGlmICh0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcclxuICAgICAgY29uc3QgaGVhZGVyID0gYnRvYShgJHt0aGlzLmNsaWVudElkfToke3RoaXMuZHVtbXlDbGllbnRTZWNyZXR9YCk7XHJcbiAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldCgnQXV0aG9yaXphdGlvbicsICdCYXNpYyAnICsgaGVhZGVyKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCkge1xyXG4gICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdjbGllbnRfaWQnLCB0aGlzLmNsaWVudElkKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCAmJiB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KSB7XHJcbiAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9zZWNyZXQnLCB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAodGhpcy5jdXN0b21RdWVyeVBhcmFtcykge1xyXG4gICAgICBmb3IgKGNvbnN0IGtleSBvZiBPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSkge1xyXG4gICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoa2V5LCB0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zW2tleV0pO1xyXG4gICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcclxuICAgICAgbGV0IHJldm9rZUFjY2Vzc1Rva2VuOiBPYnNlcnZhYmxlPHZvaWQ+O1xyXG4gICAgICBsZXQgcmV2b2tlUmVmcmVzaFRva2VuOiBPYnNlcnZhYmxlPHZvaWQ+O1xyXG5cclxuICAgICAgaWYgKGFjY2Vzc1Rva2VuKSB7XHJcbiAgICAgICAgbGV0IHJldm9rYXRpb25QYXJhbXMgPSBwYXJhbXNcclxuICAgICAgICAgIC5zZXQoJ3Rva2VuJywgYWNjZXNzVG9rZW4pXHJcbiAgICAgICAgICAuc2V0KCd0b2tlbl90eXBlX2hpbnQnLCAnYWNjZXNzX3Rva2VuJyk7XHJcbiAgICAgICAgcmV2b2tlQWNjZXNzVG9rZW4gPSB0aGlzLmh0dHAucG9zdDx2b2lkPihcclxuICAgICAgICAgIHJldm9rZUVuZHBvaW50LFxyXG4gICAgICAgICAgcmV2b2thdGlvblBhcmFtcyxcclxuICAgICAgICAgIHsgaGVhZGVycyB9XHJcbiAgICAgICAgKTtcclxuICAgICAgfSBlbHNlIHtcclxuICAgICAgICByZXZva2VBY2Nlc3NUb2tlbiA9IG9mKG51bGwpO1xyXG4gICAgICB9XHJcblxyXG4gICAgICBpZiAocmVmcmVzaFRva2VuKSB7XHJcbiAgICAgICAgbGV0IHJldm9rYXRpb25QYXJhbXMgPSBwYXJhbXNcclxuICAgICAgICAgIC5zZXQoJ3Rva2VuJywgcmVmcmVzaFRva2VuKVxyXG4gICAgICAgICAgLnNldCgndG9rZW5fdHlwZV9oaW50JywgJ3JlZnJlc2hfdG9rZW4nKTtcclxuICAgICAgICByZXZva2VSZWZyZXNoVG9rZW4gPSB0aGlzLmh0dHAucG9zdDx2b2lkPihcclxuICAgICAgICAgIHJldm9rZUVuZHBvaW50LFxyXG4gICAgICAgICAgcmV2b2thdGlvblBhcmFtcyxcclxuICAgICAgICAgIHsgaGVhZGVycyB9XHJcbiAgICAgICAgKTtcclxuICAgICAgfSBlbHNlIHtcclxuICAgICAgICByZXZva2VSZWZyZXNoVG9rZW4gPSBvZihudWxsKTtcclxuICAgICAgfVxyXG5cclxuICAgICAgY29tYmluZUxhdGVzdChbcmV2b2tlQWNjZXNzVG9rZW4sIHJldm9rZVJlZnJlc2hUb2tlbl0pLnN1YnNjcmliZShcclxuICAgICAgICByZXMgPT4ge1xyXG4gICAgICAgICAgdGhpcy5sb2dPdXQoKTtcclxuICAgICAgICAgIHJlc29sdmUocmVzKTtcclxuICAgICAgICAgIHRoaXMubG9nZ2VyLmluZm8oJ1Rva2VuIHN1Y2Nlc3NmdWxseSByZXZva2VkJyk7XHJcbiAgICAgICAgfSxcclxuICAgICAgICBlcnIgPT4ge1xyXG4gICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ0Vycm9yIHJldm9raW5nIHRva2VuJywgZXJyKTtcclxuICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxyXG4gICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl9yZXZva2VfZXJyb3InLCBlcnIpXHJcbiAgICAgICAgICApO1xyXG4gICAgICAgICAgcmVqZWN0KGVycik7XHJcbiAgICAgICAgfVxyXG4gICAgICApO1xyXG4gICAgfSk7XHJcbiAgfVxyXG59XHJcbiJdfQ==