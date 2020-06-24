import { __awaiter, __generator } from "tslib";
import { base64UrlEncode } from '../base64-helper';
/**
 * Interface for Handlers that are hooked in to
 * validate tokens.
 */
var ValidationHandler = /** @class */ (function () {
    function ValidationHandler() {
    }
    return ValidationHandler;
}());
export { ValidationHandler };
/**
 * This abstract implementation of ValidationHandler already implements
 * the method validateAtHash. However, to make use of it,
 * you have to override the method calcHash.
 */
var AbstractValidationHandler = /** @class */ (function () {
    function AbstractValidationHandler() {
    }
    /**
     * Validates the at_hash in an id_token against the received access_token.
     */
    AbstractValidationHandler.prototype.validateAtHash = function (params) {
        return __awaiter(this, void 0, void 0, function () {
            var hashAlg, tokenHash, leftMostHalf, atHash, claimsAtHash;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        hashAlg = this.inferHashAlgorithm(params.idTokenHeader);
                        return [4 /*yield*/, this.calcHash(params.accessToken, hashAlg)];
                    case 1:
                        tokenHash = _a.sent();
                        leftMostHalf = tokenHash.substr(0, tokenHash.length / 2);
                        atHash = base64UrlEncode(leftMostHalf);
                        claimsAtHash = params.idTokenClaims['at_hash'].replace(/=/g, '');
                        if (atHash !== claimsAtHash) {
                            console.error('exptected at_hash: ' + atHash);
                            console.error('actual at_hash: ' + claimsAtHash);
                        }
                        return [2 /*return*/, atHash === claimsAtHash];
                }
            });
        });
    };
    /**
     * Infers the name of the hash algorithm to use
     * from the alg field of an id_token.
     *
     * @param jwtHeader the id_token's parsed header
     */
    AbstractValidationHandler.prototype.inferHashAlgorithm = function (jwtHeader) {
        var alg = jwtHeader['alg'];
        if (!alg.match(/^.S[0-9]{3}$/)) {
            throw new Error('Algorithm not supported: ' + alg);
        }
        return 'sha-' + alg.substr(2);
    };
    return AbstractValidationHandler;
}());
export { AbstractValidationHandler };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidmFsaWRhdGlvbi1oYW5kbGVyLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1vYXV0aDItb2lkYy8iLCJzb3VyY2VzIjpbInRva2VuLXZhbGlkYXRpb24vdmFsaWRhdGlvbi1oYW5kbGVyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQSxPQUFPLEVBQUUsZUFBZSxFQUFFLE1BQU0sa0JBQWtCLENBQUM7QUFXbkQ7OztHQUdHO0FBQ0g7SUFBQTtJQWNBLENBQUM7SUFBRCx3QkFBQztBQUFELENBQUMsQUFkRCxJQWNDOztBQUVEOzs7O0dBSUc7QUFDSDtJQUFBO0lBdURBLENBQUM7SUFqREM7O09BRUc7SUFDRyxrREFBYyxHQUFwQixVQUFxQixNQUF3Qjs7Ozs7O3dCQUN2QyxPQUFPLEdBQUcsSUFBSSxDQUFDLGtCQUFrQixDQUFDLE1BQU0sQ0FBQyxhQUFhLENBQUMsQ0FBQzt3QkFFNUMscUJBQU0sSUFBSSxDQUFDLFFBQVEsQ0FBQyxNQUFNLENBQUMsV0FBVyxFQUFFLE9BQU8sQ0FBQyxFQUFBOzt3QkFBNUQsU0FBUyxHQUFHLFNBQWdEO3dCQUU1RCxZQUFZLEdBQUcsU0FBUyxDQUFDLE1BQU0sQ0FBQyxDQUFDLEVBQUUsU0FBUyxDQUFDLE1BQU0sR0FBRyxDQUFDLENBQUMsQ0FBQzt3QkFFekQsTUFBTSxHQUFHLGVBQWUsQ0FBQyxZQUFZLENBQUMsQ0FBQzt3QkFFdkMsWUFBWSxHQUFHLE1BQU0sQ0FBQyxhQUFhLENBQUMsU0FBUyxDQUFDLENBQUMsT0FBTyxDQUFDLElBQUksRUFBRSxFQUFFLENBQUMsQ0FBQzt3QkFFckUsSUFBSSxNQUFNLEtBQUssWUFBWSxFQUFFOzRCQUMzQixPQUFPLENBQUMsS0FBSyxDQUFDLHFCQUFxQixHQUFHLE1BQU0sQ0FBQyxDQUFDOzRCQUM5QyxPQUFPLENBQUMsS0FBSyxDQUFDLGtCQUFrQixHQUFHLFlBQVksQ0FBQyxDQUFDO3lCQUNsRDt3QkFFRCxzQkFBTyxNQUFNLEtBQUssWUFBWSxFQUFDOzs7O0tBQ2hDO0lBRUQ7Ozs7O09BS0c7SUFDTyxzREFBa0IsR0FBNUIsVUFBNkIsU0FBaUI7UUFDNUMsSUFBSSxHQUFHLEdBQVcsU0FBUyxDQUFDLEtBQUssQ0FBQyxDQUFDO1FBRW5DLElBQUksQ0FBQyxHQUFHLENBQUMsS0FBSyxDQUFDLGNBQWMsQ0FBQyxFQUFFO1lBQzlCLE1BQU0sSUFBSSxLQUFLLENBQUMsMkJBQTJCLEdBQUcsR0FBRyxDQUFDLENBQUM7U0FDcEQ7UUFFRCxPQUFPLE1BQU0sR0FBRyxHQUFHLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxDQUFDO0lBQ2hDLENBQUM7SUFhSCxnQ0FBQztBQUFELENBQUMsQUF2REQsSUF1REMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBiYXNlNjRVcmxFbmNvZGUgfSBmcm9tICcuLi9iYXNlNjQtaGVscGVyJztcclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgVmFsaWRhdGlvblBhcmFtcyB7XHJcbiAgaWRUb2tlbjogc3RyaW5nO1xyXG4gIGFjY2Vzc1Rva2VuOiBzdHJpbmc7XHJcbiAgaWRUb2tlbkhlYWRlcjogb2JqZWN0O1xyXG4gIGlkVG9rZW5DbGFpbXM6IG9iamVjdDtcclxuICBqd2tzOiBvYmplY3Q7XHJcbiAgbG9hZEtleXM6ICgpID0+IFByb21pc2U8b2JqZWN0PjtcclxufVxyXG5cclxuLyoqXHJcbiAqIEludGVyZmFjZSBmb3IgSGFuZGxlcnMgdGhhdCBhcmUgaG9va2VkIGluIHRvXHJcbiAqIHZhbGlkYXRlIHRva2Vucy5cclxuICovXHJcbmV4cG9ydCBhYnN0cmFjdCBjbGFzcyBWYWxpZGF0aW9uSGFuZGxlciB7XHJcbiAgLyoqXHJcbiAgICogVmFsaWRhdGVzIHRoZSBzaWduYXR1cmUgb2YgYW4gaWRfdG9rZW4uXHJcbiAgICovXHJcbiAgcHVibGljIGFic3RyYWN0IHZhbGlkYXRlU2lnbmF0dXJlKFxyXG4gICAgdmFsaWRhdGlvblBhcmFtczogVmFsaWRhdGlvblBhcmFtc1xyXG4gICk6IFByb21pc2U8YW55PjtcclxuXHJcbiAgLyoqXHJcbiAgICogVmFsaWRhdGVzIHRoZSBhdF9oYXNoIGluIGFuIGlkX3Rva2VuIGFnYWluc3QgdGhlIHJlY2VpdmVkIGFjY2Vzc190b2tlbi5cclxuICAgKi9cclxuICBwdWJsaWMgYWJzdHJhY3QgdmFsaWRhdGVBdEhhc2goXHJcbiAgICB2YWxpZGF0aW9uUGFyYW1zOiBWYWxpZGF0aW9uUGFyYW1zXHJcbiAgKTogUHJvbWlzZTxib29sZWFuPjtcclxufVxyXG5cclxuLyoqXHJcbiAqIFRoaXMgYWJzdHJhY3QgaW1wbGVtZW50YXRpb24gb2YgVmFsaWRhdGlvbkhhbmRsZXIgYWxyZWFkeSBpbXBsZW1lbnRzXHJcbiAqIHRoZSBtZXRob2QgdmFsaWRhdGVBdEhhc2guIEhvd2V2ZXIsIHRvIG1ha2UgdXNlIG9mIGl0LFxyXG4gKiB5b3UgaGF2ZSB0byBvdmVycmlkZSB0aGUgbWV0aG9kIGNhbGNIYXNoLlxyXG4gKi9cclxuZXhwb3J0IGFic3RyYWN0IGNsYXNzIEFic3RyYWN0VmFsaWRhdGlvbkhhbmRsZXIgaW1wbGVtZW50cyBWYWxpZGF0aW9uSGFuZGxlciB7XHJcbiAgLyoqXHJcbiAgICogVmFsaWRhdGVzIHRoZSBzaWduYXR1cmUgb2YgYW4gaWRfdG9rZW4uXHJcbiAgICovXHJcbiAgYWJzdHJhY3QgdmFsaWRhdGVTaWduYXR1cmUodmFsaWRhdGlvblBhcmFtczogVmFsaWRhdGlvblBhcmFtcyk6IFByb21pc2U8YW55PjtcclxuXHJcbiAgLyoqXHJcbiAgICogVmFsaWRhdGVzIHRoZSBhdF9oYXNoIGluIGFuIGlkX3Rva2VuIGFnYWluc3QgdGhlIHJlY2VpdmVkIGFjY2Vzc190b2tlbi5cclxuICAgKi9cclxuICBhc3luYyB2YWxpZGF0ZUF0SGFzaChwYXJhbXM6IFZhbGlkYXRpb25QYXJhbXMpOiBQcm9taXNlPGJvb2xlYW4+IHtcclxuICAgIGxldCBoYXNoQWxnID0gdGhpcy5pbmZlckhhc2hBbGdvcml0aG0ocGFyYW1zLmlkVG9rZW5IZWFkZXIpO1xyXG5cclxuICAgIGxldCB0b2tlbkhhc2ggPSBhd2FpdCB0aGlzLmNhbGNIYXNoKHBhcmFtcy5hY2Nlc3NUb2tlbiwgaGFzaEFsZyk7IC8vIHNoYTI1NihhY2Nlc3NUb2tlbiwgeyBhc1N0cmluZzogdHJ1ZSB9KTtcclxuXHJcbiAgICBsZXQgbGVmdE1vc3RIYWxmID0gdG9rZW5IYXNoLnN1YnN0cigwLCB0b2tlbkhhc2gubGVuZ3RoIC8gMik7XHJcblxyXG4gICAgbGV0IGF0SGFzaCA9IGJhc2U2NFVybEVuY29kZShsZWZ0TW9zdEhhbGYpO1xyXG5cclxuICAgIGxldCBjbGFpbXNBdEhhc2ggPSBwYXJhbXMuaWRUb2tlbkNsYWltc1snYXRfaGFzaCddLnJlcGxhY2UoLz0vZywgJycpO1xyXG5cclxuICAgIGlmIChhdEhhc2ggIT09IGNsYWltc0F0SGFzaCkge1xyXG4gICAgICBjb25zb2xlLmVycm9yKCdleHB0ZWN0ZWQgYXRfaGFzaDogJyArIGF0SGFzaCk7XHJcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ2FjdHVhbCBhdF9oYXNoOiAnICsgY2xhaW1zQXRIYXNoKTtcclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gYXRIYXNoID09PSBjbGFpbXNBdEhhc2g7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBJbmZlcnMgdGhlIG5hbWUgb2YgdGhlIGhhc2ggYWxnb3JpdGhtIHRvIHVzZVxyXG4gICAqIGZyb20gdGhlIGFsZyBmaWVsZCBvZiBhbiBpZF90b2tlbi5cclxuICAgKlxyXG4gICAqIEBwYXJhbSBqd3RIZWFkZXIgdGhlIGlkX3Rva2VuJ3MgcGFyc2VkIGhlYWRlclxyXG4gICAqL1xyXG4gIHByb3RlY3RlZCBpbmZlckhhc2hBbGdvcml0aG0oand0SGVhZGVyOiBvYmplY3QpOiBzdHJpbmcge1xyXG4gICAgbGV0IGFsZzogc3RyaW5nID0gand0SGVhZGVyWydhbGcnXTtcclxuXHJcbiAgICBpZiAoIWFsZy5tYXRjaCgvXi5TWzAtOV17M30kLykpIHtcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKCdBbGdvcml0aG0gbm90IHN1cHBvcnRlZDogJyArIGFsZyk7XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuICdzaGEtJyArIGFsZy5zdWJzdHIoMik7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBDYWxjdWxhdGVzIHRoZSBoYXNoIGZvciB0aGUgcGFzc2VkIHZhbHVlIGJ5IHVzaW5nXHJcbiAgICogdGhlIHBhc3NlZCBoYXNoIGFsZ29yaXRobS5cclxuICAgKlxyXG4gICAqIEBwYXJhbSB2YWx1ZVRvSGFzaFxyXG4gICAqIEBwYXJhbSBhbGdvcml0aG1cclxuICAgKi9cclxuICBwcm90ZWN0ZWQgYWJzdHJhY3QgY2FsY0hhc2goXHJcbiAgICB2YWx1ZVRvSGFzaDogc3RyaW5nLFxyXG4gICAgYWxnb3JpdGhtOiBzdHJpbmdcclxuICApOiBQcm9taXNlPHN0cmluZz47XHJcbn1cclxuIl19