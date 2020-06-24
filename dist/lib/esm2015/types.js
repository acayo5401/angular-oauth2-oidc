import { __decorate } from "tslib";
import { Injectable } from '@angular/core';
/**
 * Additional options that can be passed to tryLogin.
 */
export class LoginOptions {
    constructor() {
        /**
         * Normally, you want to clear your hash fragment after
         * the lib read the token(s) so that they are not displayed
         * anymore in the url. If not, set this to true. For code flow
         * this controls removing query string values.
         */
        this.preventClearHashAfterLogin = false;
    }
}
/**
 * Defines the logging interface the OAuthService uses
 * internally. Is compatible with the `console` object,
 * but you can provide your own implementation as well
 * through dependency injection.
 */
export class OAuthLogger {
}
/**
 * Defines a simple storage that can be used for
 * storing the tokens at client side.
 * Is compatible to localStorage and sessionStorage,
 * but you can also create your own implementations.
 */
export class OAuthStorage {
}
let MemoryStorage = class MemoryStorage {
    constructor() {
        this.data = new Map();
    }
    getItem(key) {
        return this.data.get(key);
    }
    removeItem(key) {
        this.data.delete(key);
    }
    setItem(key, data) {
        this.data.set(key, data);
    }
};
MemoryStorage = __decorate([
    Injectable()
], MemoryStorage);
export { MemoryStorage };
/**
 * Represents the received tokens, the received state
 * and the parsed claims from the id-token.
 */
export class ReceivedTokens {
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidHlwZXMuanMiLCJzb3VyY2VSb290Ijoibmc6Ly9hbmd1bGFyLW9hdXRoMi1vaWRjLyIsInNvdXJjZXMiOlsidHlwZXMudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IjtBQUFBLE9BQU8sRUFBRSxVQUFVLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFFM0M7O0dBRUc7QUFDSCxNQUFNLE9BQU8sWUFBWTtJQUF6QjtRQThDRTs7Ozs7V0FLRztRQUNILCtCQUEwQixHQUFJLEtBQUssQ0FBQztJQVF0QyxDQUFDO0NBQUE7QUFFRDs7Ozs7R0FLRztBQUNILE1BQU0sT0FBZ0IsV0FBVztDQU1oQztBQUVEOzs7OztHQUtHO0FBQ0gsTUFBTSxPQUFnQixZQUFZO0NBSWpDO0FBR0QsSUFBYSxhQUFhLEdBQTFCLE1BQWEsYUFBYTtJQUExQjtRQUNVLFNBQUksR0FBRyxJQUFJLEdBQUcsRUFBa0IsQ0FBQztJQWEzQyxDQUFDO0lBWEMsT0FBTyxDQUFDLEdBQVc7UUFDakIsT0FBTyxJQUFJLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUM1QixDQUFDO0lBRUQsVUFBVSxDQUFDLEdBQVc7UUFDcEIsSUFBSSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUM7SUFDeEIsQ0FBQztJQUVELE9BQU8sQ0FBQyxHQUFXLEVBQUUsSUFBWTtRQUMvQixJQUFJLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxHQUFHLEVBQUUsSUFBSSxDQUFDLENBQUM7SUFDM0IsQ0FBQztDQUNGLENBQUE7QUFkWSxhQUFhO0lBRHpCLFVBQVUsRUFBRTtHQUNBLGFBQWEsQ0FjekI7U0FkWSxhQUFhO0FBZ0IxQjs7O0dBR0c7QUFDSCxNQUFNLE9BQU8sY0FBYztDQUsxQiIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcclxuXHJcbi8qKlxyXG4gKiBBZGRpdGlvbmFsIG9wdGlvbnMgdGhhdCBjYW4gYmUgcGFzc2VkIHRvIHRyeUxvZ2luLlxyXG4gKi9cclxuZXhwb3J0IGNsYXNzIExvZ2luT3B0aW9ucyB7XHJcbiAgLyoqXHJcbiAgICogSXMgY2FsbGVkLCBhZnRlciBhIHRva2VuIGhhcyBiZWVuIHJlY2VpdmVkIGFuZFxyXG4gICAqIHN1Y2Nlc3NmdWxseSB2YWxpZGF0ZWQuXHJcbiAgICpcclxuICAgKiBEZXByZWNhdGVkOiAgVXNlIHByb3BlcnR5IGBgZXZlbnRzYGAgb24gT0F1dGhTZXJ2aWNlIGluc3RlYWQuXHJcbiAgICovXHJcbiAgb25Ub2tlblJlY2VpdmVkPzogKHJlY2VpdmVkVG9rZW5zOiBSZWNlaXZlZFRva2VucykgPT4gdm9pZDtcclxuXHJcbiAgLyoqXHJcbiAgICogSG9vaywgdG8gdmFsaWRhdGUgdGhlIHJlY2VpdmVkIHRva2Vucy5cclxuICAgKlxyXG4gICAqIERlcHJlY2F0ZWQ6ICBVc2UgcHJvcGVydHkgYGB0b2tlblZhbGlkYXRpb25IYW5kbGVyYGAgb24gT0F1dGhTZXJ2aWNlIGluc3RlYWQuXHJcbiAgICovXHJcbiAgdmFsaWRhdGlvbkhhbmRsZXI/OiAocmVjZWl2ZWRUb2tlbnM6IFJlY2VpdmVkVG9rZW5zKSA9PiBQcm9taXNlPGFueT47XHJcblxyXG4gIC8qKlxyXG4gICAqIENhbGxlZCB3aGVuIHRyeUxvZ2luIGRldGVjdHMgdGhhdCB0aGUgYXV0aCBzZXJ2ZXJcclxuICAgKiBpbmNsdWRlZCBhbiBlcnJvciBtZXNzYWdlIGludG8gdGhlIGhhc2ggZnJhZ21lbnQuXHJcbiAgICpcclxuICAgKiBEZXByZWNhdGVkOiAgVXNlIHByb3BlcnR5IGBgZXZlbnRzYGAgb24gT0F1dGhTZXJ2aWNlIGluc3RlYWQuXHJcbiAgICovXHJcbiAgb25Mb2dpbkVycm9yPzogKHBhcmFtczogb2JqZWN0KSA9PiB2b2lkO1xyXG5cclxuICAvKipcclxuICAgKiBBIGN1c3RvbSBoYXNoIGZyYWdtZW50IHRvIGJlIHVzZWQgaW5zdGVhZCBvZiB0aGVcclxuICAgKiBhY3R1YWwgb25lLiBUaGlzIGlzIHVzZWQgZm9yIHNpbGVudCByZWZyZXNoZXMsIHRvXHJcbiAgICogcGFzcyB0aGUgaWZyYW1lcyBoYXNoIGZyYWdtZW50IHRvIHRoaXMgbWV0aG9kLCBhbmRcclxuICAgKiBpcyBhbHNvIHVzZWQgYnkgcG9wdXAgZmxvd3MgaW4gdGhlIHNhbWUgbWFubmVyLlxyXG4gICAqIFRoaXMgY2FuIGJlIHVzZWQgd2l0aCBjb2RlIGZsb3csIHdoZXJlIGlzIG11c3QgYmUgc2V0XHJcbiAgICogdG8gYSBoYXNoIHN5bWJvbCBmb2xsb3dlZCBieSB0aGUgcXVlcnlzdHJpbmcuIFRoZVxyXG4gICAqIHF1ZXN0aW9uIG1hcmsgaXMgb3B0aW9uYWwsIGJ1dCBtYXkgYmUgcHJlc2VudCBmb2xsb3dpbmdcclxuICAgKiB0aGUgaGFzaCBzeW1ib2wuXHJcbiAgICovXHJcbiAgY3VzdG9tSGFzaEZyYWdtZW50Pzogc3RyaW5nO1xyXG5cclxuICAvKipcclxuICAgKiBTZXQgdGhpcyB0byB0cnVlIHRvIGRpc2FibGUgdGhlIG9hdXRoMiBzdGF0ZVxyXG4gICAqIGNoZWNrIHdoaWNoIGlzIGEgYmVzdCBwcmFjdGljZSB0byBhdm9pZFxyXG4gICAqIHNlY3VyaXR5IGF0dGFja3MuXHJcbiAgICogQXMgT0lEQyBkZWZpbmVzIGEgbm9uY2UgY2hlY2sgdGhhdCBpbmNsdWRlc1xyXG4gICAqIHRoaXMsIHRoaXMgY2FuIGJlIHNldCB0byB0cnVlIHdoZW4gb25seSBkb2luZ1xyXG4gICAqIE9JREMuXHJcbiAgICovXHJcbiAgZGlzYWJsZU9BdXRoMlN0YXRlQ2hlY2s/OiBib29sZWFuO1xyXG5cclxuICAvKipcclxuICAgKiBOb3JtYWxseSwgeW91IHdhbnQgdG8gY2xlYXIgeW91ciBoYXNoIGZyYWdtZW50IGFmdGVyXHJcbiAgICogdGhlIGxpYiByZWFkIHRoZSB0b2tlbihzKSBzbyB0aGF0IHRoZXkgYXJlIG5vdCBkaXNwbGF5ZWRcclxuICAgKiBhbnltb3JlIGluIHRoZSB1cmwuIElmIG5vdCwgc2V0IHRoaXMgdG8gdHJ1ZS4gRm9yIGNvZGUgZmxvd1xyXG4gICAqIHRoaXMgY29udHJvbHMgcmVtb3ZpbmcgcXVlcnkgc3RyaW5nIHZhbHVlcy5cclxuICAgKi9cclxuICBwcmV2ZW50Q2xlYXJIYXNoQWZ0ZXJMb2dpbj8gPSBmYWxzZTtcclxuXHJcbiAgLyoqXHJcbiAgICogU2V0IHRoaXMgZm9yIGNvZGUgZmxvdyBpZiB5b3UgdXNlZCBhIGN1c3RvbSByZWRpcmVjdCBVcmlcclxuICAgKiB3aGVuIHJldHJpZXZpbmcgdGhlIGNvZGUuIFRoaXMgaXMgdXNlZCBpbnRlcm5hbGx5IGZvciBzaWxlbnRcclxuICAgKiByZWZyZXNoIGFuZCBwb3B1cCBmbG93cy5cclxuICAgKi9cclxuICBjdXN0b21SZWRpcmVjdFVyaT86IHN0cmluZztcclxufVxyXG5cclxuLyoqXHJcbiAqIERlZmluZXMgdGhlIGxvZ2dpbmcgaW50ZXJmYWNlIHRoZSBPQXV0aFNlcnZpY2UgdXNlc1xyXG4gKiBpbnRlcm5hbGx5LiBJcyBjb21wYXRpYmxlIHdpdGggdGhlIGBjb25zb2xlYCBvYmplY3QsXHJcbiAqIGJ1dCB5b3UgY2FuIHByb3ZpZGUgeW91ciBvd24gaW1wbGVtZW50YXRpb24gYXMgd2VsbFxyXG4gKiB0aHJvdWdoIGRlcGVuZGVuY3kgaW5qZWN0aW9uLlxyXG4gKi9cclxuZXhwb3J0IGFic3RyYWN0IGNsYXNzIE9BdXRoTG9nZ2VyIHtcclxuICBhYnN0cmFjdCBkZWJ1ZyhtZXNzYWdlPzogYW55LCAuLi5vcHRpb25hbFBhcmFtczogYW55W10pOiB2b2lkO1xyXG4gIGFic3RyYWN0IGluZm8obWVzc2FnZT86IGFueSwgLi4ub3B0aW9uYWxQYXJhbXM6IGFueVtdKTogdm9pZDtcclxuICBhYnN0cmFjdCBsb2cobWVzc2FnZT86IGFueSwgLi4ub3B0aW9uYWxQYXJhbXM6IGFueVtdKTogdm9pZDtcclxuICBhYnN0cmFjdCB3YXJuKG1lc3NhZ2U/OiBhbnksIC4uLm9wdGlvbmFsUGFyYW1zOiBhbnlbXSk6IHZvaWQ7XHJcbiAgYWJzdHJhY3QgZXJyb3IobWVzc2FnZT86IGFueSwgLi4ub3B0aW9uYWxQYXJhbXM6IGFueVtdKTogdm9pZDtcclxufVxyXG5cclxuLyoqXHJcbiAqIERlZmluZXMgYSBzaW1wbGUgc3RvcmFnZSB0aGF0IGNhbiBiZSB1c2VkIGZvclxyXG4gKiBzdG9yaW5nIHRoZSB0b2tlbnMgYXQgY2xpZW50IHNpZGUuXHJcbiAqIElzIGNvbXBhdGlibGUgdG8gbG9jYWxTdG9yYWdlIGFuZCBzZXNzaW9uU3RvcmFnZSxcclxuICogYnV0IHlvdSBjYW4gYWxzbyBjcmVhdGUgeW91ciBvd24gaW1wbGVtZW50YXRpb25zLlxyXG4gKi9cclxuZXhwb3J0IGFic3RyYWN0IGNsYXNzIE9BdXRoU3RvcmFnZSB7XHJcbiAgYWJzdHJhY3QgZ2V0SXRlbShrZXk6IHN0cmluZyk6IHN0cmluZyB8IG51bGw7XHJcbiAgYWJzdHJhY3QgcmVtb3ZlSXRlbShrZXk6IHN0cmluZyk6IHZvaWQ7XHJcbiAgYWJzdHJhY3Qgc2V0SXRlbShrZXk6IHN0cmluZywgZGF0YTogc3RyaW5nKTogdm9pZDtcclxufVxyXG5cclxuQEluamVjdGFibGUoKVxyXG5leHBvcnQgY2xhc3MgTWVtb3J5U3RvcmFnZSBpbXBsZW1lbnRzIE9BdXRoU3RvcmFnZSB7XHJcbiAgcHJpdmF0ZSBkYXRhID0gbmV3IE1hcDxzdHJpbmcsIHN0cmluZz4oKTtcclxuXHJcbiAgZ2V0SXRlbShrZXk6IHN0cmluZyk6IHN0cmluZyB7XHJcbiAgICByZXR1cm4gdGhpcy5kYXRhLmdldChrZXkpO1xyXG4gIH1cclxuXHJcbiAgcmVtb3ZlSXRlbShrZXk6IHN0cmluZyk6IHZvaWQge1xyXG4gICAgdGhpcy5kYXRhLmRlbGV0ZShrZXkpO1xyXG4gIH1cclxuXHJcbiAgc2V0SXRlbShrZXk6IHN0cmluZywgZGF0YTogc3RyaW5nKTogdm9pZCB7XHJcbiAgICB0aGlzLmRhdGEuc2V0KGtleSwgZGF0YSk7XHJcbiAgfVxyXG59XHJcblxyXG4vKipcclxuICogUmVwcmVzZW50cyB0aGUgcmVjZWl2ZWQgdG9rZW5zLCB0aGUgcmVjZWl2ZWQgc3RhdGVcclxuICogYW5kIHRoZSBwYXJzZWQgY2xhaW1zIGZyb20gdGhlIGlkLXRva2VuLlxyXG4gKi9cclxuZXhwb3J0IGNsYXNzIFJlY2VpdmVkVG9rZW5zIHtcclxuICBpZFRva2VuOiBzdHJpbmc7XHJcbiAgYWNjZXNzVG9rZW46IHN0cmluZztcclxuICBpZENsYWltcz86IG9iamVjdDtcclxuICBzdGF0ZT86IHN0cmluZztcclxufVxyXG5cclxuLyoqXHJcbiAqIFJlcHJlc2VudHMgdGhlIHBhcnNlZCBhbmQgdmFsaWRhdGVkIGlkX3Rva2VuLlxyXG4gKi9cclxuZXhwb3J0IGludGVyZmFjZSBQYXJzZWRJZFRva2VuIHtcclxuICBpZFRva2VuOiBzdHJpbmc7XHJcbiAgaWRUb2tlbkNsYWltczogb2JqZWN0O1xyXG4gIGlkVG9rZW5IZWFkZXI6IG9iamVjdDtcclxuICBpZFRva2VuQ2xhaW1zSnNvbjogc3RyaW5nO1xyXG4gIGlkVG9rZW5IZWFkZXJKc29uOiBzdHJpbmc7XHJcbiAgaWRUb2tlbkV4cGlyZXNBdDogbnVtYmVyO1xyXG59XHJcblxyXG4vKipcclxuICogUmVwcmVzZW50cyB0aGUgcmVzcG9uc2UgZnJvbSB0aGUgdG9rZW4gZW5kcG9pbnRcclxuICogaHR0cDovL29wZW5pZC5uZXQvc3BlY3Mvb3BlbmlkLWNvbm5lY3QtY29yZS0xXzAuaHRtbCNUb2tlbkVuZHBvaW50XHJcbiAqL1xyXG5leHBvcnQgaW50ZXJmYWNlIFRva2VuUmVzcG9uc2Uge1xyXG4gIGFjY2Vzc190b2tlbjogc3RyaW5nO1xyXG4gIGlkX3Rva2VuOiBzdHJpbmc7XHJcbiAgdG9rZW5fdHlwZTogc3RyaW5nO1xyXG4gIGV4cGlyZXNfaW46IG51bWJlcjtcclxuICByZWZyZXNoX3Rva2VuOiBzdHJpbmc7XHJcbiAgc2NvcGU6IHN0cmluZztcclxuICBzdGF0ZT86IHN0cmluZztcclxufVxyXG5cclxuLyoqXHJcbiAqIFJlcHJlc2VudHMgdGhlIHJlc3BvbnNlIGZyb20gdGhlIHVzZXIgaW5mbyBlbmRwb2ludFxyXG4gKiBodHRwOi8vb3BlbmlkLm5ldC9zcGVjcy9vcGVuaWQtY29ubmVjdC1jb3JlLTFfMC5odG1sI1VzZXJJbmZvXHJcbiAqL1xyXG5leHBvcnQgaW50ZXJmYWNlIFVzZXJJbmZvIHtcclxuICBzdWI6IHN0cmluZztcclxuICBba2V5OiBzdHJpbmddOiBhbnk7XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBSZXByZXNlbnRzIGFuIE9wZW5JRCBDb25uZWN0IGRpc2NvdmVyeSBkb2N1bWVudFxyXG4gKi9cclxuZXhwb3J0IGludGVyZmFjZSBPaWRjRGlzY292ZXJ5RG9jIHtcclxuICBpc3N1ZXI6IHN0cmluZztcclxuICBhdXRob3JpemF0aW9uX2VuZHBvaW50OiBzdHJpbmc7XHJcbiAgdG9rZW5fZW5kcG9pbnQ6IHN0cmluZztcclxuICB0b2tlbl9lbmRwb2ludF9hdXRoX21ldGhvZHNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcclxuICB0b2tlbl9lbmRwb2ludF9hdXRoX3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQ6IHN0cmluZ1tdO1xyXG4gIHVzZXJpbmZvX2VuZHBvaW50OiBzdHJpbmc7XHJcbiAgY2hlY2tfc2Vzc2lvbl9pZnJhbWU6IHN0cmluZztcclxuICBlbmRfc2Vzc2lvbl9lbmRwb2ludDogc3RyaW5nO1xyXG4gIGp3a3NfdXJpOiBzdHJpbmc7XHJcbiAgcmVnaXN0cmF0aW9uX2VuZHBvaW50OiBzdHJpbmc7XHJcbiAgc2NvcGVzX3N1cHBvcnRlZDogc3RyaW5nW107XHJcbiAgcmVzcG9uc2VfdHlwZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcclxuICBhY3JfdmFsdWVzX3N1cHBvcnRlZDogc3RyaW5nW107XHJcbiAgcmVzcG9uc2VfbW9kZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcclxuICBncmFudF90eXBlc19zdXBwb3J0ZWQ6IHN0cmluZ1tdO1xyXG4gIHN1YmplY3RfdHlwZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcclxuICB1c2VyaW5mb19zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcclxuICB1c2VyaW5mb19lbmNyeXB0aW9uX2FsZ192YWx1ZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcclxuICB1c2VyaW5mb19lbmNyeXB0aW9uX2VuY192YWx1ZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcclxuICBpZF90b2tlbl9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcclxuICBpZF90b2tlbl9lbmNyeXB0aW9uX2FsZ192YWx1ZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcclxuICBpZF90b2tlbl9lbmNyeXB0aW9uX2VuY192YWx1ZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcclxuICByZXF1ZXN0X29iamVjdF9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcclxuICBkaXNwbGF5X3ZhbHVlc19zdXBwb3J0ZWQ6IHN0cmluZ1tdO1xyXG4gIGNsYWltX3R5cGVzX3N1cHBvcnRlZDogc3RyaW5nW107XHJcbiAgY2xhaW1zX3N1cHBvcnRlZDogc3RyaW5nW107XHJcbiAgY2xhaW1zX3BhcmFtZXRlcl9zdXBwb3J0ZWQ6IGJvb2xlYW47XHJcbiAgc2VydmljZV9kb2N1bWVudGF0aW9uOiBzdHJpbmc7XHJcbiAgdWlfbG9jYWxlc19zdXBwb3J0ZWQ6IHN0cmluZ1tdO1xyXG4gIHJldm9jYXRpb25fZW5kcG9pbnQ6IHN0cmluZztcclxufVxyXG4iXX0=