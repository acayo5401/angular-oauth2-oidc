import { __extends } from "tslib";
var OAuthEvent = /** @class */ (function () {
    function OAuthEvent(type) {
        this.type = type;
    }
    return OAuthEvent;
}());
export { OAuthEvent };
var OAuthSuccessEvent = /** @class */ (function (_super) {
    __extends(OAuthSuccessEvent, _super);
    function OAuthSuccessEvent(type, info) {
        if (info === void 0) { info = null; }
        var _this = _super.call(this, type) || this;
        _this.info = info;
        return _this;
    }
    return OAuthSuccessEvent;
}(OAuthEvent));
export { OAuthSuccessEvent };
var OAuthInfoEvent = /** @class */ (function (_super) {
    __extends(OAuthInfoEvent, _super);
    function OAuthInfoEvent(type, info) {
        if (info === void 0) { info = null; }
        var _this = _super.call(this, type) || this;
        _this.info = info;
        return _this;
    }
    return OAuthInfoEvent;
}(OAuthEvent));
export { OAuthInfoEvent };
var OAuthErrorEvent = /** @class */ (function (_super) {
    __extends(OAuthErrorEvent, _super);
    function OAuthErrorEvent(type, reason, params) {
        if (params === void 0) { params = null; }
        var _this = _super.call(this, type) || this;
        _this.reason = reason;
        _this.params = params;
        return _this;
    }
    return OAuthErrorEvent;
}(OAuthEvent));
export { OAuthErrorEvent };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZXZlbnRzLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1vYXV0aDItb2lkYy8iLCJzb3VyY2VzIjpbImV2ZW50cy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiO0FBMEJBO0lBQ0Usb0JBQXFCLElBQWU7UUFBZixTQUFJLEdBQUosSUFBSSxDQUFXO0lBQUcsQ0FBQztJQUMxQyxpQkFBQztBQUFELENBQUMsQUFGRCxJQUVDOztBQUVEO0lBQXVDLHFDQUFVO0lBQy9DLDJCQUFZLElBQWUsRUFBVyxJQUFnQjtRQUFoQixxQkFBQSxFQUFBLFdBQWdCO1FBQXRELFlBQ0Usa0JBQU0sSUFBSSxDQUFDLFNBQ1o7UUFGcUMsVUFBSSxHQUFKLElBQUksQ0FBWTs7SUFFdEQsQ0FBQztJQUNILHdCQUFDO0FBQUQsQ0FBQyxBQUpELENBQXVDLFVBQVUsR0FJaEQ7O0FBRUQ7SUFBb0Msa0NBQVU7SUFDNUMsd0JBQVksSUFBZSxFQUFXLElBQWdCO1FBQWhCLHFCQUFBLEVBQUEsV0FBZ0I7UUFBdEQsWUFDRSxrQkFBTSxJQUFJLENBQUMsU0FDWjtRQUZxQyxVQUFJLEdBQUosSUFBSSxDQUFZOztJQUV0RCxDQUFDO0lBQ0gscUJBQUM7QUFBRCxDQUFDLEFBSkQsQ0FBb0MsVUFBVSxHQUk3Qzs7QUFFRDtJQUFxQyxtQ0FBVTtJQUM3Qyx5QkFDRSxJQUFlLEVBQ04sTUFBYyxFQUNkLE1BQXFCO1FBQXJCLHVCQUFBLEVBQUEsYUFBcUI7UUFIaEMsWUFLRSxrQkFBTSxJQUFJLENBQUMsU0FDWjtRQUpVLFlBQU0sR0FBTixNQUFNLENBQVE7UUFDZCxZQUFNLEdBQU4sTUFBTSxDQUFlOztJQUdoQyxDQUFDO0lBQ0gsc0JBQUM7QUFBRCxDQUFDLEFBUkQsQ0FBcUMsVUFBVSxHQVE5QyIsInNvdXJjZXNDb250ZW50IjpbImV4cG9ydCB0eXBlIEV2ZW50VHlwZSA9XHJcbiAgfCAnZGlzY292ZXJ5X2RvY3VtZW50X2xvYWRlZCdcclxuICB8ICdqd2tzX2xvYWRfZXJyb3InXHJcbiAgfCAnaW52YWxpZF9ub25jZV9pbl9zdGF0ZSdcclxuICB8ICdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZF9lcnJvcidcclxuICB8ICdkaXNjb3ZlcnlfZG9jdW1lbnRfdmFsaWRhdGlvbl9lcnJvcidcclxuICB8ICd1c2VyX3Byb2ZpbGVfbG9hZGVkJ1xyXG4gIHwgJ3VzZXJfcHJvZmlsZV9sb2FkX2Vycm9yJ1xyXG4gIHwgJ3Rva2VuX3JlY2VpdmVkJ1xyXG4gIHwgJ3Rva2VuX2Vycm9yJ1xyXG4gIHwgJ2NvZGVfZXJyb3InXHJcbiAgfCAndG9rZW5fcmVmcmVzaGVkJ1xyXG4gIHwgJ3Rva2VuX3JlZnJlc2hfZXJyb3InXHJcbiAgfCAnc2lsZW50X3JlZnJlc2hfZXJyb3InXHJcbiAgfCAnc2lsZW50bHlfcmVmcmVzaGVkJ1xyXG4gIHwgJ3NpbGVudF9yZWZyZXNoX3RpbWVvdXQnXHJcbiAgfCAndG9rZW5fdmFsaWRhdGlvbl9lcnJvcidcclxuICB8ICd0b2tlbl9leHBpcmVzJ1xyXG4gIHwgJ3Nlc3Npb25fY2hhbmdlZCdcclxuICB8ICdzZXNzaW9uX2Vycm9yJ1xyXG4gIHwgJ3Nlc3Npb25fdGVybWluYXRlZCdcclxuICB8ICdsb2dvdXQnXHJcbiAgfCAncG9wdXBfY2xvc2VkJ1xyXG4gIHwgJ3BvcHVwX2Jsb2NrZWQnXHJcbiAgfCAndG9rZW5fcmV2b2tlX2Vycm9yJztcclxuXHJcbmV4cG9ydCBhYnN0cmFjdCBjbGFzcyBPQXV0aEV2ZW50IHtcclxuICBjb25zdHJ1Y3RvcihyZWFkb25seSB0eXBlOiBFdmVudFR5cGUpIHt9XHJcbn1cclxuXHJcbmV4cG9ydCBjbGFzcyBPQXV0aFN1Y2Nlc3NFdmVudCBleHRlbmRzIE9BdXRoRXZlbnQge1xyXG4gIGNvbnN0cnVjdG9yKHR5cGU6IEV2ZW50VHlwZSwgcmVhZG9ubHkgaW5mbzogYW55ID0gbnVsbCkge1xyXG4gICAgc3VwZXIodHlwZSk7XHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgY2xhc3MgT0F1dGhJbmZvRXZlbnQgZXh0ZW5kcyBPQXV0aEV2ZW50IHtcclxuICBjb25zdHJ1Y3Rvcih0eXBlOiBFdmVudFR5cGUsIHJlYWRvbmx5IGluZm86IGFueSA9IG51bGwpIHtcclxuICAgIHN1cGVyKHR5cGUpO1xyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGNsYXNzIE9BdXRoRXJyb3JFdmVudCBleHRlbmRzIE9BdXRoRXZlbnQge1xyXG4gIGNvbnN0cnVjdG9yKFxyXG4gICAgdHlwZTogRXZlbnRUeXBlLFxyXG4gICAgcmVhZG9ubHkgcmVhc29uOiBvYmplY3QsXHJcbiAgICByZWFkb25seSBwYXJhbXM6IG9iamVjdCA9IG51bGxcclxuICApIHtcclxuICAgIHN1cGVyKHR5cGUpO1xyXG4gIH1cclxufVxyXG4iXX0=