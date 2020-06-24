import { __awaiter, __decorate, __generator, __values } from "tslib";
import { Injectable } from '@angular/core';
import { sha256 } from 'js-sha256';
/**
 * Abstraction for crypto algorithms
 */
var HashHandler = /** @class */ (function () {
    function HashHandler() {
    }
    return HashHandler;
}());
export { HashHandler };
var DefaultHashHandler = /** @class */ (function () {
    function DefaultHashHandler() {
    }
    DefaultHashHandler.prototype.calcHash = function (valueToHash, algorithm) {
        return __awaiter(this, void 0, void 0, function () {
            var hashArray, hashString;
            return __generator(this, function (_a) {
                hashArray = sha256.array(valueToHash);
                hashString = this.toHashString2(hashArray);
                return [2 /*return*/, hashString];
            });
        });
    };
    DefaultHashHandler.prototype.toHashString2 = function (byteArray) {
        var e_1, _a;
        var result = '';
        try {
            for (var byteArray_1 = __values(byteArray), byteArray_1_1 = byteArray_1.next(); !byteArray_1_1.done; byteArray_1_1 = byteArray_1.next()) {
                var e = byteArray_1_1.value;
                result += String.fromCharCode(e);
            }
        }
        catch (e_1_1) { e_1 = { error: e_1_1 }; }
        finally {
            try {
                if (byteArray_1_1 && !byteArray_1_1.done && (_a = byteArray_1.return)) _a.call(byteArray_1);
            }
            finally { if (e_1) throw e_1.error; }
        }
        return result;
    };
    DefaultHashHandler.prototype.toHashString = function (buffer) {
        var e_2, _a;
        var byteArray = new Uint8Array(buffer);
        var result = '';
        try {
            for (var byteArray_2 = __values(byteArray), byteArray_2_1 = byteArray_2.next(); !byteArray_2_1.done; byteArray_2_1 = byteArray_2.next()) {
                var e = byteArray_2_1.value;
                result += String.fromCharCode(e);
            }
        }
        catch (e_2_1) { e_2 = { error: e_2_1 }; }
        finally {
            try {
                if (byteArray_2_1 && !byteArray_2_1.done && (_a = byteArray_2.return)) _a.call(byteArray_2);
            }
            finally { if (e_2) throw e_2.error; }
        }
        return result;
    };
    DefaultHashHandler = __decorate([
        Injectable()
    ], DefaultHashHandler);
    return DefaultHashHandler;
}());
export { DefaultHashHandler };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaGFzaC1oYW5kbGVyLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1vYXV0aDItb2lkYy8iLCJzb3VyY2VzIjpbInRva2VuLXZhbGlkYXRpb24vaGFzaC1oYW5kbGVyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQSxPQUFPLEVBQUUsVUFBVSxFQUFFLE1BQU0sZUFBZSxDQUFDO0FBRTNDLE9BQU8sRUFBRSxNQUFNLEVBQUUsTUFBTSxXQUFXLENBQUM7QUFFbkM7O0dBRUc7QUFDSDtJQUFBO0lBRUEsQ0FBQztJQUFELGtCQUFDO0FBQUQsQ0FBQyxBQUZELElBRUM7O0FBR0Q7SUFBQTtJQWtEQSxDQUFDO0lBakRPLHFDQUFRLEdBQWQsVUFBZSxXQUFtQixFQUFFLFNBQWlCOzs7O2dCQUs3QyxTQUFTLEdBQUcsTUFBTSxDQUFDLEtBQUssQ0FBQyxXQUFXLENBQUMsQ0FBQztnQkFFdEMsVUFBVSxHQUFHLElBQUksQ0FBQyxhQUFhLENBQUMsU0FBUyxDQUFDLENBQUM7Z0JBRWpELHNCQUFPLFVBQVUsRUFBQzs7O0tBQ25CO0lBRUQsMENBQWEsR0FBYixVQUFjLFNBQW1COztRQUMvQixJQUFJLE1BQU0sR0FBRyxFQUFFLENBQUM7O1lBQ2hCLEtBQWMsSUFBQSxjQUFBLFNBQUEsU0FBUyxDQUFBLG9DQUFBLDJEQUFFO2dCQUFwQixJQUFJLENBQUMsc0JBQUE7Z0JBQ1IsTUFBTSxJQUFJLE1BQU0sQ0FBQyxZQUFZLENBQUMsQ0FBQyxDQUFDLENBQUM7YUFDbEM7Ozs7Ozs7OztRQUNELE9BQU8sTUFBTSxDQUFDO0lBQ2hCLENBQUM7SUFFRCx5Q0FBWSxHQUFaLFVBQWEsTUFBbUI7O1FBQzlCLElBQU0sU0FBUyxHQUFHLElBQUksVUFBVSxDQUFDLE1BQU0sQ0FBQyxDQUFDO1FBQ3pDLElBQUksTUFBTSxHQUFHLEVBQUUsQ0FBQzs7WUFDaEIsS0FBYyxJQUFBLGNBQUEsU0FBQSxTQUFTLENBQUEsb0NBQUEsMkRBQUU7Z0JBQXBCLElBQUksQ0FBQyxzQkFBQTtnQkFDUixNQUFNLElBQUksTUFBTSxDQUFDLFlBQVksQ0FBQyxDQUFDLENBQUMsQ0FBQzthQUNsQzs7Ozs7Ozs7O1FBQ0QsT0FBTyxNQUFNLENBQUM7SUFDaEIsQ0FBQztJQTVCVSxrQkFBa0I7UUFEOUIsVUFBVSxFQUFFO09BQ0Esa0JBQWtCLENBa0Q5QjtJQUFELHlCQUFDO0NBQUEsQUFsREQsSUFrREM7U0FsRFksa0JBQWtCIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xyXG5cclxuaW1wb3J0IHsgc2hhMjU2IH0gZnJvbSAnanMtc2hhMjU2JztcclxuXHJcbi8qKlxyXG4gKiBBYnN0cmFjdGlvbiBmb3IgY3J5cHRvIGFsZ29yaXRobXNcclxuICovXHJcbmV4cG9ydCBhYnN0cmFjdCBjbGFzcyBIYXNoSGFuZGxlciB7XHJcbiAgYWJzdHJhY3QgY2FsY0hhc2godmFsdWVUb0hhc2g6IHN0cmluZywgYWxnb3JpdGhtOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz47XHJcbn1cclxuXHJcbkBJbmplY3RhYmxlKClcclxuZXhwb3J0IGNsYXNzIERlZmF1bHRIYXNoSGFuZGxlciBpbXBsZW1lbnRzIEhhc2hIYW5kbGVyIHtcclxuICBhc3luYyBjYWxjSGFzaCh2YWx1ZVRvSGFzaDogc3RyaW5nLCBhbGdvcml0aG06IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPiB7XHJcbiAgICAvLyBjb25zdCBlbmNvZGVyID0gbmV3IFRleHRFbmNvZGVyKCk7XHJcbiAgICAvLyBjb25zdCBoYXNoQXJyYXkgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5kaWdlc3QoYWxnb3JpdGhtLCBkYXRhKTtcclxuICAgIC8vIGNvbnN0IGRhdGEgPSBlbmNvZGVyLmVuY29kZSh2YWx1ZVRvSGFzaCk7XHJcblxyXG4gICAgY29uc3QgaGFzaEFycmF5ID0gc2hhMjU2LmFycmF5KHZhbHVlVG9IYXNoKTtcclxuICAgIC8vIGNvbnN0IGhhc2hTdHJpbmcgPSB0aGlzLnRvSGFzaFN0cmluZyhoYXNoQXJyYXkpO1xyXG4gICAgY29uc3QgaGFzaFN0cmluZyA9IHRoaXMudG9IYXNoU3RyaW5nMihoYXNoQXJyYXkpO1xyXG5cclxuICAgIHJldHVybiBoYXNoU3RyaW5nO1xyXG4gIH1cclxuXHJcbiAgdG9IYXNoU3RyaW5nMihieXRlQXJyYXk6IG51bWJlcltdKSB7XHJcbiAgICBsZXQgcmVzdWx0ID0gJyc7XHJcbiAgICBmb3IgKGxldCBlIG9mIGJ5dGVBcnJheSkge1xyXG4gICAgICByZXN1bHQgKz0gU3RyaW5nLmZyb21DaGFyQ29kZShlKTtcclxuICAgIH1cclxuICAgIHJldHVybiByZXN1bHQ7XHJcbiAgfVxyXG5cclxuICB0b0hhc2hTdHJpbmcoYnVmZmVyOiBBcnJheUJ1ZmZlcikge1xyXG4gICAgY29uc3QgYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoYnVmZmVyKTtcclxuICAgIGxldCByZXN1bHQgPSAnJztcclxuICAgIGZvciAobGV0IGUgb2YgYnl0ZUFycmF5KSB7XHJcbiAgICAgIHJlc3VsdCArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKGUpO1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIHJlc3VsdDtcclxuICB9XHJcblxyXG4gIC8vIGhleFN0cmluZyhidWZmZXIpIHtcclxuICAvLyAgICAgY29uc3QgYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoYnVmZmVyKTtcclxuICAvLyAgICAgY29uc3QgaGV4Q29kZXMgPSBbLi4uYnl0ZUFycmF5XS5tYXAodmFsdWUgPT4ge1xyXG4gIC8vICAgICAgIGNvbnN0IGhleENvZGUgPSB2YWx1ZS50b1N0cmluZygxNik7XHJcbiAgLy8gICAgICAgY29uc3QgcGFkZGVkSGV4Q29kZSA9IGhleENvZGUucGFkU3RhcnQoMiwgJzAnKTtcclxuICAvLyAgICAgICByZXR1cm4gcGFkZGVkSGV4Q29kZTtcclxuICAvLyAgICAgfSk7XHJcblxyXG4gIC8vICAgICByZXR1cm4gaGV4Q29kZXMuam9pbignJyk7XHJcbiAgLy8gICB9XHJcblxyXG4gIC8vIHRvSGFzaFN0cmluZyhoZXhTdHJpbmc6IHN0cmluZykge1xyXG4gIC8vICAgbGV0IHJlc3VsdCA9ICcnO1xyXG4gIC8vICAgZm9yIChsZXQgaSA9IDA7IGkgPCBoZXhTdHJpbmcubGVuZ3RoOyBpICs9IDIpIHtcclxuICAvLyAgICAgbGV0IGhleERpZ2l0ID0gaGV4U3RyaW5nLmNoYXJBdChpKSArIGhleFN0cmluZy5jaGFyQXQoaSArIDEpO1xyXG4gIC8vICAgICBsZXQgbnVtID0gcGFyc2VJbnQoaGV4RGlnaXQsIDE2KTtcclxuICAvLyAgICAgcmVzdWx0ICs9IFN0cmluZy5mcm9tQ2hhckNvZGUobnVtKTtcclxuICAvLyAgIH1cclxuICAvLyAgIHJldHVybiByZXN1bHQ7XHJcbiAgLy8gfVxyXG59XHJcbiJdfQ==