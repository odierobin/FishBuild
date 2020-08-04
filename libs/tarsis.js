var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
        return extendStatics(d, b);
    }
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var tarsis;
(function (tarsis) {
    var encrypt;
    (function (encrypt) {
        var Md5 = /** @class */ (function () {
            function Md5() {
            }
            /**
             * Add integers, wrapping at 2^32.
             * This uses 16-bit operations internally to work around bugs in interpreters.
             *
             * @param {number} x First integer
             * @param {number} y Second integer
             * @returns {number} Sum
             */
            Md5.safeAdd = function (x, y) {
                var lsw = (x & 0xffff) + (y & 0xffff);
                var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
                return (msw << 16) | (lsw & 0xffff);
            };
            /**
             * Bitwise rotate a 32-bit number to the left.
             *
             * @param {number} num 32-bit number
             * @param {number} cnt Rotation count
             * @returns {number} Rotated number
             */
            Md5.bitRotateLeft = function (num, cnt) {
                return (num << cnt) | (num >>> (32 - cnt));
            };
            /**
             * Basic operation the algorithm uses.
             *
             * @param {number} q q
             * @param {number} a a
             * @param {number} b b
             * @param {number} x x
             * @param {number} s s
             * @param {number} t t
             * @returns {number} Result
             */
            Md5.md5cmn = function (q, a, b, x, s, t) {
                return Md5.safeAdd(Md5.bitRotateLeft(Md5.safeAdd(Md5.safeAdd(a, q), Md5.safeAdd(x, t)), s), b);
            };
            /**
             * Basic operation the algorithm uses.
             *
             * @param {number} a a
             * @param {number} b b
             * @param {number} c c
             * @param {number} d d
             * @param {number} x x
             * @param {number} s s
             * @param {number} t t
             * @returns {number} Result
             */
            Md5.md5ff = function (a, b, c, d, x, s, t) {
                return Md5.md5cmn((b & c) | (~b & d), a, b, x, s, t);
            };
            /**
             * Basic operation the algorithm uses.
             *
             * @param {number} a a
             * @param {number} b b
             * @param {number} c c
             * @param {number} d d
             * @param {number} x x
             * @param {number} s s
             * @param {number} t t
             * @returns {number} Result
             */
            Md5.md5gg = function (a, b, c, d, x, s, t) {
                return Md5.md5cmn((b & d) | (c & ~d), a, b, x, s, t);
            };
            /**
             * Basic operation the algorithm uses.
             *
             * @param {number} a a
             * @param {number} b b
             * @param {number} c c
             * @param {number} d d
             * @param {number} x x
             * @param {number} s s
             * @param {number} t t
             * @returns {number} Result
             */
            Md5.md5hh = function (a, b, c, d, x, s, t) {
                return Md5.md5cmn(b ^ c ^ d, a, b, x, s, t);
            };
            /**
             * Basic operation the algorithm uses.
             *
             * @param {number} a a
             * @param {number} b b
             * @param {number} c c
             * @param {number} d d
             * @param {number} x x
             * @param {number} s s
             * @param {number} t t
             * @returns {number} Result
             */
            Md5.md5ii = function (a, b, c, d, x, s, t) {
                return Md5.md5cmn(c ^ (b | ~d), a, b, x, s, t);
            };
            /**
             * Calculate the MD5 of an array of little-endian words, and a bit length.
             *
             * @param {Array} x Array of little-endian words
             * @param {number} len Bit length
             * @returns {Array<number>} MD5 Array
             */
            Md5.binlMD5 = function (x, len) {
                /* append padding */
                x[len >> 5] |= 0x80 << len % 32;
                x[(((len + 64) >>> 9) << 4) + 14] = len;
                var i;
                var olda;
                var oldb;
                var oldc;
                var oldd;
                var a = 1732584193;
                var b = -271733879;
                var c = -1732584194;
                var d = 271733878;
                for (i = 0; i < x.length; i += 16) {
                    olda = a;
                    oldb = b;
                    oldc = c;
                    oldd = d;
                    a = Md5.md5ff(a, b, c, d, x[i], 7, -680876936);
                    d = Md5.md5ff(d, a, b, c, x[i + 1], 12, -389564586);
                    c = Md5.md5ff(c, d, a, b, x[i + 2], 17, 606105819);
                    b = Md5.md5ff(b, c, d, a, x[i + 3], 22, -1044525330);
                    a = Md5.md5ff(a, b, c, d, x[i + 4], 7, -176418897);
                    d = Md5.md5ff(d, a, b, c, x[i + 5], 12, 1200080426);
                    c = Md5.md5ff(c, d, a, b, x[i + 6], 17, -1473231341);
                    b = Md5.md5ff(b, c, d, a, x[i + 7], 22, -45705983);
                    a = Md5.md5ff(a, b, c, d, x[i + 8], 7, 1770035416);
                    d = Md5.md5ff(d, a, b, c, x[i + 9], 12, -1958414417);
                    c = Md5.md5ff(c, d, a, b, x[i + 10], 17, -42063);
                    b = Md5.md5ff(b, c, d, a, x[i + 11], 22, -1990404162);
                    a = Md5.md5ff(a, b, c, d, x[i + 12], 7, 1804603682);
                    d = Md5.md5ff(d, a, b, c, x[i + 13], 12, -40341101);
                    c = Md5.md5ff(c, d, a, b, x[i + 14], 17, -1502002290);
                    b = Md5.md5ff(b, c, d, a, x[i + 15], 22, 1236535329);
                    a = Md5.md5gg(a, b, c, d, x[i + 1], 5, -165796510);
                    d = Md5.md5gg(d, a, b, c, x[i + 6], 9, -1069501632);
                    c = Md5.md5gg(c, d, a, b, x[i + 11], 14, 643717713);
                    b = Md5.md5gg(b, c, d, a, x[i], 20, -373897302);
                    a = Md5.md5gg(a, b, c, d, x[i + 5], 5, -701558691);
                    d = Md5.md5gg(d, a, b, c, x[i + 10], 9, 38016083);
                    c = Md5.md5gg(c, d, a, b, x[i + 15], 14, -660478335);
                    b = Md5.md5gg(b, c, d, a, x[i + 4], 20, -405537848);
                    a = Md5.md5gg(a, b, c, d, x[i + 9], 5, 568446438);
                    d = Md5.md5gg(d, a, b, c, x[i + 14], 9, -1019803690);
                    c = Md5.md5gg(c, d, a, b, x[i + 3], 14, -187363961);
                    b = Md5.md5gg(b, c, d, a, x[i + 8], 20, 1163531501);
                    a = Md5.md5gg(a, b, c, d, x[i + 13], 5, -1444681467);
                    d = Md5.md5gg(d, a, b, c, x[i + 2], 9, -51403784);
                    c = Md5.md5gg(c, d, a, b, x[i + 7], 14, 1735328473);
                    b = Md5.md5gg(b, c, d, a, x[i + 12], 20, -1926607734);
                    a = Md5.md5hh(a, b, c, d, x[i + 5], 4, -378558);
                    d = Md5.md5hh(d, a, b, c, x[i + 8], 11, -2022574463);
                    c = Md5.md5hh(c, d, a, b, x[i + 11], 16, 1839030562);
                    b = Md5.md5hh(b, c, d, a, x[i + 14], 23, -35309556);
                    a = Md5.md5hh(a, b, c, d, x[i + 1], 4, -1530992060);
                    d = Md5.md5hh(d, a, b, c, x[i + 4], 11, 1272893353);
                    c = Md5.md5hh(c, d, a, b, x[i + 7], 16, -155497632);
                    b = Md5.md5hh(b, c, d, a, x[i + 10], 23, -1094730640);
                    a = Md5.md5hh(a, b, c, d, x[i + 13], 4, 681279174);
                    d = Md5.md5hh(d, a, b, c, x[i], 11, -358537222);
                    c = Md5.md5hh(c, d, a, b, x[i + 3], 16, -722521979);
                    b = Md5.md5hh(b, c, d, a, x[i + 6], 23, 76029189);
                    a = Md5.md5hh(a, b, c, d, x[i + 9], 4, -640364487);
                    d = Md5.md5hh(d, a, b, c, x[i + 12], 11, -421815835);
                    c = Md5.md5hh(c, d, a, b, x[i + 15], 16, 530742520);
                    b = Md5.md5hh(b, c, d, a, x[i + 2], 23, -995338651);
                    a = Md5.md5ii(a, b, c, d, x[i], 6, -198630844);
                    d = Md5.md5ii(d, a, b, c, x[i + 7], 10, 1126891415);
                    c = Md5.md5ii(c, d, a, b, x[i + 14], 15, -1416354905);
                    b = Md5.md5ii(b, c, d, a, x[i + 5], 21, -57434055);
                    a = Md5.md5ii(a, b, c, d, x[i + 12], 6, 1700485571);
                    d = Md5.md5ii(d, a, b, c, x[i + 3], 10, -1894986606);
                    c = Md5.md5ii(c, d, a, b, x[i + 10], 15, -1051523);
                    b = Md5.md5ii(b, c, d, a, x[i + 1], 21, -2054922799);
                    a = Md5.md5ii(a, b, c, d, x[i + 8], 6, 1873313359);
                    d = Md5.md5ii(d, a, b, c, x[i + 15], 10, -30611744);
                    c = Md5.md5ii(c, d, a, b, x[i + 6], 15, -1560198380);
                    b = Md5.md5ii(b, c, d, a, x[i + 13], 21, 1309151649);
                    a = Md5.md5ii(a, b, c, d, x[i + 4], 6, -145523070);
                    d = Md5.md5ii(d, a, b, c, x[i + 11], 10, -1120210379);
                    c = Md5.md5ii(c, d, a, b, x[i + 2], 15, 718787259);
                    b = Md5.md5ii(b, c, d, a, x[i + 9], 21, -343485551);
                    a = Md5.safeAdd(a, olda);
                    b = Md5.safeAdd(b, oldb);
                    c = Md5.safeAdd(c, oldc);
                    d = Md5.safeAdd(d, oldd);
                }
                return [a, b, c, d];
            };
            /**
             * Convert an array of little-endian words to a string
             *
             * @param {Array<number>} input MD5 Array
             * @returns {string} MD5 string
             */
            Md5.binl2rstr = function (input) {
                var i;
                var output = '';
                var length32 = input.length * 32;
                for (i = 0; i < length32; i += 8) {
                    output += String.fromCharCode((input[i >> 5] >>> i % 32) & 0xff);
                }
                return output;
            };
            /**
             * Convert a raw string to an array of little-endian words
             * Characters >255 have their high-byte silently ignored.
             *
             * @param {string} input Raw input string
             * @returns {Array<number>} Array of little-endian words
             */
            Md5.rstr2binl = function (input) {
                var i;
                var output = [];
                output[(input.length >> 2) - 1] = undefined;
                for (i = 0; i < output.length; i += 1) {
                    output[i] = 0;
                }
                var length8 = input.length * 8;
                for (i = 0; i < length8; i += 8) {
                    output[i >> 5] |= (input.charCodeAt(i / 8) & 0xff) << i % 32;
                }
                return output;
            };
            /**
             * Calculate the MD5 of a raw string
             *
             * @param {string} s Input string
             * @returns {string} Raw MD5 string
             */
            Md5.rstrMD5 = function (s) {
                return Md5.binl2rstr(Md5.binlMD5(Md5.rstr2binl(s), s.length * 8));
            };
            /**
             * Calculates the HMAC-MD5 of a key and some data (raw strings)
             *
             * @param {string} key HMAC key
             * @param {string} data Raw input string
             * @returns {string} Raw MD5 string
             */
            Md5.rstrHMACMD5 = function (key, data) {
                var i;
                var bkey = Md5.rstr2binl(key);
                var ipad = [];
                var opad = [];
                var hash;
                ipad[15] = opad[15] = undefined;
                if (bkey.length > 16) {
                    bkey = Md5.binlMD5(bkey, key.length * 8);
                }
                for (i = 0; i < 16; i += 1) {
                    ipad[i] = bkey[i] ^ 0x36363636;
                    opad[i] = bkey[i] ^ 0x5c5c5c5c;
                }
                hash = Md5.binlMD5(ipad.concat(Md5.rstr2binl(data)), 512 + data.length * 8);
                return Md5.binl2rstr(Md5.binlMD5(opad.concat(hash), 512 + 128));
            };
            /**
             * Convert a raw string to a hex string
             *
             * @param {string} input Raw input string
             * @returns {string} Hex encoded string
             */
            Md5.rstr2hex = function (input) {
                var hexTab = '0123456789abcdef';
                var output = '';
                var x;
                var i;
                for (i = 0; i < input.length; i += 1) {
                    x = input.charCodeAt(i);
                    output += hexTab.charAt((x >>> 4) & 0x0f) + hexTab.charAt(x & 0x0f);
                }
                return output;
            };
            /**
             * Encode a string as UTF-8
             *
             * @param {string} input Input string
             * @returns {string} UTF8 string
             */
            Md5.str2rstrUTF8 = function (input) {
                return unescape(encodeURIComponent(input));
            };
            /**
             * Encodes input string as raw MD5 string
             *
             * @param {string} s Input string
             * @returns {string} Raw MD5 string
             */
            Md5.rawMD5 = function (s) {
                return Md5.rstrMD5(Md5.str2rstrUTF8(s));
            };
            /**
             * Encodes input string as Hex encoded string
             *
             * @param {string} s Input string
             * @returns {string} Hex encoded string
             */
            Md5.hexMD5 = function (s) {
                return Md5.rstr2hex(Md5.rawMD5(s));
            };
            /**
             * Calculates the raw HMAC-MD5 for the given key and data
             *
             * @param {string} k HMAC key
             * @param {string} d Input string
             * @returns {string} Raw MD5 string
             */
            Md5.rawHMACMD5 = function (k, d) {
                return Md5.rstrHMACMD5(Md5.str2rstrUTF8(k), Md5.str2rstrUTF8(d));
            };
            /**
             * Calculates the Hex encoded HMAC-MD5 for the given key and data
             *
             * @param {string} k HMAC key
             * @param {string} d Input string
             * @returns {string} Raw MD5 string
             */
            Md5.hexHMACMD5 = function (k, d) {
                return Md5.rstr2hex(Md5.rawHMACMD5(k, d));
            };
            /**
             * Calculates MD5 value for a given string.
             * If a key is provided, calculates the HMAC-MD5 value.
             * Returns a Hex encoded string unless the raw argument is given.
             *
             * @param {string} string Input string
             * @param {string} [key] HMAC key
             * @param {boolean} [raw] Raw output switch
             * @returns {string} MD5 output
             */
            Md5.md5 = function (string, key, raw) {
                if (!key) {
                    if (!raw) {
                        return Md5.hexMD5(string);
                    }
                    return Md5.rawMD5(string);
                }
                if (!raw) {
                    return Md5.hexHMACMD5(key, string);
                }
                return Md5.rawHMACMD5(key, string);
            };
            return Md5;
        }());
        encrypt.Md5 = Md5;
    })(encrypt = tarsis.encrypt || (tarsis.encrypt = {}));
})(tarsis || (tarsis = {}));
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-11-27 15:10:26
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-11-27 15:51:10
 */
var tarsis;
(function (tarsis) {
    var laya;
    (function (laya) {
        var ViewControl = /** @class */ (function (_super) {
            __extends(ViewControl, _super);
            function ViewControl() {
                return _super !== null && _super.apply(this, arguments) || this;
            }
            ViewControl.prototype.onEnable = function () {
                this.self = this.owner;
                this.view = this.owner;
            };
            ViewControl.prototype.setShow = function (show) {
                this.self.visible = show;
            };
            ViewControl.prototype.filtAllChildren = function (action) {
                for (var index = 0; index < this.self.numChildren; index++) {
                    var element = this.self.getChildAt(index);
                    action(element, this);
                }
            };
            return ViewControl;
        }(Laya.Script));
        laya.ViewControl = ViewControl;
        var ButtonControl = /** @class */ (function (_super) {
            __extends(ButtonControl, _super);
            function ButtonControl() {
                var _this = _super !== null && _super.apply(this, arguments) || this;
                /** @prop {name:widthValue,tips:"定义宽度",type:Int,default:0}*/
                _this.widthValue = 0;
                /** @prop {name:heightValue,tips:"定义高度",type:Int,default:0}*/
                _this.heightValue = 0;
                /** @prop {name:scaleDuration,tips:"定义缩放时长",type:Int,default:100}*/
                _this.scaleDuration = 100;
                /** @prop {name:scaleSize,tips:"定义缩放比例",type:Number,default:0.8}*/
                _this.scaleSize = 0.8;
                /** @prop {name:scaleOri,tips:"定义缩放基础比例",type:Number,default:1}*/
                _this.scaleOri = 1;
                _this.onClicked = null;
                _this.onCooldownDone = null;
                _this.nowState = 0; // 0 nomal,1 hover, 2 down
                _this.isDisable = false;
                _this.isChecked = false;
                _this.isFrozen = false;
                _this.isCooldown = false;
                _this.isPurchasing = false;
                _this.isSilence = false;
                _this.newLabel = null;
                _this.labelInited = false;
                _this.labelText = null;
                _this.labelFilters = [];
                _this.labelOffset = null;
                _this.valueZone = null;
                _this.valueLabel = null;
                _this.countLabel = null;
                _this.cooldownZone = null;
                _this.cooldownTimeLabel = null;
                _this.isOnCooldown = false;
                _this.coverColor = '#000000';
                return _this;
            }
            /**
             * 设置响应方法
             * @param callback 点击的回调
             * @param cooldownDone CD完成的回调
             */
            ButtonControl.prototype.setCallback = function (callback, cooldownDone) {
                if (cooldownDone === void 0) { cooldownDone = null; }
                this.onClicked = callback;
                this.onCooldownDone = cooldownDone;
            };
            /**
             * 外部触发按钮的点击
             */
            ButtonControl.prototype.triggerClick = function () {
                this.onMouseUp();
            };
            /**
             * 触发选中状态
             * @param checked 是否选中
             */
            ButtonControl.prototype.toggleChcek = function (checked) {
                if (checked === void 0) { checked = false; }
                this.isChecked = checked;
                this.owner.skin = checked && this.checkSkin ? this.checkSkin : this.mainSkin;
                if (this.valueZone)
                    this.valueZone.visible = !checked;
                if (this.isCooldown) {
                    this.toggleCooldown(checked);
                }
            };
            /**
             * 触发禁用状态
             * @param disabled 是否禁用
             */
            ButtonControl.prototype.toggleDiable = function (disabled) {
                if (disabled === void 0) { disabled = false; }
                this.isDisable = disabled;
                this.owner.gray = this.isDisable;
            };
            /**
             * 触发冻结状态（不响应点击）
             * @param freeze 是否冻结
             */
            ButtonControl.prototype.toggleFrozen = function (freeze) {
                this.isFrozen = freeze;
            };
            /**
             * 触发静默状态（不响应点击 并且不发消息）
             * @param silence 是否静默
             */
            ButtonControl.prototype.toggleSilence = function (silence) {
                this.isSilence = silence;
            };
            /**
             * 触发倒计时
             * @param cooldown 是否是开始倒计时
             */
            ButtonControl.prototype.toggleCooldown = function (cooldown) {
                this.isOnCooldown = cooldown;
                if (cooldown) {
                    this.timeLeft = this.cooldownDuration * 1000;
                    this.nowAngle = -90;
                    this.strideDuration = this.cooldownDuration * 1000 / 360;
                    if (this.cooldownZone) {
                        this.cooldownZone.visible = true;
                        if (this.cooldownTimeLabel) {
                            this.cooldownTimeLabel.changeText(this.countTime());
                        }
                    }
                    if (this.valueZone) {
                        this.valueZone.visible = false;
                    }
                    Laya.timer.loop(this.strideDuration, this, this.coverDown);
                }
                else {
                    Laya.timer.clear(this, this.coverDown);
                    if (this.cooldownZone) {
                        this.cooldownZone.visible = false;
                    }
                    if (this.isPurchasing) {
                        this.setValueZone();
                    }
                    this.toggleFrozen(false);
                    this.cover.graphics.clear();
                }
            };
            /**
             * 缩小到设置的目标值
             */
            ButtonControl.prototype.scaleSmall = function () {
                Laya.Tween.to(this.owner, { scaleX: this.scaleSize, scaleY: this.scaleSize }, this.scaleDuration);
            };
            /**
             * 回弹到设置的默认值
             */
            ButtonControl.prototype.scaleBig = function () {
                Laya.Tween.to(this.owner, { scaleX: this.scaleOri, scaleY: this.scaleOri }, this.scaleDuration);
            };
            /**
             * 重写的OVER方法（未使用）
             */
            ButtonControl.prototype.onMouseOver = function () {
            };
            /**
             * 重写的OUT方法，恢复默认大小
             */
            ButtonControl.prototype.onMouseOut = function () {
                this.scaleBig();
            };
            /**
             * 重写的DOWN方法，缩小按钮
             */
            ButtonControl.prototype.onMouseDown = function () {
                if (!this.isDisable && !this.isFrozen) {
                    this.scaleSmall();
                }
            };
            /**
             * 重写的UP方法，回弹按钮
             */
            ButtonControl.prototype.onMouseUp = function () {
                this.scaleBig();
                if (!this.isDisable && !this.isFrozen && this.onClicked && !this.isSilence) {
                    this.onClicked();
                }
            };
            /**
             * 初始化方法
             */
            ButtonControl.prototype.onEnable = function () {
                this.button = this.owner;
                this.button.stateNum = 1;
                this.button.skin = this.isChecked && this.checkSkin
                    ? this.checkSkin
                    : this.mainSkin;
                this.button.width = this.widthValue;
                this.button.height = this.heightValue;
                this.button.anchorX = 0.5;
                this.button.anchorY = 0.5;
                if (this.labelSetting && this.labelSetting[0]) {
                    this.newLabel = new Laya.Label("" + (this.labelText ? this.labelText : 'Label'));
                    this.newLabel.bold = this.labelSetting[1];
                    this.newLabel.fontSize = this.labelSetting[2];
                    this.newLabel.color = this.labelSetting[3];
                    this.newLabel.stroke = this.labelSetting[4];
                    this.newLabel.strokeColor = this.labelSetting[5];
                    this.newLabel.align = "center";
                    this.newLabel.valign = "middle";
                    this.newLabel.anchorX = 0.5;
                    this.newLabel.anchorY = 0.5;
                    this.labelFilters = this.labelFilters.length > 0 ? this.labelFilters : [];
                    var offset = this.labelOffset ? this.labelOffset : new Laya.Point(0, -5);
                    this.owner.addChild(this.newLabel.size(this.button.width, this.labelSetting[2] + 10).pos(this.button.width / 2 + offset.x, this.button.height / 2 + offset.y));
                    this.labelInited = true;
                }
                if (this.coolDownSetting && this.coolDownSetting[0]) {
                    this.isCooldown = true;
                    this.cover = new Laya.Sprite();
                    var image = new Laya.Image(this.button.skin);
                    this.cover.mask = image;
                    this.cover.alpha = 0.5;
                    this.cover.pivot(image.width / 2, image.height / 2);
                    this.button.addChild(this.cover.pos(image.width / 2, image.height / 2));
                    this.radius = image.height;
                    // this.cover.graphics.drawPie(this.cover.pivotX,this.cover.pivotY,this.radius,-90,150,this.coverColor)
                }
                if (this.purchasingSetting && this.purchasingSetting[0]) {
                    this.isPurchasing = true;
                }
            };
            /**
             * 修改按钮样式
             * @param skin 皮肤图片路径
             */
            ButtonControl.prototype.setMainSkin = function (skin) {
                this.owner.skin = skin;
            };
            /**
             * 设置按钮的Label（不是Laya.Button的Label）
             * @param text Label文字
             */
            ButtonControl.prototype.setLabelText = function (text) {
                if (this.labelInited) {
                    this.newLabel.text = text;
                }
                else {
                    this.labelText = text;
                }
            };
            /**
             * 设置按钮Label的过滤效果器（不是Laya.Button的Label）
             * @param filters 过滤集合
             */
            ButtonControl.prototype.setLabelFilter = function (filters) {
                if (this.labelInited) {
                    this.newLabel.filters = filters;
                }
                else {
                    this.labelFilters = filters;
                }
            };
            /**
             * 设置按钮Label的偏移（不是Laya.Button的Label）
             * @param x 偏移量：x
             * @param y 偏移量：y
             */
            ButtonControl.prototype.setLabelOffset = function (x, y) {
                if (this.labelInited) {
                    this.newLabel.pos(this.newLabel.x + x, this.newLabel.y + y);
                }
                else {
                    this.labelOffset = new Laya.Point(x, y);
                }
            };
            /**
             * 设置内部附加对象
             * @param param 传入的对象列表和设置
             * @param param.valueZone 按钮对象的价格区
             * @param param.valueLabel 按钮对象的价格标签
             * @param param.cooldownZone 按钮对象的倒计时标签区
             * @param param.cooldownTimeLabel 按钮对象的倒计时标签
             * @param param.countLabel 按钮对象的计数区
             * @param param.countValue 按钮对象的计数初始值
             * @param param.cooldownDuration 按钮对象的倒计时时长（秒）
             */
            ButtonControl.prototype.setAddonItem = function (param) {
                this.valueZone = param.valueZone || null;
                this.valueLabel = param.valueLabel || null;
                this.cooldownZone = param.cooldownZone || null;
                this.cooldownTimeLabel = param.timeLabel || null;
                this.countLabel = param.countLabel || null;
                this.countValue = param.count || 0;
                this.cooldownDuration = param.duration || 30;
                if (this.cooldownZone)
                    this.cooldownZone.visible = false;
                if (this.countLabel)
                    this.countLabel.text = "" + this.countValue;
                if (this.valueLabel)
                    this.valueLabel.changeText("" + param.addonValue);
                this.setValueZone();
            };
            /**
             * 设置按钮计数的值
             * @param count 计数值
             */
            ButtonControl.prototype.setCount = function (count) {
                this.countValue = count;
                if (this.countLabel) {
                    this.countLabel.text = "" + count;
                    this.setValueZone();
                }
            };
            /**
             * 设置按钮对象的价格值
             * @param text 按钮对象的价格值
             */
            ButtonControl.prototype.setValue = function (text) {
                if (this.valueLabel) {
                    this.valueLabel.changeText("" + text);
                }
            };
            /**
             * 检查是否需要显示按钮价格区
             */
            ButtonControl.prototype.setValueZone = function () {
                if (this.valueZone) {
                    this.valueZone.visible = !this.isChecked && !this.isOnCooldown && this.countValue == 0;
                }
            };
            /**
             * 倒计时单元处理函数
             */
            ButtonControl.prototype.coverDown = function () {
                this.nowAngle += 1;
                if (this.coolDownSetting[2] && this.cooldownTimeLabel) {
                    this.timeLeft -= this.strideDuration;
                    this.cooldownTimeLabel.text = this.countTime();
                }
                this.cover.graphics.clear();
                this.cover.graphics.drawPie(this.cover.pivotX, this.cover.pivotY, this.radius, -90, this.nowAngle, this.coverColor);
                if (this.nowAngle >= 270) {
                    this.toggleChcek(false);
                    if (this.onCooldownDone) {
                        this.onCooldownDone();
                    }
                }
            };
            /**
             * 计算倒计时显示的时间
             */
            ButtonControl.prototype.countTime = function () {
                var totalSeconds = this.timeLeft / 1000;
                var hours = Math.floor(totalSeconds / 3600);
                var minius = Math.floor((totalSeconds - hours * 3600) / 60);
                var second = Math.floor(totalSeconds - hours * 3600 - minius * 60);
                var hoursStr = hours > 0
                    ? hours >= 10
                        ? hours
                        : "0" + hours
                    : "";
                var miniusStr = minius > 0
                    ? minius >= 10
                        ? minius
                        : "0" + minius
                    : "00";
                var secondStr = second > 0
                    ? second >= 10
                        ? second
                        : "0" + second
                    : "00";
                return hoursStr != ""
                    ? hoursStr + ":" + miniusStr + ":" + secondStr
                    : miniusStr + ":" + secondStr;
            };
            return ButtonControl;
        }(Laya.Script));
        laya.ButtonControl = ButtonControl;
    })(laya = tarsis.laya || (tarsis.laya = {}));
})(tarsis || (tarsis = {}));
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-11-27 15:10:34
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-11-27 15:51:11
 */
var tarsis;
(function (tarsis) {
    var laya;
    (function (laya) {
        var Http = /** @class */ (function () {
            function Http() {
            }
            Http.StartHttpCall = function (params) {
                console.log(params);
                var settings = __assign({ url: '', isPost: false, data: null, onSuccess: null, onError: null, onProgress: null, timeout: 10000, responseType: 'text' }, params);
                var xhr = new Laya.HttpRequest();
                var postData = '';
                xhr.http.timeout = settings.timeout;
                xhr.once(Laya.Event.COMPLETE, this, function (data) {
                    if (settings.onSuccess) {
                        settings.onSuccess(data);
                    }
                    else {
                        console.log("[HTTP] success @ " + data);
                    }
                });
                xhr.once(Laya.Event.ERROR, this, function (data) {
                    if (settings.onError) {
                        settings.onError(data);
                    }
                    else {
                        console.log("[HTTP] error @ " + data);
                    }
                });
                xhr.on(Laya.Event.PROGRESS, this, function (data) {
                    if (settings.onProgress) {
                        settings.onProgress(data);
                    }
                    else {
                        console.log("[HTTP] progress @ " + data);
                    }
                });
                if (settings.data) {
                    var index = 0;
                    for (var _i = 0, _a = Object.keys(settings.data); _i < _a.length; _i++) {
                        var key = _a[_i];
                        if (index > 0) {
                            postData += "&";
                        }
                        index += 1;
                        postData += key + "=" + settings.data[key];
                    }
                }
                xhr.send("" + settings.url + (!settings.isPost && postData ? '?' + postData : ''), settings.isPost ? postData : '', "" + (settings.isPost ? 'post' : 'get'), settings.responseType);
            };
            return Http;
        }());
        laya.Http = Http;
    })(laya = tarsis.laya || (tarsis.laya = {}));
})(tarsis || (tarsis = {}));
(function (tarsis) {
    var laya;
    (function (laya) {
        var Socket = /** @class */ (function () {
            function Socket() {
                this.isOpen = false;
                this.onOpen = null;
                this.onError = null;
                this.onClose = null;
                this.onMsg = null;
            }
            Socket.prototype.init = function (url, onOpen, onError, onClose, onMsg) {
                this.onOpen = onOpen;
                this.onClose = onClose;
                this.onError = onError;
                this.onMsg = onMsg;
                this.connect(url);
            };
            Socket.prototype.close = function () {
                this.socket.close();
            };
            Socket.prototype.connect = function (url) {
                console.log("SOCKET INIT @ " + url);
                this.socket = new Laya.Socket();
                this.socket.connectByUrl(url);
                this.output = this.socket.output;
                this.socket.on(Laya.Event.OPEN, this, this.onSocketOpen);
                this.socket.on(Laya.Event.CLOSE, this, this.onSocketClose);
                this.socket.on(Laya.Event.MESSAGE, this, this.onMessageReveived);
                this.socket.on(Laya.Event.ERROR, this, this.onConnectError);
            };
            Socket.prototype.onSocketOpen = function () {
                console.log("[SOCKET] Socket Connected");
                this.isOpen = true;
                if (this.onOpen)
                    this.onOpen();
            };
            Socket.prototype.onSocketClose = function () {
                console.log("[SOCKET] Socket closed");
                this.isOpen = false;
                if (this.onClose)
                    this.onClose();
            };
            Socket.prototype.onMessageReveived = function (message) {
                var msg = "";
                if (typeof message == "string") {
                    msg = message;
                }
                else if (message instanceof ArrayBuffer) {
                    console.log(new Laya.Byte(message).readUTFBytes());
                    msg = new Laya.Byte(message).readUTFBytes();
                }
                this.socket.input.clear();
                if (this.onMsg)
                    this.onMsg(msg);
            };
            Socket.prototype.onConnectError = function (e) {
                console.log("[SOCKET] Error : " + e);
                if (this.onError)
                    this.onError(e);
            };
            Socket.prototype.sendMessge = function (msg) {
                if (this.isOpen) {
                    try {
                        this.socket.send(JSON.stringify(msg));
                    }
                    catch (error) {
                        if (this.onError)
                            this.onError(error);
                    }
                }
            };
            return Socket;
        }());
        laya.Socket = Socket;
    })(laya = tarsis.laya || (tarsis.laya = {}));
})(tarsis || (tarsis = {}));
(function (tarsis) {
    var laya;
    (function (laya) {
        var PostOffice = /** @class */ (function () {
            function PostOffice() {
                this.isSocketOpen = false;
                this.onHeartFail = null;
                this.ping = 'PING';
                this.debugIn = false;
                this.debugOut = false;
                PostOffice.instance = this;
            }
            /**
             * @param
             * setting:{
             *  url : stirng,
             *  ping : string,
             *  debugIn : bool = false,
             *  debugOut : bool = false,
             *  onOpenCallback:Function = null,
             *  onMessageCallback:Function = null,
             *  onSocketError:Function = null,
             *  onHeartFail : Function = null
             * }
             */
            PostOffice.prototype.startNet = function (setting) {
                var _this = this;
                this.socket = new laya.Socket();
                this.onHeartFail = setting.onHeartFail;
                this.ping = setting.ping;
                this.debugIn = setting.debugIn || this.debugIn;
                this.debugOut = setting.debugIn || this.debugOut;
                this.socket.init(setting.url, function () {
                    _this.onOpen();
                    if (setting.onOpenCallback) {
                        setting.onOpenCallback();
                    }
                }, function (e) {
                    _this.onError(e);
                    if (setting.onSocketError) {
                        setting.onSocketError(e);
                    }
                }, function () {
                    _this.onClose();
                }, function (data) {
                    _this.onMessage(data, setting.onMessageCallback);
                });
            };
            PostOffice.prototype.onOpen = function () {
                this.isSocketOpen = true;
                Laya.timer.loop(5000, this, this.heartBeat);
            };
            PostOffice.prototype.onError = function (res) {
                console.log("Socket On Error :: " + res);
            };
            PostOffice.prototype.onMessage = function (data, onMessageCallback) {
                if (onMessageCallback === void 0) { onMessageCallback = null; }
                var msg = JSON.parse(data);
                if (this.debugIn && msg.type !== this.ping) {
                    console.log(msg);
                }
                if (msg.type == this.ping) {
                    Laya.timer.clear(this, this.heartBeatFail);
                }
                else {
                    this.dealMessage(msg);
                    if (onMessageCallback) {
                        onMessageCallback(msg);
                    }
                }
            };
            PostOffice.prototype.onClose = function () {
                this.isSocketOpen = false;
                Laya.timer.clear(this, this.heartBeat);
                if (this.onHeartFail) {
                    this.onHeartFail();
                }
            };
            PostOffice.prototype.heartBeat = function () {
                if (this.isSocketOpen) {
                    this.sendMessage({ type: this.ping });
                    Laya.timer.once(4000, this, this.heartBeatFail);
                }
            };
            PostOffice.prototype.heartBeatFail = function () {
                this.socket.close();
                if (this.onHeartFail) {
                    this.onHeartFail();
                }
            };
            PostOffice.prototype.dealMessage = function (msg) {
            };
            PostOffice.prototype.sendMessage = function (msg) {
                if (this.isSocketOpen) {
                    if (this.debugOut && msg.type !== this.ping) {
                        console.log("Msg Out : " + JSON.stringify(msg));
                    }
                    this.socket.sendMessge(msg);
                }
            };
            return PostOffice;
        }());
        laya.PostOffice = PostOffice;
    })(laya = tarsis.laya || (tarsis.laya = {}));
})(tarsis || (tarsis = {}));
(function (tarsis) {
    var laya;
    (function (laya) {
        var helper = /** @class */ (function () {
            function helper() {
            }
            /**
             * 获取外部图片，执行回调函数
             */
            helper.getOutsideImage = function (url, callback) {
                laya.Http.StartHttpCall({
                    url: url,
                    responseType: 'arraybuffer',
                    onSuccess: function (data) {
                        var byte = new Laya.Byte(data); //Byte数组接收arraybuffer
                        byte.writeArrayBuffer(data, 4); //从第四个字节开始读取数据
                        var blob = new Laya.Browser.window.Blob([data], { type: "image/png" });
                        var url = Laya.Browser.window.URL.createObjectURL(blob); //创建一个url对象；
                        if (callback) {
                            callback(url);
                        }
                    }
                });
            };
            return helper;
        }());
        laya.helper = helper;
    })(laya = tarsis.laya || (tarsis.laya = {}));
})(tarsis || (tarsis = {}));
/*
 * @Author: Odie Robin (odierobin@gmai.com)
 * @Date: 2019-08-30 13:56:19
 * @Last Modified by: Odie Robin (odierobin@gmai.com)
 * @Last Modified time: 2019-08-30 14:25:25
 */
var tarsis;
(function (tarsis) {
    var laya;
    (function (laya) {
        var vector = /** @class */ (function () {
            function vector() {
            }
            vector.Vector2Magnitude = function (v2) {
                return Math.sqrt(v2.x * v2.x + v2.y * v2.y);
            };
            vector.Vector2SqrtMagnitude = function (v2) {
                return v2.x * v2.x + v2.y + v2.y;
            };
            vector.Vector2Normalize = function (v2) {
                var meg = this.Vector2Magnitude(v2);
                if (meg > this.kEpsilon) {
                    return new Laya.Vector2(v2.x / meg, v2.y / meg);
                }
                else {
                    return new Laya.Vector2(0, 0);
                }
            };
            vector.Vector2Angle = function (from, to) {
                var deg2Rad = 360 / Math.PI / 2;
                var denominator = Math.sqrt((from.x * from.x + from.y * from.y) * (to.x * to.x + to.y * to.y));
                if (denominator < this.kEpsilonNormalSqrt)
                    return 0;
                var dot = Math.max(-1, Math.min(1, from.x * to.x + from.y * to.y / denominator));
                return Math.acos(dot) * deg2Rad;
            };
            vector.Vector2Plus = function (lhs, rhs) {
                return new Laya.Vector2(lhs.x + rhs.x, lhs.y + rhs.y);
            };
            vector.Vector2Minus = function (lhs, rhs) {
                return new Laya.Vector2(lhs.x - rhs.x, lhs.y - rhs.y);
            };
            vector.Vector2Dot = function (lhs, rhs) {
                return lhs.x * rhs.x + lhs.y * rhs.y;
            };
            vector.Vector2Rotate = function (v, degrees) {
                var sin = Math.sin(degrees * Math.PI / 180);
                var cos = Math.cos(degrees * Math.PI / 180);
                var tx = v.x;
                var ty = v.y;
                return new Laya.Vector2((cos * tx) - (sin * ty), (sin * tx) + (cos * ty));
            };
            vector.GetSprite3DProjection = function (target, camera) {
                var result = new Laya.Vector3(-1000, -1000, -1000);
                camera.viewport.project(target.transform.position, camera.projectionViewMatrix, result);
                return result;
            };
            vector.GetTransform3DProjection = function (trans, camera) {
                var result = new Laya.Vector3(-1000, -1000, -1000);
                camera.viewport.project(trans.position, camera.projectionViewMatrix, result);
                return result;
            };
            vector.kEpsilon = 0.00001;
            vector.kEpsilonNormalSqrt = 1e-15;
            return vector;
        }());
        laya.vector = vector;
    })(laya = tarsis.laya || (tarsis.laya = {}));
})(tarsis || (tarsis = {}));
/*
 * @Author: Odie Robin (odierobin@gmai.com)
 * @Date: 2019-08-30 13:55:04
 * @Last Modified by:   Odie Robin (odierobin@gmai.com)
 * @Last Modified time: 2019-08-30 13:55:04
 */
var tarsis;
(function (tarsis) {
    var math;
    (function (math) {
        /**
         * 贝赛尔曲线处理方法
         */
        var Besizer = /** @class */ (function () {
            function Besizer() {
            }
            /**
             * 生成控制点集合
             * @param points 目标路径点
             */
            Besizer.CubicCurveAlgorithmControlPoints = function (points) {
                var firstControlPoints = [];
                var secondControlPoints = [];
                var count = points.length - 1;
                if (count == 1) {
                    var P0 = points[0];
                    var P3 = points[1];
                    var P1x = (2 * P0.x + P3.x) / 3;
                    var P1y = (2 * P0.y + P3.y) / 3;
                    firstControlPoints.push({ x: P1x, y: P1y });
                    var P2x = (2 * P1x - P0.x);
                    var P2y = (2 * P1y - P0.y);
                    secondControlPoints.push({ x: P2x, y: P2y });
                }
                else {
                    var rhsArray = [];
                    var a = [];
                    var b = [];
                    var c = [];
                    for (var i = 0; i < count; i++) {
                        var rhsValueX = 0;
                        var rhsValueY = 0;
                        var P0 = points[i];
                        var P3 = points[i + 1];
                        if (i == 0) {
                            a.push(0);
                            b.push(2);
                            c.push(1);
                            rhsValueX = P0.x + 2 * P3.x;
                            rhsValueY = P0.y + 2 * P3.y;
                        }
                        else if (i == count - 1) {
                            a.push(2);
                            b.push(7);
                            c.push(0);
                            rhsValueX = 8 * P0.x + P3.x;
                            rhsValueY = 8 * P0.y + P3.y;
                        }
                        else {
                            a.push(1);
                            b.push(4);
                            c.push(1);
                            rhsValueX = 4 * P0.x + 2 * P3.x;
                            rhsValueY = 4 * P0.y + 2 * P3.y;
                        }
                        rhsArray.push({ x: rhsValueX, y: rhsValueY });
                    }
                    for (var i = 1; i < count; i++) {
                        var rhsValueX = rhsArray[i].x;
                        var rhsValueY = rhsArray[i].y;
                        var prevRhsValueX = rhsArray[i - 1].x;
                        var prevRhsValueY = rhsArray[i - 1].y;
                        var m = a[i] / b[i - 1];
                        var b1 = b[i] - m * c[i - 1];
                        b[i] = b1;
                        var r2x = rhsValueX - m * prevRhsValueX;
                        var r2y = rhsValueY - m * prevRhsValueY;
                        rhsArray[i] = { x: r2x, y: r2y };
                    }
                    var lastControlPointX = rhsArray[count - 1].x / b[count - 1];
                    var lastControlPointY = rhsArray[count - 1].y / b[count - 1];
                    firstControlPoints[count - 1] = { x: lastControlPointX, y: lastControlPointY };
                    for (var i = count - 2; i >= 0; i--) {
                        var nextControlPoint = firstControlPoints[i + 1];
                        if (nextControlPoint) {
                            var controlPointX = (rhsArray[i].x - c[i] * nextControlPoint.x) / b[i];
                            var controlPointY = (rhsArray[i].y - c[i] * nextControlPoint.y) / b[i];
                            firstControlPoints[i] = { x: controlPointX, y: controlPointY };
                        }
                    }
                    for (var i = 0; i < count; i++) {
                        if (i == count - 1) {
                            var P3 = points[i + 1];
                            var P1 = firstControlPoints[i];
                            if (P1) {
                                var controlPointX = (P3.x + P1.x) / 2;
                                var controlPointY = (P3.y + P1.y) / 2;
                                secondControlPoints.push({ x: controlPointX, y: controlPointY });
                            }
                        }
                        else {
                            var P3 = points[i + 1];
                            var nextP1 = firstControlPoints[i + 1];
                            if (nextP1) {
                                var controlPointX = 2 * P3.x - nextP1.x;
                                var controlPointY = 2 * P3.y - nextP1.y;
                                secondControlPoints.push({ x: controlPointX, y: controlPointY });
                            }
                        }
                    }
                }
                var controlPoints = [];
                for (var i = 0; i < count; i++) {
                    var firstControlPoint = firstControlPoints[i];
                    var secondControlPoint = secondControlPoints[i];
                    if (firstControlPoint && secondControlPoint) {
                        var segment = { controlPoint1: firstControlPoint, controlPoint2: secondControlPoint };
                        controlPoints.push(segment);
                    }
                }
                return controlPoints;
            };
            /**
             * 曲线插值
             * @param points 目标路径点
             * @param pointDistance 生成点的密度(距离)
             */
            Besizer.CubicCurveAlgorithmInterpolation = function (points, pointDistance) {
                if (pointDistance === void 0) { pointDistance = 10; }
                var cpList = Besizer.CubicCurveAlgorithmControlPoints(points);
                var list = [];
                for (var i = 0; i < points.length; i++) {
                    if (i > 0) {
                        var p1 = points[i - 1];
                        var p2 = cpList[i - 1].controlPoint1;
                        var p3 = cpList[i - 1].controlPoint2;
                        var p4 = points[i];
                        var count = Math.ceil(Math.sqrt(Math.pow((p4.x - p1.x), 2) + Math.pow((p4.y - p1.y), 2)) / pointDistance);
                        var step = 1.0 / count;
                        var t = 0;
                        for (var j = 0; j < count; j++) {
                            var x = Math.pow((1 - t), 3) * p1.x + 3 * p2.x * t * (1 - t) * (1 - t) + 3 * p3.x * t * t * (1 - t) + p4.x * Math.pow(t, 3);
                            var y = Math.pow((1 - t), 3) * p1.y + 3 * p2.y * t * (1 - t) * (1 - t) + 3 * p3.y * t * t * (1 - t) + p4.y * Math.pow(t, 3);
                            list.push({ x: x, y: y });
                            t += step;
                        }
                    }
                }
                list.push(points[points.length - 1]);
                return list;
            };
            return Besizer;
        }());
        math.Besizer = Besizer;
    })(math = tarsis.math || (tarsis.math = {}));
})(tarsis || (tarsis = {}));
(function (tarsis) {
    var math;
    (function (math) {
        /**
         * Easing集合
         */
        var Easing = /** @class */ (function () {
            function Easing() {
            }
            Easing.easeInQuad = function (x, t, b, c, d) {
                return c * (t /= d) * t + b;
            };
            Easing.easeOutQuad = function (x, t, b, c, d) {
                return -c * (t /= d) * (t - 2) + b;
            };
            Easing.easeInOutQuad = function (x, t, b, c, d) {
                if ((t /= d / 2) < 1)
                    return c / 2 * t * t + b;
                return -c / 2 * ((--t) * (t - 2) - 1) + b;
            };
            Easing.easeInCubic = function (x, t, b, c, d) {
                return c * (t /= d) * t * t + b;
            };
            Easing.easeOutCubic = function (x, t, b, c, d) {
                return c * ((t = t / d - 1) * t * t + 1) + b;
            };
            Easing.easeInOutCubic = function (x, t, b, c, d) {
                if ((t /= d / 2) < 1)
                    return c / 2 * t * t * t + b;
                return c / 2 * ((t -= 2) * t * t + 2) + b;
            };
            Easing.easeInQuart = function (x, t, b, c, d) {
                return c * (t /= d) * t * t * t + b;
            };
            Easing.easeOutQuart = function (x, t, b, c, d) {
                return -c * ((t = t / d - 1) * t * t * t - 1) + b;
            };
            Easing.easeInOutQuart = function (x, t, b, c, d) {
                if ((t /= d / 2) < 1)
                    return c / 2 * t * t * t * t + b;
                return -c / 2 * ((t -= 2) * t * t * t - 2) + b;
            };
            Easing.easeInQuint = function (x, t, b, c, d) {
                return c * (t /= d) * t * t * t * t + b;
            };
            Easing.easeOutQuint = function (x, t, b, c, d) {
                return c * ((t = t / d - 1) * t * t * t * t + 1) + b;
            };
            Easing.easeInOutQuint = function (x, t, b, c, d) {
                if ((t /= d / 2) < 1)
                    return c / 2 * t * t * t * t * t + b;
                return c / 2 * ((t -= 2) * t * t * t * t + 2) + b;
            };
            Easing.easeInSine = function (x, t, b, c, d) {
                return -c * Math.cos(t / d * (Math.PI / 2)) + c + b;
            };
            Easing.easeOutSine = function (x, t, b, c, d) {
                return c * Math.sin(t / d * (Math.PI / 2)) + b;
            };
            Easing.easeInOutSine = function (x, t, b, c, d) {
                return -c / 2 * (Math.cos(Math.PI * t / d) - 1) + b;
            };
            Easing.easeInExpo = function (x, t, b, c, d) {
                return (t == 0) ? b : c * Math.pow(2, 10 * (t / d - 1)) + b;
            };
            Easing.easeOutExpo = function (x, t, b, c, d) {
                return (t == d) ? b + c : c * (-Math.pow(2, -10 * t / d) + 1) + b;
            };
            Easing.easeInOutExpo = function (x, t, b, c, d) {
                if (t == 0)
                    return b;
                if (t == d)
                    return b + c;
                if ((t /= d / 2) < 1)
                    return c / 2 * Math.pow(2, 10 * (t - 1)) + b;
                return c / 2 * (-Math.pow(2, -10 * --t) + 2) + b;
            };
            Easing.easeInCirc = function (x, t, b, c, d) {
                return -c * (Math.sqrt(1 - (t /= d) * t) - 1) + b;
            };
            Easing.easeOutCirc = function (x, t, b, c, d) {
                return c * Math.sqrt(1 - (t = t / d - 1) * t) + b;
            };
            Easing.easeInOutCirc = function (x, t, b, c, d) {
                if ((t /= d / 2) < 1)
                    return -c / 2 * (Math.sqrt(1 - t * t) - 1) + b;
                return c / 2 * (Math.sqrt(1 - (t -= 2) * t) + 1) + b;
            };
            Easing.easeInElastic = function (x, t, b, c, d) {
                var s = 1.70158;
                var p = 0;
                var a = c;
                if (t == 0)
                    return b;
                if ((t /= d) == 1)
                    return b + c;
                if (!p)
                    p = d * .3;
                if (a < Math.abs(c)) {
                    a = c;
                    var s = p / 4;
                }
                else
                    var s = p / (2 * Math.PI) * Math.asin(c / a);
                return -(a * Math.pow(2, 10 * (t -= 1)) * Math.sin((t * d - s) * (2 * Math.PI) / p)) + b;
            };
            Easing.easeOutElastic = function (x, t, b, c, d) {
                var s = 1.70158;
                var p = 0;
                var a = c;
                if (t == 0)
                    return b;
                if ((t /= d) == 1)
                    return b + c;
                if (!p)
                    p = d * .3;
                if (a < Math.abs(c)) {
                    a = c;
                    var s = p / 4;
                }
                else
                    var s = p / (2 * Math.PI) * Math.asin(c / a);
                return a * Math.pow(2, -10 * t) * Math.sin((t * d - s) * (2 * Math.PI) / p) + c + b;
            };
            Easing.easeInOutElastic = function (x, t, b, c, d) {
                var s = 1.70158;
                var p = 0;
                var a = c;
                if (t == 0)
                    return b;
                if ((t /= d / 2) == 2)
                    return b + c;
                if (!p)
                    p = d * (.3 * 1.5);
                if (a < Math.abs(c)) {
                    a = c;
                    var s = p / 4;
                }
                else
                    var s = p / (2 * Math.PI) * Math.asin(c / a);
                if (t < 1)
                    return -.5 * (a * Math.pow(2, 10 * (t -= 1)) * Math.sin((t * d - s) * (2 * Math.PI) / p)) + b;
                return a * Math.pow(2, -10 * (t -= 1)) * Math.sin((t * d - s) * (2 * Math.PI) / p) * .5 + c + b;
            };
            Easing.easeInBack = function (x, t, b, c, d, s) {
                if (s === void 0) { s = 1.70158; }
                return c * (t /= d) * t * ((s + 1) * t - s) + b;
            };
            Easing.easeOutBack = function (x, t, b, c, d, s) {
                if (s === void 0) { s = 1.70158; }
                return c * ((t = t / d - 1) * t * ((s + 1) * t + s) + 1) + b;
            };
            Easing.easeInOutBack = function (x, t, b, c, d, s) {
                if (s === void 0) { s = 1.70158; }
                if (s == undefined)
                    s = 1.70158;
                if ((t /= d / 2) < 1)
                    return c / 2 * (t * t * (((s *= (1.525)) + 1) * t - s)) + b;
                return c / 2 * ((t -= 2) * t * (((s *= (1.525)) + 1) * t + s) + 2) + b;
            };
            Easing.easeInBounce = function (x, t, b, c, d) {
                return c - Easing.easeOutBounce(x, d - t, 0, c, d) + b;
            };
            Easing.easeOutBounce = function (x, t, b, c, d) {
                if ((t /= d) < (1 / 2.75)) {
                    return c * (7.5625 * t * t) + b;
                }
                else if (t < (2 / 2.75)) {
                    return c * (7.5625 * (t -= (1.5 / 2.75)) * t + .75) + b;
                }
                else if (t < (2.5 / 2.75)) {
                    return c * (7.5625 * (t -= (2.25 / 2.75)) * t + .9375) + b;
                }
                else {
                    return c * (7.5625 * (t -= (2.625 / 2.75)) * t + .984375) + b;
                }
            };
            Easing.easeInOutBounce = function (x, t, b, c, d) {
                if (t < d / 2)
                    return Easing.easeInBounce(x, t * 2, 0, c, d) * .5 + b;
                return Easing.easeOutBounce(x, t * 2 - d, 0, c, d) * .5 + c * .5 + b;
            };
            return Easing;
        }());
        math.Easing = Easing;
    })(math = tarsis.math || (tarsis.math = {}));
})(tarsis || (tarsis = {}));
(function (tarsis) {
    var math;
    (function (math) {
        /**
         * 随机函数集合
         */
        var Random = /** @class */ (function () {
            function Random() {
            }
            /**
             * 在一个范围内取值
             * @param min 最小值
             * @param max 最大值
             */
            Random.RandomRange = function (min, max) {
                return min + Math.floor(Math.random() * (max - min));
            };
            /**
             * 在一个范围内取值，取值范围是个对象
             * @param target 取值范围对象{min:number,max:number}
             */
            Random.RandomRangeTarget = function (target) {
                return target.min + Math.floor(Math.random() * (target.max - target.min));
            };
            /**
             * 随机取数组的一项
             * @param array 目标数组
             */
            Random.RandomArrayItem = function (array) {
                return array[this.RandomRange(0, array.length)];
            };
            /**
             * 生成UUID
             * Erzeugt eine UUID nach RFC 4122
             */
            Random.uuid = function () {
                return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function (char) {
                    var random = Math.random() * 16 | 0; // Nachkommastellen abschneiden
                    var value = char === "x" ? random : (random % 4 + 8); // Bei x Random 0-15 (0-F), bei y Random 0-3 + 8 = 8-11 (8-b) gemäss RFC 4122
                    return value.toString(16); // Hexadezimales Zeichen zurückgeben
                });
            };
            return Random;
        }());
        math.Random = Random;
    })(math = tarsis.math || (tarsis.math = {}));
})(tarsis || (tarsis = {}));
(function (tarsis) {
    var math;
    (function (math) {
        /**
         * 使用种子排序或恢复排序
         * 相同种子相同结果
         */
        var Shuffle = /** @class */ (function () {
            function Shuffle() {
            }
            /**
             * 使用种子排序
             * @param arr 目标数组
             * @param seed 目标种子(数字或字符串)
             * @param copy 是否要复制数组
             */
            Shuffle.shuffle = function (arr, seed, copy) {
                if (this.getType(arr) == 'Array') {
                    if (this.setSeed(seed)) {
                        var shuff = (copy ? arr.slice(0) : arr), size = shuff.length, map = this.genMap(size);
                        for (var i = size - 1; i > 0; i--) {
                            shuff[i] = shuff.splice(map[size - 1 - i], 1, shuff[i])[0];
                        }
                        return shuff;
                    }
                }
                return null;
            };
            /**
             * 使用种子恢复数组
             * @param arr 目标数组
             * @param seed 目标种子(数字或字符串)
             * @param copy 是否复制数组
             */
            Shuffle.unshuffle = function (arr, seed, copy) {
                if (this.getType(arr) == "Array") {
                    if (this.setSeed(seed)) {
                        var shuff = (copy ? arr.slice(0) : arr), size = shuff.length, map = this.genMap(size);
                        for (var i = 1; i < size; i++) {
                            shuff[i] = shuff.splice(map[size - 1 - i], 1, shuff[i])[0];
                        }
                        return shuff;
                    }
                }
                return null;
            };
            /**
             * 生成Map数组
             * @param size 数组的长度
             */
            Shuffle.genMap = function (size) {
                var map = new Array(size);
                for (var x = 0; x < size; x++) {
                    //Don't change these numbers.
                    map[x] = ((this.__seed = (this.__seed * 9301 + 49297) % 233280) / 233280.0) * size | 0;
                }
                return map;
            };
            /**
             * 设置当前种子
             * @param seed 目标种子数
             */
            Shuffle.setSeed = function (seed) {
                if (!/(number|string)/i.test(this.getType(seed))) {
                    return false;
                }
                ;
                if (isNaN(seed)) {
                    seed = String((this.strSeed = seed)).split('').map(function (x) { return x.charCodeAt(0); }).join('');
                }
                ;
                return this.__seed = this.seed = Number(seed);
            };
            /**
             * 判断对象类型
             * @param obj 目标对象
             */
            Shuffle.getType = function (obj) {
                return Object.prototype.toString.call(obj).match(/^\[object (.*)\]$/)[1];
            };
            Shuffle.strSeed = null;
            return Shuffle;
        }());
        math.Shuffle = Shuffle;
    })(math = tarsis.math || (tarsis.math = {}));
})(tarsis || (tarsis = {}));
/*
 * @Author: Odie Robin (odierobin@gmai.com)
 * @Date: 2019-08-30 13:44:49
 * @Last Modified by:   Odie Robin (odierobin@gmai.com)
 * @Last Modified time: 2019-08-30 13:44:49
 */
var tarsis;
(function (tarsis) {
    var utils;
    (function (utils) {
        /**
         * 低通滤波器
         * 容许低频信号通过，但减弱（或减少）频率高于截止频率的信号的通过
         * filter's time constant
         * lower = faster reponse + weaker noise suppresion
         * higher = slower, smoother response
         */
        var LowPassFilter = /** @class */ (function () {
            function LowPassFilter(tau) {
                this.iteration = 0;
                this.tau = tau;
            }
            LowPassFilter.prototype.NextStep = function (h, raw) {
                if (this.iteration == 0) { // if it's the first iteration
                    this.filteredValue = raw; // just initate filteredValue
                }
                else {
                    var alpha = Math.exp(-h / this.tau); // calculate alfa value based on time step and filter's time constant
                    this.filteredValue = alpha * this.filteredValue + (1 - alpha) * raw; // calculate new filteredValue from previous value and new raw value
                }
                this.iteration += 1; // increment iteration number
                return this.filteredValue;
            };
            LowPassFilter.prototype.Reset = function () {
                this.iteration = 0; // reset iteration count / force filteredValue initalization
            };
            return LowPassFilter;
        }());
        utils.LowPassFilter = LowPassFilter;
        var Converter = /** @class */ (function () {
            function Converter() {
            }
            /**
             * 转换rgb数组为"#"开头的颜色字符串
             * @param rgbarr rgb数组，[R,G,B]
             */
            Converter.RGBToHex = function (rgbarr) {
                var hexColor = "#";
                var hex = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'];
                for (var i = 0; i < 3; i++) {
                    var r = null;
                    var c = rgbarr[i];
                    var hexAr = [];
                    while (c > 16) {
                        r = c % 16;
                        c = (c / 16) >> 0;
                        hexAr.push(hex[r]);
                    }
                    hexAr.push(hex[c]);
                    if (hexAr.length < 2) {
                        hexAr.push("0");
                    }
                    hexColor += hexAr.reverse().join('');
                }
                return hexColor;
            };
            /**
             * 转换web颜色字符串为rgb的数组：[R,G,B]
             * @param hex 字符串，“#”开头，#f00或#ff00cd
             */
            Converter.HexToRGBArr = function (hex) {
                var rgb = [];
                hex = hex.substr(1);
                if (hex.length === 3) {
                    hex = hex.replace(/(.)/g, '$1$1');
                }
                for (var i = 0; i < 3; i++) {
                    var color = hex.substr(i * 2, 2);
                    rgb.push(parseInt(color, 0x10));
                }
                return rgb;
            };
            Converter.GetWebSafeName = function (code, isCap) {
                if (isCap === void 0) { isCap = false; }
                code = code.replace("-", "_");
                return isCap ? code.toUpperCase() : code.toLowerCase();
            };
            /**
             * 获取当前时间的指定格式
             * @param fmt 指定格式，例如'yyyy-MM-dd HH:mm:ss'
             * @param date 指定的日期，不传为即时
             */
            Converter.FormatDate = function (fmt, date) {
                if (date === void 0) { date = null; }
                var dateTime = date || new Date();
                var o = {
                    "M+": dateTime.getMonth() + 1,
                    "d+": dateTime.getDate(),
                    "H+": dateTime.getHours(),
                    "m+": dateTime.getMinutes(),
                    "s+": dateTime.getSeconds(),
                    "q+": Math.floor((dateTime.getMonth() + 3) / 3),
                    "S": dateTime.getMilliseconds() //毫秒 
                };
                if (/(y+)/.test(fmt)) {
                    fmt = fmt.replace(RegExp.$1, (dateTime.getFullYear() + "").substr(4 - RegExp.$1.length));
                }
                for (var k in o) {
                    if (new RegExp("(" + k + ")").test(fmt)) {
                        fmt = fmt.replace(RegExp.$1, (RegExp.$1.length == 1) ? (o[k]) : (("00" + o[k]).substr(("" + o[k]).length)));
                    }
                }
                return fmt;
            };
            /**
             * 转换地址栏参数，返回对象
             * @param url 地址栏内容
             */
            Converter.ParseQueryString = function (url) {
                var params = {};
                var arr = url.split("?");
                if (arr.length > 1) {
                    var arr1 = arr[1].split("&");
                    for (var i = 0; i < arr1.length; i++) {
                        var arr2 = arr1[i].split('=');
                        if (!arr2[1]) {
                            params[arr2[0]] = 'true';
                        }
                        else if (params[arr2[0]]) {
                            var arr3 = [params[arr2[0]]];
                            arr3.push(arr2[1]);
                            params[arr2[0]] = arr3;
                        }
                        else {
                            params[arr2[0]] = decodeURI(arr2[1]);
                        }
                    }
                }
                else {
                    params = null;
                }
                return params;
            };
            return Converter;
        }());
        utils.Converter = Converter;
    })(utils = tarsis.utils || (tarsis.utils = {}));
})(tarsis || (tarsis = {}));
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidGFyc2lzLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vdGFyc2lzLmVuY3J5cHQudHMiLCIuLi8uLi90YXJzaXMubGF5YWNvbXBvbmVudC50cyIsIi4uLy4uL3RhcnNpcy5sYXlhbmV0LnRzIiwiLi4vLi4vdGFyc2lzLmxheWF2ZWN0b3IudHMiLCIuLi8uLi90YXJzaXMubWF0aC50cyIsIi4uLy4uL3RhcnNpcy51dGlscy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUFFQSxJQUFPLE1BQU0sQ0FpWFo7QUFqWEQsV0FBTyxNQUFNO0lBQUMsSUFBQSxPQUFPLENBaVhwQjtJQWpYYSxXQUFBLE9BQU87UUFDakI7WUFBQTtZQStXQSxDQUFDO1lBOVdHOzs7Ozs7O2VBT0c7WUFDVyxXQUFPLEdBQXJCLFVBQXNCLENBQUMsRUFBRSxDQUFDO2dCQUN0QixJQUFJLEdBQUcsR0FBRyxDQUFDLENBQUMsR0FBRyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUMsR0FBRyxNQUFNLENBQUMsQ0FBQTtnQkFDckMsSUFBSSxHQUFHLEdBQUcsQ0FBQyxDQUFDLElBQUksRUFBRSxDQUFDLEdBQUcsQ0FBQyxDQUFDLElBQUksRUFBRSxDQUFDLEdBQUcsQ0FBQyxHQUFHLElBQUksRUFBRSxDQUFDLENBQUE7Z0JBQzdDLE9BQU8sQ0FBQyxHQUFHLElBQUksRUFBRSxDQUFDLEdBQUcsQ0FBQyxHQUFHLEdBQUcsTUFBTSxDQUFDLENBQUE7WUFDdkMsQ0FBQztZQUVEOzs7Ozs7ZUFNRztZQUNXLGlCQUFhLEdBQTNCLFVBQTRCLEdBQUcsRUFBRSxHQUFHO2dCQUNoQyxPQUFPLENBQUMsR0FBRyxJQUFJLEdBQUcsQ0FBQyxHQUFHLENBQUMsR0FBRyxLQUFLLENBQUMsRUFBRSxHQUFHLEdBQUcsQ0FBQyxDQUFDLENBQUE7WUFDOUMsQ0FBQztZQUVEOzs7Ozs7Ozs7O2VBVUc7WUFDVyxVQUFNLEdBQXBCLFVBQXFCLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQztnQkFDakMsT0FBTyxHQUFHLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxhQUFhLENBQUMsR0FBRyxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsT0FBTyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsRUFBRSxHQUFHLENBQUMsT0FBTyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFBO1lBQ2xHLENBQUM7WUFDRDs7Ozs7Ozs7Ozs7ZUFXRztZQUNXLFNBQUssR0FBbkIsVUFBb0IsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQztnQkFDbkMsT0FBTyxHQUFHLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFBO1lBQ3hELENBQUM7WUFDRDs7Ozs7Ozs7Ozs7ZUFXRztZQUNXLFNBQUssR0FBbkIsVUFBb0IsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQztnQkFDbkMsT0FBTyxHQUFHLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFBO1lBQ3hELENBQUM7WUFDRDs7Ozs7Ozs7Ozs7ZUFXRztZQUNXLFNBQUssR0FBbkIsVUFBb0IsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQztnQkFDbkMsT0FBTyxHQUFHLENBQUMsTUFBTSxDQUFDLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQTtZQUMvQyxDQUFDO1lBQ0Q7Ozs7Ozs7Ozs7O2VBV0c7WUFDVyxTQUFLLEdBQW5CLFVBQW9CLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUM7Z0JBQ25DLE9BQU8sR0FBRyxDQUFDLE1BQU0sQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUE7WUFDbEQsQ0FBQztZQUVEOzs7Ozs7ZUFNRztZQUNXLFdBQU8sR0FBckIsVUFBc0IsQ0FBQyxFQUFFLEdBQUc7Z0JBQ3hCLG9CQUFvQjtnQkFDcEIsQ0FBQyxDQUFDLEdBQUcsSUFBSSxDQUFDLENBQUMsSUFBSSxJQUFJLElBQUksR0FBRyxHQUFHLEVBQUUsQ0FBQTtnQkFDL0IsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLEdBQUcsR0FBRyxFQUFFLENBQUMsS0FBSyxDQUFDLENBQUMsSUFBSSxDQUFDLENBQUMsR0FBRyxFQUFFLENBQUMsR0FBRyxHQUFHLENBQUE7Z0JBRXZDLElBQUksQ0FBQyxDQUFBO2dCQUNMLElBQUksSUFBSSxDQUFBO2dCQUNSLElBQUksSUFBSSxDQUFBO2dCQUNSLElBQUksSUFBSSxDQUFBO2dCQUNSLElBQUksSUFBSSxDQUFBO2dCQUNSLElBQUksQ0FBQyxHQUFHLFVBQVUsQ0FBQTtnQkFDbEIsSUFBSSxDQUFDLEdBQUcsQ0FBQyxTQUFTLENBQUE7Z0JBQ2xCLElBQUksQ0FBQyxHQUFHLENBQUMsVUFBVSxDQUFBO2dCQUNuQixJQUFJLENBQUMsR0FBRyxTQUFTLENBQUE7Z0JBRWpCLEtBQUssQ0FBQyxHQUFHLENBQUMsRUFBRSxDQUFDLEdBQUcsQ0FBQyxDQUFDLE1BQU0sRUFBRSxDQUFDLElBQUksRUFBRSxFQUFFO29CQUMvQixJQUFJLEdBQUcsQ0FBQyxDQUFBO29CQUNSLElBQUksR0FBRyxDQUFDLENBQUE7b0JBQ1IsSUFBSSxHQUFHLENBQUMsQ0FBQTtvQkFDUixJQUFJLEdBQUcsQ0FBQyxDQUFBO29CQUVSLENBQUMsR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsU0FBUyxDQUFDLENBQUE7b0JBQzlDLENBQUMsR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxFQUFFLEVBQUUsRUFBRSxDQUFDLFNBQVMsQ0FBQyxDQUFBO29CQUNuRCxDQUFDLEdBQUcsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsR0FBRyxDQUFDLENBQUMsRUFBRSxFQUFFLEVBQUUsU0FBUyxDQUFDLENBQUE7b0JBQ2xELENBQUMsR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxFQUFFLEVBQUUsRUFBRSxDQUFDLFVBQVUsQ0FBQyxDQUFBO29CQUNwRCxDQUFDLEdBQUcsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsR0FBRyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxTQUFTLENBQUMsQ0FBQTtvQkFDbEQsQ0FBQyxHQUFHLEdBQUcsQ0FBQyxLQUFLLENBQUMsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLEVBQUUsRUFBRSxFQUFFLFVBQVUsQ0FBQyxDQUFBO29CQUNuRCxDQUFDLEdBQUcsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsR0FBRyxDQUFDLENBQUMsRUFBRSxFQUFFLEVBQUUsQ0FBQyxVQUFVLENBQUMsQ0FBQTtvQkFDcEQsQ0FBQyxHQUFHLEdBQUcsQ0FBQyxLQUFLLENBQUMsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLEVBQUUsRUFBRSxFQUFFLENBQUMsUUFBUSxDQUFDLENBQUE7b0JBQ2xELENBQUMsR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxFQUFFLENBQUMsRUFBRSxVQUFVLENBQUMsQ0FBQTtvQkFDbEQsQ0FBQyxHQUFHLEdBQUcsQ0FBQyxLQUFLLENBQUMsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLEVBQUUsRUFBRSxFQUFFLENBQUMsVUFBVSxDQUFDLENBQUE7b0JBQ3BELENBQUMsR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxHQUFHLEVBQUUsQ0FBQyxFQUFFLEVBQUUsRUFBRSxDQUFDLEtBQUssQ0FBQyxDQUFBO29CQUNoRCxDQUFDLEdBQUcsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsR0FBRyxFQUFFLENBQUMsRUFBRSxFQUFFLEVBQUUsQ0FBQyxVQUFVLENBQUMsQ0FBQTtvQkFDckQsQ0FBQyxHQUFHLEdBQUcsQ0FBQyxLQUFLLENBQUMsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLEdBQUcsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLFVBQVUsQ0FBQyxDQUFBO29CQUNuRCxDQUFDLEdBQUcsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsR0FBRyxFQUFFLENBQUMsRUFBRSxFQUFFLEVBQUUsQ0FBQyxRQUFRLENBQUMsQ0FBQTtvQkFDbkQsQ0FBQyxHQUFHLEdBQUcsQ0FBQyxLQUFLLENBQUMsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLEdBQUcsRUFBRSxDQUFDLEVBQUUsRUFBRSxFQUFFLENBQUMsVUFBVSxDQUFDLENBQUE7b0JBQ3JELENBQUMsR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxHQUFHLEVBQUUsQ0FBQyxFQUFFLEVBQUUsRUFBRSxVQUFVLENBQUMsQ0FBQTtvQkFFcEQsQ0FBQyxHQUFHLEdBQUcsQ0FBQyxLQUFLLENBQUMsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsU0FBUyxDQUFDLENBQUE7b0JBQ2xELENBQUMsR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLFVBQVUsQ0FBQyxDQUFBO29CQUNuRCxDQUFDLEdBQUcsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsR0FBRyxFQUFFLENBQUMsRUFBRSxFQUFFLEVBQUUsU0FBUyxDQUFDLENBQUE7b0JBQ25ELENBQUMsR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxDQUFDLEVBQUUsRUFBRSxFQUFFLENBQUMsU0FBUyxDQUFDLENBQUE7b0JBQy9DLENBQUMsR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLFNBQVMsQ0FBQyxDQUFBO29CQUNsRCxDQUFDLEdBQUcsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsR0FBRyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsUUFBUSxDQUFDLENBQUE7b0JBQ2pELENBQUMsR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxHQUFHLEVBQUUsQ0FBQyxFQUFFLEVBQUUsRUFBRSxDQUFDLFNBQVMsQ0FBQyxDQUFBO29CQUNwRCxDQUFDLEdBQUcsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsR0FBRyxDQUFDLENBQUMsRUFBRSxFQUFFLEVBQUUsQ0FBQyxTQUFTLENBQUMsQ0FBQTtvQkFDbkQsQ0FBQyxHQUFHLEdBQUcsQ0FBQyxLQUFLLENBQUMsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLFNBQVMsQ0FBQyxDQUFBO29CQUNqRCxDQUFDLEdBQUcsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsR0FBRyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxVQUFVLENBQUMsQ0FBQTtvQkFDcEQsQ0FBQyxHQUFHLEdBQUcsQ0FBQyxLQUFLLENBQUMsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLEVBQUUsRUFBRSxFQUFFLENBQUMsU0FBUyxDQUFDLENBQUE7b0JBQ25ELENBQUMsR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxFQUFFLEVBQUUsRUFBRSxVQUFVLENBQUMsQ0FBQTtvQkFDbkQsQ0FBQyxHQUFHLEdBQUcsQ0FBQyxLQUFLLENBQUMsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLEdBQUcsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsVUFBVSxDQUFDLENBQUE7b0JBQ3BELENBQUMsR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLFFBQVEsQ0FBQyxDQUFBO29CQUNqRCxDQUFDLEdBQUcsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsR0FBRyxDQUFDLENBQUMsRUFBRSxFQUFFLEVBQUUsVUFBVSxDQUFDLENBQUE7b0JBQ25ELENBQUMsR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxHQUFHLEVBQUUsQ0FBQyxFQUFFLEVBQUUsRUFBRSxDQUFDLFVBQVUsQ0FBQyxDQUFBO29CQUVyRCxDQUFDLEdBQUcsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsR0FBRyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxNQUFNLENBQUMsQ0FBQTtvQkFDL0MsQ0FBQyxHQUFHLEdBQUcsQ0FBQyxLQUFLLENBQUMsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLEVBQUUsRUFBRSxFQUFFLENBQUMsVUFBVSxDQUFDLENBQUE7b0JBQ3BELENBQUMsR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxHQUFHLEVBQUUsQ0FBQyxFQUFFLEVBQUUsRUFBRSxVQUFVLENBQUMsQ0FBQTtvQkFDcEQsQ0FBQyxHQUFHLEdBQUcsQ0FBQyxLQUFLLENBQUMsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLEdBQUcsRUFBRSxDQUFDLEVBQUUsRUFBRSxFQUFFLENBQUMsUUFBUSxDQUFDLENBQUE7b0JBQ25ELENBQUMsR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLFVBQVUsQ0FBQyxDQUFBO29CQUNuRCxDQUFDLEdBQUcsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsR0FBRyxDQUFDLENBQUMsRUFBRSxFQUFFLEVBQUUsVUFBVSxDQUFDLENBQUE7b0JBQ25ELENBQUMsR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxFQUFFLEVBQUUsRUFBRSxDQUFDLFNBQVMsQ0FBQyxDQUFBO29CQUNuRCxDQUFDLEdBQUcsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsR0FBRyxFQUFFLENBQUMsRUFBRSxFQUFFLEVBQUUsQ0FBQyxVQUFVLENBQUMsQ0FBQTtvQkFDckQsQ0FBQyxHQUFHLEdBQUcsQ0FBQyxLQUFLLENBQUMsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLEdBQUcsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLFNBQVMsQ0FBQyxDQUFBO29CQUNsRCxDQUFDLEdBQUcsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsQ0FBQyxFQUFFLEVBQUUsRUFBRSxDQUFDLFNBQVMsQ0FBQyxDQUFBO29CQUMvQyxDQUFDLEdBQUcsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsR0FBRyxDQUFDLENBQUMsRUFBRSxFQUFFLEVBQUUsQ0FBQyxTQUFTLENBQUMsQ0FBQTtvQkFDbkQsQ0FBQyxHQUFHLEdBQUcsQ0FBQyxLQUFLLENBQUMsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLEVBQUUsRUFBRSxFQUFFLFFBQVEsQ0FBQyxDQUFBO29CQUNqRCxDQUFDLEdBQUcsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsR0FBRyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxTQUFTLENBQUMsQ0FBQTtvQkFDbEQsQ0FBQyxHQUFHLEdBQUcsQ0FBQyxLQUFLLENBQUMsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLEdBQUcsRUFBRSxDQUFDLEVBQUUsRUFBRSxFQUFFLENBQUMsU0FBUyxDQUFDLENBQUE7b0JBQ3BELENBQUMsR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxHQUFHLEVBQUUsQ0FBQyxFQUFFLEVBQUUsRUFBRSxTQUFTLENBQUMsQ0FBQTtvQkFDbkQsQ0FBQyxHQUFHLEdBQUcsQ0FBQyxLQUFLLENBQUMsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLEVBQUUsRUFBRSxFQUFFLENBQUMsU0FBUyxDQUFDLENBQUE7b0JBRW5ELENBQUMsR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsU0FBUyxDQUFDLENBQUE7b0JBQzlDLENBQUMsR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxFQUFFLEVBQUUsRUFBRSxVQUFVLENBQUMsQ0FBQTtvQkFDbkQsQ0FBQyxHQUFHLEdBQUcsQ0FBQyxLQUFLLENBQUMsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLEdBQUcsRUFBRSxDQUFDLEVBQUUsRUFBRSxFQUFFLENBQUMsVUFBVSxDQUFDLENBQUE7b0JBQ3JELENBQUMsR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxFQUFFLEVBQUUsRUFBRSxDQUFDLFFBQVEsQ0FBQyxDQUFBO29CQUNsRCxDQUFDLEdBQUcsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsR0FBRyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsVUFBVSxDQUFDLENBQUE7b0JBQ25ELENBQUMsR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxFQUFFLEVBQUUsRUFBRSxDQUFDLFVBQVUsQ0FBQyxDQUFBO29CQUNwRCxDQUFDLEdBQUcsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsR0FBRyxFQUFFLENBQUMsRUFBRSxFQUFFLEVBQUUsQ0FBQyxPQUFPLENBQUMsQ0FBQTtvQkFDbEQsQ0FBQyxHQUFHLEdBQUcsQ0FBQyxLQUFLLENBQUMsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLEVBQUUsRUFBRSxFQUFFLENBQUMsVUFBVSxDQUFDLENBQUE7b0JBQ3BELENBQUMsR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxFQUFFLENBQUMsRUFBRSxVQUFVLENBQUMsQ0FBQTtvQkFDbEQsQ0FBQyxHQUFHLEdBQUcsQ0FBQyxLQUFLLENBQUMsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLEdBQUcsRUFBRSxDQUFDLEVBQUUsRUFBRSxFQUFFLENBQUMsUUFBUSxDQUFDLENBQUE7b0JBQ25ELENBQUMsR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxFQUFFLEVBQUUsRUFBRSxDQUFDLFVBQVUsQ0FBQyxDQUFBO29CQUNwRCxDQUFDLEdBQUcsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsR0FBRyxFQUFFLENBQUMsRUFBRSxFQUFFLEVBQUUsVUFBVSxDQUFDLENBQUE7b0JBQ3BELENBQUMsR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLFNBQVMsQ0FBQyxDQUFBO29CQUNsRCxDQUFDLEdBQUcsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsR0FBRyxFQUFFLENBQUMsRUFBRSxFQUFFLEVBQUUsQ0FBQyxVQUFVLENBQUMsQ0FBQTtvQkFDckQsQ0FBQyxHQUFHLEdBQUcsQ0FBQyxLQUFLLENBQUMsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLEVBQUUsRUFBRSxFQUFFLFNBQVMsQ0FBQyxDQUFBO29CQUNsRCxDQUFDLEdBQUcsR0FBRyxDQUFDLEtBQUssQ0FB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QUFDLENBQUMsQ0FBQTtvQkFDekUsSUFBSSxDQUFDLEtBQUssQ0FBQyxRQUFRLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxLQUFLLEVBQUMsSUFBSSxDQUFDLFlBQVksQ0FBQyxDQUFDLENBQUMsR0FBRyxFQUFFLENBQUMsQ0FBQyxHQUFHLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxLQUFLLEdBQUcsQ0FBQyxHQUFHLE1BQU0sQ0FBQyxDQUFDLEVBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxNQUFNLEdBQUcsQ0FBQyxHQUFHLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFBO29CQUM1SixJQUFJLENBQUMsV0FBVyxHQUFHLElBQUksQ0FBQTtpQkFFMUI7Z0JBRUQsSUFBRyxJQUFJLENBQUMsZUFBZSxJQUFJLElBQUksQ0FBQyxlQUFlLENBQUMsQ0FBQyxDQUFDLEVBQUM7b0JBQy9DLElBQUksQ0FBQyxVQUFVLEdBQUcsSUFBSSxDQUFBO29CQUN0QixJQUFJLENBQUMsS0FBSyxHQUFHLElBQUksSUFBSSxDQUFDLE1BQU0sRUFBRSxDQUFBO29CQUM5QixJQUFJLEtBQUssR0FBRyxJQUFJLElBQUksQ0FBQyxLQUFLLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsQ0FBQTtvQkFDNUMsSUFBSSxDQUFDLEtBQUssQ0FBQyxJQUFJLEdBQUcsS0FBSyxDQUFBO29CQUN2QixJQUFJLENBQUMsS0FBSyxDQUFDLEtBQUssR0FBRyxHQUFHLENBQUE7b0JBQ3RCLElBQUksQ0FBQyxLQUFLLENBQUMsS0FBSyxDQUFDLEtBQUssQ0FBQyxLQUFLLEdBQUcsQ0FBQyxFQUFDLEtBQUssQ0FBQyxNQUFNLEdBQUcsQ0FBQyxDQUFDLENBQUE7b0JBQ2xELElBQUksQ0FBQyxNQUFNLENBQUMsUUFBUSxDQUFDLElBQUksQ0FBQyxLQUFLLENBQUMsR0FBRyxDQUFDLEtBQUssQ0FBQyxLQUFLLEdBQUcsQ0FBQyxFQUFDLEtBQUssQ0FBQyxNQUFNLEdBQUcs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QUUsQ0FBQyxHQUFHLE1BQU0sQ0FBQyxNQUFNLEVBQUUsQ0FBQyxFQUFFLEVBQUU7b0JBQ3BDLElBQUksQ0FBQyxHQUFHLENBQUMsRUFBRTt3QkFDUCxJQUFNLEVBQUUsR0FBRyxNQUFNLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFBO3dCQUN4QixJQUFNLEVBQUUsR0FBRyxNQUFNLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLGFBQWEsQ0FBQTt3QkFDdEMsSUFBTSxFQUFFLEdBQUcsTUFBTSxDQUFDLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxhQUFhLENBQUE7d0JBQ3RDLElBQU0sRUFBRSxHQUFHLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQTt3QkFDcEIsSUFBTSxLQUFLLEdBQUcsSUFBSSxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxHQUFHLEVBQUUsQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsR0FBRyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsR0FBRyxFQUFFLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsR0FBRyxhQUFhLENBQUMsQ0FBQTt3QkFDM0csSUFBTSxJQUFJLEdBQUcsR0FBRyxHQUFHLEtBQUssQ0FBQTt3QkFDeEIsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFBO3dCQUNULEtBQUssSUFBSSxDQUFDLEdBQUcsQ0FBQyxFQUFFLENBQUMsR0FBRyxLQUFLLEVBQUUsQ0FBQyxFQUFFLEVBQUU7NEJBQzVCLElBQUksQ0FBQyxHQUFXLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLEdBQUcsRUFBRSxDQUFDLENBQUMsR0FBRyxDQUFDLEdBQUcsRUFBRSxDQUFDLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFD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b0JBQUUsT0FBTyxDQUFDLENBQUM7Z0JBQUMsSUFBSSxDQUFDLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDLElBQUksQ0FBQztvQkFBRSxPQUFPLENBQUMsR0FBRyxDQUFDLENBQUM7Z0JBQUMsSUFBSSxDQUFDLENBQUM7b0JBQUUsQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLEVBQUUsR0FBRyxHQUFHLENBQUMsQ0FBQztnQkFDdEYsSUFBSSxDQUFDLEdBQUcsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsRUFBRTtvQkFBRSxDQUFDLEdBQUcsQ0FBQyxDQUFDO29CQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLENBQUM7aUJBQUU7O29CQUN6QyxJQUFJLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxDQUFDLEdBQUcsSUFBSSxDQUFDLEVBQUUsQ0FBQyxHQUFHLElBQUksQ0FBQyxJQUFJLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDO2dCQUNsRCxJQUFJLENBQUMsR0FBRyxDQUFDO29CQUFFLE9BQU8sQ0FBQyxFQUFFLEdBQUcsQ0FBQyxDQUFDLEdBQUcsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDLEVBQUUsRUFBRSxHQUFHLENBQUMsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLEdBQUcsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLEdBQUcsSUFBSSxDQUFDLEVBQUUsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDO2dCQUN6RyxPQUFPLENBQUMsR0FBRyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsR0FBRyxDQUFDLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxHQUFHLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxHQUFHLElBQUksQ0FBQyxFQUFFLENB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