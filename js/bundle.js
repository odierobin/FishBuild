var __extends = (this && this.__extends) || (function () {
    var extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-28 15:58:34
 * @Last Modified by: ZZL
 * @Last Modified time: 2019-07-15 17:27:33
 */
Object.defineProperty(exports, "__esModule", { value: true });
var SoundManager = Laya.SoundManager;
const GameConstant_1 = require("../GameConstant");
const GameSettings_1 = require("../GameSettings");
const GameCenter_1 = require("./GameCenter");
class AudioManager {
    constructor() {
        this._music = false;
        this._sound = false;
        this._vibr = false;
        AudioManager.instance = this;
        if (Laya.LocalStorage.getItem(GameConstant_1.default.LOCALSTORAGEKEY.MUSIC)) {
            this._music = Laya.LocalStorage.getItem(GameConstant_1.default.LOCALSTORAGEKEY.MUSIC) == '1';
        }
        else {
            this.music = true;
        }
        if (Laya.LocalStorage.getItem(GameConstant_1.default.LOCALSTORAGEKEY.SOUND)) {
            this._sound = Laya.LocalStorage.getItem(GameConstant_1.default.LOCALSTORAGEKEY.SOUND) == '1';
        }
        else {
            this.sound = true;
        }
        if (Laya.LocalStorage.getItem(GameConstant_1.default.LOCALSTORAGEKEY.VIBR)) {
            this._vibr = Laya.LocalStorage.getItem(GameConstant_1.default.LOCALSTORAGEKEY.VIBR) == '1';
        }
        else {
            this.vibr = true;
        }
    }
    get music() {
        return this._music;
    }
    set music(m) {
        this._music = m;
        Laya.LocalStorage.setItem(GameConstant_1.default.LOCALSTORAGEKEY.MUSIC, this._music ? '1' : '0');
        if (this._music) {
            SoundManager.playMusic(GameSettings_1.default.musicList[GameConstant_1.default.MUSICTYPE.BGM], 0);
        }
        else {
            SoundManager.stopMusic();
        }
    }
    get sound() {
        return this._sound;
    }
    set sound(s) {
        this._sound = s;
        Laya.LocalStorage.setItem(GameConstant_1.default.LOCALSTORAGEKEY.SOUND, this._sound ? '1' : '0');
        if (!this._sound) {
            SoundManager.stopAllSound();
        }
    }
    get vibr() {
        return this._vibr;
    }
    set vibr(v) {
        this._vibr = v;
        Laya.LocalStorage.setItem(GameConstant_1.default.LOCALSTORAGEKEY.VIBR, this._vibr ? '1' : '0');
    }
    playSound(sound) {
        if (this._sound) {
            SoundManager.playSound(GameSettings_1.default.musicList[sound], 1);
        }
    }
    playMusic(music = null) {
        if (this._music) {
            music = music ? GameConstant_1.default.MUSICTYPE.BGM : music;
            SoundManager.playMusic(GameSettings_1.default.musicList[music]);
        }
    }
    playVibr(duration, delay = 0, duration2 = 0) {
        if (this._vibr) {
            if (navigator.vibrate) {
                if (delay > 0) {
                    navigator.vibrate([duration, delay, duration2]);
                }
                else {
                    navigator.vibrate(duration);
                }
            }
            else {
                // console.log('不支持震动')
                if (GameSettings_1.default.platType == GameConstant_1.default.PLATTYPE.WECHAT) {
                    GameCenter_1.default.instance.platform.vibrateLong();
                }
            }
        }
    }
}
exports.default = AudioManager;
},{"../GameConstant":10,"../GameSettings":11,"./GameCenter":3}],2:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-28 16:28:25
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-07-05 20:02:50
 */
Object.defineProperty(exports, "__esModule", { value: true });
const GameSettings_1 = require("../GameSettings");
class FireStatus {
    /**
     * 构造函数
     */
    constructor() {
        /**
         * 内部RAGE标记
         */
        this._rage = false;
        /**
         * 内部LOCK标记
         */
        this._lock = false;
        /**
         * 内部AUTO标记
         */
        this._auto = false;
        /**
         * 内部DIAMONDGUN标记
         */
        this._diamond = false;
        /**
         * 内部普通射速标记
         */
        this._normalRate = 8;
        /**
         * 内部自动射速标记
         */
        this._autoRate = 8;
        /**
         * 内部RAGE射速标记
         * 增加的射速
         */
        this._rageRate = 2;
        /**
         * 内部总射速标记
         */
        this._rate = 8;
        /**
         * 内部子弹速度标记
         */
        this._speed = 5;
        /**
         * 炮台的一发消耗
         */
        this._costRatio = 1;
        /**
         * 是否禁止射击
         */
        this._hold = false;
        /**
         * 指定子弹数
         */
        this._bulletCountDown = 0;
        this._pos = new Laya.Point(540, 960);
        this._yScale = Laya.stage.height / 1920;
        this._speed = GameSettings_1.default.bulletDefaultSpeed;
    }
    /**
     * 外部获取是否RAGE
     */
    get rage() {
        return this._rage;
    }
    /**
     * 外部设置RAGE
     */
    set rage(r) {
        this._rage = r;
        this.countRate();
    }
    /**
     * 外部获取是否LOCK
     */
    get lock() {
        return this._lock;
    }
    /**
     * 外部设置LOCK
     */
    set lock(l) {
        this._lock = l;
    }
    /**
     * 外部获取是否AUTO
     */
    get auto() {
        return this._auto;
    }
    /**
     * 外部设置AUTO
     */
    set auto(a) {
        this._auto = a;
        this.countRate();
    }
    /**
     * 外部获取是否DIAMONDGUN
     */
    get diamond() {
        return this._diamond;
    }
    /**
     * 外部设置DIAMONDGUN
     */
    set diamond(d) {
        this._diamond = d;
        this.countRate();
    }
    /**
     * 外部获取子弹速度
     */
    get speed() {
        return this._speed;
    }
    /**
     * 外部获取射速
     */
    get rate() {
        return this._rate;
    }
    /**
     * 外部获取位置
     */
    get pos() {
        return new Laya.Point(this._pos.x, this._pos.y / this._yScale);
    }
    /**
     * 外部获取是否射击
     */
    get hold() {
        return this._hold;
    }
    /**
     * 外部设置是否射击
     */
    set hold(h) {
        this._hold = h;
    }
    /**
     * 设置当前目标位置
     */
    setPos(x, y) {
        this._pos = new Laya.Point(x, y);
    }
    /**
     * 设置基础射速
     */
    setRate(battery) {
        this._normalRate = battery.normalRate;
        this._autoRate = battery.autoRate;
        this._rageRate = battery.rageRate;
        this._speed = battery.bulletSpeed;
        this.countRate();
    }
    /**
     * 内部计算射速
     */
    countRate() {
        this._rate = this._auto
            ? this._rage
                ? this._autoRate + this._rageRate
                : this._autoRate
            : this._rage
                ? this._normalRate + this._rageRate
                : this._normalRate;
    }
    /**
     * 外部获取指定子弹数
     */
    get bulletCountDown() {
        return this._bulletCountDown;
    }
    /**
     * 外部设置指定子弹数
     */
    set bulletCountDown(b) {
        this._bulletCountDown = b;
    }
    /**
     * 消耗指定子弹数
     */
    fireCountDownBullet() {
        this._bulletCountDown = Math.max(0, this._bulletCountDown - 1);
        return this._bulletCountDown;
    }
}
exports.default = FireStatus;
},{"../GameSettings":11}],3:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-28 15:58:40
 * @Last Modified by: ZZL
 * @Last Modified time: 2019-12-18 14:38:06
 */
Object.defineProperty(exports, "__esModule", { value: true });
const TarsisHttp_1 = require("../utils/TarsisHttp");
const GameConstant_1 = require("../GameConstant");
const FishControl_1 = require("../element/FishControl");
const GameSettings_1 = require("../GameSettings");
const StatusCenter_1 = require("./StatusCenter");
const FireStatus_1 = require("./FireStatus");
const AudioManager_1 = require("./AudioManager");
const Tarsis_1 = require("../utils/Tarsis");
const IntentControl_1 = require("./IntentControl");
class GameCenter {
    constructor() {
        this.inviteId = null;
        this.loginInfo = null;
        this.nowUser = {};
        this.nowEnemy = {};
        this.fishList = [];
        this.nowFishIdIndex = 0;
        this.nowBulletIdIndex = 0;
        this.nowMissionTargetFishIdList = [];
        this.nowMissionBulletCount = 0;
        this.nowMissionBulletDic = [];
        this.userBulletCount = 0;
        this.nowMissionHitFishCount = 1;
        this.missionList = null;
        this.missionData = null;
        this.aquaManRankInfo = {
            info: [],
            self: null,
            desc: null
        };
        this.nowActiveScene = 'scene/Loading.scene';
        this.dropTargetHolderList = [];
        GameCenter.instance = this;
        this.nowFishIdIndex = Math.floor(Math.random() * GameSettings_1.default.maxFishId / 2);
        this.nowBulletIdIndex = Math.floor(Math.random() * GameSettings_1.default.maxBulletId / 2);
        this.status = new StatusCenter_1.default();
        this.fireStatus = new FireStatus_1.default();
        const audio = new AudioManager_1.default;
        this.audio = AudioManager_1.default.instance;
    }
    isNowUserHasBattery(batteryId) {
        let result = false;
        this.nowUser.batteryList.forEach(element => {
            if (`${element.batteryid}` == `${batteryId}`) {
                result = true;
            }
        });
        return result;
    }
    getUserItemCount(itemType) {
        let count = 0;
        this.nowUser.propList.forEach(element => {
            if (element.id == itemType) {
                count = parseInt(element.cnt);
            }
        });
        return count;
    }
    changeScene(type, callback = null) {
        switch (type) {
            case GameConstant_1.default.SCENETYPE.GAME:
                Laya.Scene.open("scene/MainGame.json", true, null, Laya.Handler.create(this, () => {
                    this.nowActiveScene = 'scene/MainGame.json';
                    if (callback) {
                        callback();
                    }
                }));
                break;
            case GameConstant_1.default.SCENETYPE.LOADING:
                Laya.View.open('scene/Loading.scene', true, null, Laya.Handler.create(this, () => {
                    this.nowActiveScene = 'scene/Loading.scene';
                    if (callback) {
                        callback();
                    }
                }));
                break;
        }
        this.nowScene = type;
    }
    registComponent(type, component, action = null) {
        switch (type) {
            case GameConstant_1.default.GAMECOMPONENT.MAINBG:
                if (this.nowScene == GameConstant_1.default.SCENETYPE.LOADING) {
                    const bg = component;
                    bg.stopMove();
                }
                break;
            case GameConstant_1.default.GAMECOMPONENT.TOUCH:
                this.touch = component;
                if (action) {
                    action(this.fireStatus, Laya.Handler.create(this, this.onTouchAction, null, false));
                }
                break;
            case GameConstant_1.default.GAMECOMPONENT.ROBOTINFO:
                this.robot = component;
                this.dropTargetHolderList.push(component);
                if (action) {
                    action();
                }
                this.msgOut({
                    type: GameConstant_1.default.MESSAGETYPE.ROBOTCONFIG
                });
                break;
            case GameConstant_1.default.GAMECOMPONENT.USERINFO:
                this.userInfoZone = component;
                this.dropTargetHolderList.push(component);
                if (GameSettings_1.default.isAquamanRankOpen) {
                    this.userInfoZone.setAquaManRank(this.aquaManRankInfo.self.seq);
                }
                this.userInfoZone.setAquaManRank(this.aquaManRankInfo.self.seq);
                if (action) {
                    action(Laya.Handler.create(this, this.onUserAction, null, false));
                }
                if (GameSettings_1.default.isMissionOpen) {
                    this.msgOut({
                        type: GameConstant_1.default.MESSAGETYPE.MISSIONINIT
                    });
                }
                if (GameSettings_1.default.isNewbeeOpen) {
                    if (!this.nowUser.isNewUser) {
                        this.status.isOnNewbee = false;
                        this.checkVersion();
                    }
                    else {
                        this.status.setLoading(true, {
                            text: '载入引导界面....'
                        });
                        Laya.View.open(GameSettings_1.default.sceneViewList.NEWBEE, false, null, Laya.Handler.create(this, (s) => {
                            this.status.setLoading(false);
                        }));
                    }
                }
                else {
                    this.status.isOnNewbee = false;
                    this.checkVersion();
                }
                break;
            case GameConstant_1.default.GAMECOMPONENT.USERSHIP:
                this.userShip = component;
                if (action) {
                    action();
                }
                break;
            case GameConstant_1.default.GAMECOMPONENT.ROBOTSHIP:
                this.robotShip = component;
                if (action) {
                    action();
                }
                break;
            case GameConstant_1.default.GAMECOMPONENT.FISHMANAGER:
                this.fishManager = component;
                if (action) {
                    action();
                }
                break;
            case GameConstant_1.default.GAMECOMPONENT.SHOP:
                this.shop = component;
                if (action) {
                    action(Laya.Handler.create(this, this.onUserAction, null, false));
                }
                break;
            case GameConstant_1.default.GAMECOMPONENT.REDPACKSHOP:
                this.redPackShop = component;
                if (action) {
                    action(Laya.Handler.create(this, this.onUserAction, null, false));
                }
                break;
            case GameConstant_1.default.GAMECOMPONENT.SYSTEMMENU:
                this.menu = component;
                this.dropTargetHolderList.push(component);
                window['menu'] = component;
                if (action) {
                    action(Laya.Handler.create(this, this.onUserAction, null, false));
                }
                break;
            case GameConstant_1.default.GAMECOMPONENT.ENEMYINFO:
                if (action) {
                    action(() => { return this.nowEnemy; }, this.getOutsideImage);
                }
                break;
            case GameConstant_1.default.GAMECOMPONENT.DROP:
                this.drop = component;
                if (action) {
                    action(Laya.Handler.create(this, this.onUserAction, null, false));
                }
                break;
            case GameConstant_1.default.GAMECOMPONENT.MISSION:
                this.mission = component;
                if (action) {
                    action(Laya.Handler.create(this, this.onUserAction, null, false));
                }
                this.mission.MissionList = this.missionList;
                this.mission.MissionData = this.missionData;
                break;
            case GameConstant_1.default.GAMECOMPONENT.POPUP:
                this.popup = component;
                if (action) {
                    action(Laya.Handler.create(this, this.onUserAction, null, false));
                }
                break;
            case GameConstant_1.default.GAMECOMPONENT.COUNTDOWN:
                this.countdown = component;
                if (action) {
                    action(Laya.Handler.create(this, this.onUserAction, null, false));
                }
                break;
            case GameConstant_1.default.GAMECOMPONENT.NEWBEE:
                this.newbee = component;
                if (action) {
                    action(Laya.Handler.create(this, this.onUserAction, null, false));
                }
                break;
            case GameConstant_1.default.GAMECOMPONENT.AQUAMAN:
                this.aquaman = component;
                if (action) {
                    action(Laya.Handler.create(this, this.onUserAction, null, false));
                }
                break;
            case GameConstant_1.default.GAMECOMPONENT.SHARENEW:
                this.share = component;
                if (action) {
                    action(Laya.Handler.create(this, this.onUserAction, null, false));
                }
                break;
            case GameConstant_1.default.GAMECOMPONENT.RECHARGEACTIVITY:
                this.rechargeActivity = component;
                if (action) {
                    action(Laya.Handler.create(this, this.onUserAction, null, false));
                }
                break;
        }
    }
    onTouchAction(actionType, params = null) {
        switch (actionType) {
            case GameConstant_1.default.TOUCHACTIONTYPE.ROTATE:
                this.userShipRotate(params.x, params.y);
                this.fireStatus.setPos(params.x, params.y);
                break;
            case GameConstant_1.default.TOUCHACTIONTYPE.FIRE:
                this.userFireOnce();
                break;
            case GameConstant_1.default.TOUCHACTIONTYPE.LOCK:
                console.log("Touch cause LOCK ");
                break;
        }
    }
    loadViewByNeed(type, callback) {
        switch (type) {
            case GameConstant_1.default.GAMECOMPONENT.SHOP:
                if (this.shop) {
                    callback();
                }
                else {
                    this.status.setLoading(true, {
                        text: '载入商城....'
                    });
                    Laya.View.open(GameSettings_1.default.sceneViewList.Shop, false, null, Laya.Handler.create(this, (s) => {
                        this.status.setLoading(false);
                        callback();
                    }));
                }
                break;
            case GameConstant_1.default.GAMECOMPONENT.REDPACKSHOP:
                if (this.redPackShop) {
                    callback();
                }
                else {
                    this.status.setLoading(true, {
                        text: '载入红包商城....'
                    });
                    Laya.View.open(GameSettings_1.default.sceneViewList.RedPackShop, false, null, Laya.Handler.create(this, (s) => {
                        this.status.setLoading(false);
                        callback();
                    }));
                }
                break;
            case GameConstant_1.default.GAMECOMPONENT.MISSION:
                if (this.mission) {
                    callback();
                }
                else {
                    this.status.setLoading(true, {
                        text: '载入任务界面....'
                    });
                    Laya.View.open(GameSettings_1.default.sceneViewList.Mission, false, null, Laya.Handler.create(this, (s) => {
                        this.status.setLoading(false);
                        callback();
                        GameSettings_1.default.sceneViewList.MissonAddon.forEach((element) => {
                            Laya.View.open(element, false, null, Laya.Handler.create(this, (s) => { }));
                        });
                    }));
                }
                break;
            case GameConstant_1.default.GAMECOMPONENT.POPUP:
                if (this.popup) {
                    callback();
                }
                else {
                    this.status.setLoading(true, {
                        text: '载入弹出界面....'
                    });
                    Laya.View.open(GameSettings_1.default.sceneViewList.POPUP, false, null, Laya.Handler.create(this, (s) => {
                        this.status.setLoading(false);
                        callback();
                    }));
                }
                break;
            case GameConstant_1.default.GAMECOMPONENT.AQUAMAN:
                if (this.aquaman) {
                    callback();
                }
                else {
                    this.status.setLoading(true, {
                        text: '载入海王排行榜....'
                    });
                    Laya.View.open(GameSettings_1.default.sceneViewList.AQUAMAN, false, null, Laya.Handler.create(this, (s) => {
                        this.status.setLoading(false);
                        callback();
                    }));
                }
                break;
            case GameConstant_1.default.GAMECOMPONENT.SHARENEW:
                if (this.share) {
                    callback();
                }
                else {
                    this.status.setLoading(true, {
                        text: '载入分享奖励....'
                    });
                    Laya.View.open(GameSettings_1.default.sceneViewList.SHARENEW, false, null, Laya.Handler.create(this, (s) => {
                        this.status.setLoading(false);
                        callback();
                    }));
                }
                break;
            case GameConstant_1.default.GAMECOMPONENT.RECHARGEACTIVITY:
                if (this.rechargeActivity) {
                    callback();
                }
                else {
                    this.status.setLoading(true, {
                        text: '载入活动页....'
                    });
                    Laya.View.open(GameSettings_1.default.sceneViewList.RechargeActivity, false, null, Laya.Handler.create(this, (s) => {
                        this.status.setLoading(false);
                        callback();
                    }));
                }
                break;
        }
    }
    onUserAction(actionType, params = null) {
        switch (actionType) {
            case GameConstant_1.default.USERACTIONTYPE.USERINFOCOIN:
                this.loadViewByNeed(GameConstant_1.default.GAMECOMPONENT.SHOP, () => {
                    this.status.openShop(GameConstant_1.default.SHOPTYPE.COIN);
                });
                break;
            case GameConstant_1.default.USERACTIONTYPE.USERINFODIAMOND:
                this.loadViewByNeed(GameConstant_1.default.GAMECOMPONENT.SHOP, () => {
                    this.status.openShop(GameConstant_1.default.SHOPTYPE.DIAMOND);
                });
                break;
            case GameConstant_1.default.USERACTIONTYPE.USERINFOVIP:
                this.loadViewByNeed(GameConstant_1.default.GAMECOMPONENT.SHOP, () => {
                    this.status.openShop(GameConstant_1.default.SHOPTYPE.VIP);
                });
                break;
            case GameConstant_1.default.USERACTIONTYPE.GUNVALUEPLUS:
                this.msgOut({
                    type: GameConstant_1.default.MESSAGETYPE.GUNVALUEEXCHANGE,
                    oper: GameConstant_1.default.USERGUNVALUECHANGETYPE.PLUS
                });
                break;
            case GameConstant_1.default.USERACTIONTYPE.GUNVALUEMINUS:
                this.msgOut({
                    type: GameConstant_1.default.MESSAGETYPE.GUNVALUEEXCHANGE,
                    oper: GameConstant_1.default.USERGUNVALUECHANGETYPE.MINUS
                });
                break;
            case GameConstant_1.default.USERACTIONTYPE.USERINFOREDPACK:
                this.loadViewByNeed(GameConstant_1.default.GAMECOMPONENT.REDPACKSHOP, () => {
                    this.status.openRedPackShop();
                });
                break;
            case GameConstant_1.default.USERACTIONTYPE.CHANGESHOPTYPE:
                this.status.setShop(params);
                break;
            case GameConstant_1.default.USERACTIONTYPE.CLOSESHOP:
                this.status.closeShop();
                break;
            case GameConstant_1.default.USERACTIONTYPE.CHANGEREDPACKSHOPTYPE:
                this.status.setRedPackShop(params);
                break;
            case GameConstant_1.default.USERACTIONTYPE.CLOSEREDPACKSHOP:
                this.status.closeRedPackShop();
                break;
            case GameConstant_1.default.USERACTIONTYPE.SWITCHBATTERY:
                this.msgOut({
                    type: GameConstant_1.default.MESSAGETYPE.BATTERYEQUIPT,
                    battery_id: params
                });
                break;
            case GameConstant_1.default.USERACTIONTYPE.MISSON:
                this.loadViewByNeed(GameConstant_1.default.GAMECOMPONENT.MISSION, () => {
                    this.status.isOnCoving = true;
                    this.mission.setShow(true);
                });
                break;
            case GameConstant_1.default.USERACTIONTYPE.SKILLSWITCH:
                console.log(`user swith skill with ${params}`);
                switch (params) {
                    case GameConstant_1.default.SKILLSWITCHTYPE.AUTO:
                        this.fireStatus.auto = !this.fireStatus.auto;
                        break;
                    case GameConstant_1.default.SKILLSWITCHTYPE.RAGE:
                        this.msgOut({
                            type: GameConstant_1.default.MESSAGETYPE.SKLLSWITCH,
                            skill_type: GameConstant_1.default.SKILLSWITCHTYPE.RAGE,
                            switch: !this.fireStatus.rage ? 1 : 0
                        });
                        break;
                    case GameConstant_1.default.SKILLSWITCHTYPE.RAGECOOLDOWN:
                        this.fireStatus.rage = false;
                        Laya.timer.once(1000, this, () => {
                            this.msgOut({
                                type: GameConstant_1.default.MESSAGETYPE.SKLLSWITCH,
                                skill_type: GameConstant_1.default.SKILLSWITCHTYPE.RAGE,
                                switch: 1
                            });
                        });
                        break;
                }
                break;
            case GameConstant_1.default.USERACTIONTYPE.GRANDREWARD:
                console.log(`user open grand reward`);
                break;
            case GameConstant_1.default.USERACTIONTYPE.COLLECTIONDROPITEM:
                this.userGetItem(params.id, params.count);
                break;
            case GameConstant_1.default.USERACTIONTYPE.CLOSEMISSION:
                this.status.isOnCoving = false;
                this.mission.setShow(false);
                break;
            case GameConstant_1.default.USERACTIONTYPE.MISSIONSTART:
                this.msgOut({
                    type: GameConstant_1.default.MESSAGETYPE.MISSIONSTART
                });
                break;
            case GameConstant_1.default.USERACTIONTYPE.MISSIONRECBIGPRIZE:
                this.msgOut({
                    type: GameConstant_1.default.MESSAGETYPE.MISSIOBIGPRIZE
                });
                break;
            case GameConstant_1.default.USERACTIONTYPE.MUSIC:
                this.audio.music = !params;
                break;
            case GameConstant_1.default.USERACTIONTYPE.SOUND:
                this.audio.sound = !params;
                break;
            case GameConstant_1.default.USERACTIONTYPE.VIBR:
                this.audio.vibr = !params;
                break;
            case GameConstant_1.default.USERACTIONTYPE.USERVIPREC:
                this.msgOut({
                    type: GameConstant_1.default.MESSAGETYPE.VIPREC
                });
                break;
            case GameConstant_1.default.USERACTIONTYPE.REDPACKPURCH:
                switch (params.goodsType) {
                    case GameConstant_1.default.SHOPGOODSTYPE.REDPACK:
                        this.msgOut({
                            type: GameConstant_1.default.MESSAGETYPE.REDPACKETREC,
                            rec_id: params.id
                        });
                        break;
                    default:
                        // GameConstant.SHOPGOODSTYPE.REDPACKCOIN
                        // GameConstant.SHOPGOODSTYPE.REDPACKVIP
                        this.msgOut({
                            type: GameConstant_1.default.MESSAGETYPE.PAYREDPACKET,
                            goods_id: params.id
                        });
                        break;
                }
                break;
            case GameConstant_1.default.USERACTIONTYPE.SHOPPURCH:
                console.log(`SHOP PURCH ::  ${JSON.stringify(params)}`);
                //#popup
                let param = {
                    type: GameConstant_1.default.POPUPTYPE.REDPACKSHOPTIP,
                    isTouchClose: true
                };
                this.loadViewByNeed(GameConstant_1.default.GAMECOMPONENT.POPUP, () => {
                    this.status.setPopup(param);
                });
                switch (params.goodsType) {
                    case GameConstant_1.default.SHOPGOODSTYPE.COIN:
                        this.msgOut({
                            type: GameConstant_1.default.MESSAGETYPE.PAYDIAMOND,
                            goods_id: params.id
                        });
                        break;
                    case GameConstant_1.default.SHOPGOODSTYPE.DIAMOND:
                        //TODO: 支付流程
                        switch (GameSettings_1.default.platType) {
                            case GameConstant_1.default.PLATTYPE.NATIVE:
                                break;
                            case GameConstant_1.default.PLATTYPE.WECHAT:
                                this.msgOut({
                                    type: GameConstant_1.default.MESSAGETYPE.PAY,
                                    goods_id: params.id
                                });
                                break;
                            case GameConstant_1.default.PLATTYPE.BAIDU:
                                this.msgOut({
                                    type: GameConstant_1.default.MESSAGETYPE.BAIDUORDER,
                                    goods_id: params.id
                                });
                                break;
                            case GameConstant_1.default.PLATTYPE.NATIVEANDROID:
                                this.status.setLoading(true);
                                const addres = `${GameSettings_1.default.nativeChargeAddres}?gameType=p001&gameid=${this.nowUser.uid}&goodsid=${params.id}&body=${params.value}钻石&mid=${GameSettings_1.default.channelId}`;
                                IntentControl_1.default.openUrl(addres);
                                break;
                            case GameConstant_1.default.PLATTYPE.NATIVEIOS:
                                this.status.setLoading(true);
                                IntentControl_1.default.iosPay(params.goodsId);
                                break;
                        }
                        break;
                }
                break;
            case GameConstant_1.default.USERACTIONTYPE.NEWBEE:
                this.checkVersion();
                break;
            case GameConstant_1.default.USERACTIONTYPE.AQUAMANRANK:
                this.loadViewByNeed(GameConstant_1.default.GAMECOMPONENT.AQUAMAN, () => {
                    this.status.openAquaMan(this.aquaManRankInfo);
                });
                break;
            case GameConstant_1.default.USERACTIONTYPE.CLOSEAQUAMANRANK:
                this.status.closeAquaMan();
                break;
            case GameConstant_1.default.USERACTIONTYPE.OPENSHARENEW:
                this.loadViewByNeed(GameConstant_1.default.GAMECOMPONENT.SHARENEW, () => {
                    this.msgOut({
                        type: GameConstant_1.default.MESSAGETYPE.INVITENEWINFO
                    });
                    this.status.openShare();
                });
                break;
            case GameConstant_1.default.USERACTIONTYPE.SHARENEW:
                this.platform.shareAppMessage({
                    title: '仅需邀请10人！日赚5000轻松简单！',
                    imageUrl: 'https://xiazai.shycgame.com/share-img/share_05.jpg',
                    query: "inviteId=" + this.nowUser.uid
                });
                break;
            case GameConstant_1.default.USERACTIONTYPE.SHANRNEWREC:
                this.msgOut({
                    type: GameConstant_1.default.MESSAGETYPE.INVITENEWREC
                });
                break;
        }
    }
    checkPayResult(data) {
        console.log(`Native Pay Result : ${data}`);
        if (GameSettings_1.default.isNative) {
            if (GameSettings_1.default.isNativeAndroid) {
                const resultJson = JSON.stringify(data);
                const resultStr = JSON.parse(resultJson);
                let desc = `支付成功，请关注数据变化。`;
                if (resultStr.result != 0) {
                    desc = resultStr.message;
                }
                this.status.setAlert({
                    desc: desc
                });
            }
            if (GameSettings_1.default.isNativeIos) {
                this.msgOut({
                    type: GameConstant_1.default.MESSAGETYPE.IOSPAYCHECK,
                    data: data
                });
            }
        }
    }
    fireNewbeeBullet() {
        this.userBulletCount += 1;
        this.userShip.fireOnce(GameConstant_1.default.NEWBEEINFO.bulletID);
    }
    userFireOnce() {
        if (this.fireStatus.hold) {
            return;
        }
        if (this.status.isOnMission && this.fireStatus.bulletCountDown == 0) {
            return;
        }
        if (!this.status.isOnMission && this.userBulletCount > GameSettings_1.default.userMaxBulletCount) {
            return;
        }
        if (this.userShip) {
            if (this.isBulletEnough()) {
                const bulletId = this.getBulletId();
                this.userBulletCount += 1;
                this.userShip.fireOnce(bulletId);
                const pos = this.fireStatus.pos;
                this.msgOut({
                    type: GameConstant_1.default.MESSAGETYPE.USERSHOOT,
                    bullet_id: bulletId,
                    dir: `[${pos.x.toFixed(2)},${pos.y.toFixed(2)}]`
                });
                if (this.status.isOnMission) {
                    this.fireStatus.fireCountDownBullet();
                    this.nowMissionBulletDic[bulletId] = true;
                }
            }
            else {
                // this.loadViewByNeed(GameConstant.GAMECOMPONENT.SHOP,()=>{
                //     this.status.openShop(GameConstant.SHOPTYPE.COIN)
                // })
                this.msgOut({
                    type: GameConstant_1.default.MESSAGETYPE.SHARE
                });
                this.fireStatus.auto = false;
            }
        }
    }
    userShipRotate(x, y) {
        if (this.userShip) {
            this.userShip.rotate(x, y);
        }
    }
    addFish(fishId, fishType, sprite, isTargetFish = false, drop = null) {
        this.fishList[fishId] = {
            type: fishType,
            sprite: sprite,
            drop: drop
        };
        if (isTargetFish) {
            this.nowMissionTargetFishIdList.push(fishId);
        }
    }
    setMissionInfoCount(bulletCount, hitCount) {
        this.nowMissionBulletCount = bulletCount;
        this.nowMissionHitFishCount = hitCount;
        // 清空子弹记录
        this.nowMissionBulletDic = [];
        // 禁止射击
        this.fireStatus.hold = true;
        // 关闭自动
        this.fireStatus.auto = false;
        // 如果狂暴，关闭狂暴
        if (this.fireStatus.rage) {
            this.msgOut({
                type: GameConstant_1.default.MESSAGETYPE.SKLLSWITCH,
                skill_type: GameConstant_1.default.SKILLSWITCHTYPE.RAGE,
                switch: 0
            });
        }
        // 设置基础炮
        // this.userShip.setBattery('1')
        this.msgOut({
            type: GameConstant_1.default.MESSAGETYPE.BATTERYEQUIPT,
            battery_id: 1
        });
        // 设置任务标记
        this.status.setMission({
            duration: 15 * 1000,
            callback: () => {
                this.msgOut({
                    type: GameConstant_1.default.MESSAGETYPE.MISSIONSPECIALEND,
                    state: 0
                });
            },
            countDown: 5 * 1000,
            startCallback: () => {
                this.fireStatus.hold = false;
                this.nowMissionBulletCount = bulletCount;
            }
        });
    }
    removeFish(fishId) {
        if (this.fishList[fishId]) {
            const drop = this.fishList[fishId].drop;
            if (drop) {
                drop.removeSelf();
            }
            delete this.fishList[fishId];
        }
    }
    checkVersion() {
        //console.log("GameSettings.nowVersionInfo:",GameSettings.nowVersionInfo)
        //console.log("Laya.LocalStorage.getItem(GameConstant.LOCALSTORAGEKEY.VERSIONINFO):",Laya.LocalStorage.getItem(GameConstant.LOCALSTORAGEKEY.VERSIONINFO))
        //-----------------------------bate------------------------------------
        if (Laya.LocalStorage.getItem(GameConstant_1.default.LOCALSTORAGEKEY.VERSIONINFO) == null) {
            GameConstant_1.default.LOCALSTORAGEKEY.VERSIONINFO = "2.07";
        }
        if (GameSettings_1.default.nowVersionInfo && Laya.LocalStorage.getItem(GameConstant_1.default.LOCALSTORAGEKEY.VERSIONINFO) != GameSettings_1.default.nowVersionStr) {
            //TODO 显示版本信息
            let param = {
                versionInfo: GameSettings_1.default.nowVersionInfo,
                type: GameConstant_1.default.POPUPTYPE.VERSIONINFO,
                isTouchClose: false
            };
            this.loadViewByNeed(GameConstant_1.default.GAMECOMPONENT.POPUP, () => {
                this.status.setPopup(param);
            });
            Laya.LocalStorage.setItem(GameConstant_1.default.LOCALSTORAGEKEY.VERSIONINFO, GameSettings_1.default.nowVersionStr);
        }
        this.status.setLoading(true, {
            text: '载入敌方....'
        });
        Laya.View.open(GameSettings_1.default.sceneViewList.RobotUI, false, null, Laya.Handler.create(this, (s) => {
            this.status.setLoading(false);
        }));
    }
    speedUpFish(isMission = false) {
        const fishIdList = Object.keys(this.fishList);
        for (let index = 0; index < fishIdList.length; index++) {
            const element = this.fishList[fishIdList[index]];
            if (element) {
                const fc = element.sprite.getComponent(FishControl_1.default);
                if (fc && !fc.isDead) {
                    fc.speedUp(isMission);
                }
            }
        }
    }
    getFish(fishId) {
        return this.fishList[fishId] ? this.fishList[fishId].sprite : null;
    }
    getFishId() {
        this.nowFishIdIndex += 1;
        if (this.nowFishIdIndex >= GameSettings_1.default.maxFishId) {
            this.nowFishIdIndex = 0;
        }
        return `F-${this.nowFishIdIndex}`;
    }
    getBulletId() {
        this.nowBulletIdIndex += 1;
        if (this.nowBulletIdIndex >= GameSettings_1.default.maxBulletId) {
            this.nowBulletIdIndex = 0;
        }
        return `B-${this.nowBulletIdIndex}`;
    }
    checkHit(param) {
        let setting = Object.assign({ multiHit: false, checkRadius: 0, report: false, bulletId: '', isBullet: true }, param);
        let arr = [];
        let index = 0;
        let isNewbeeFish = false;
        for (let index = 0; index < Object.keys(this.fishList).length; index++) {
            const element = this.fishList[Object.keys(this.fishList)[index]];
            const fc = element.sprite.getComponent(FishControl_1.default);
            if (fc && !fc.isDead) {
                if (element.sprite.hitTestPoint(setting.x, setting.y)) {
                    if (fc.fishId == GameConstant_1.default.NEWBEEINFO.fishID) {
                        isNewbeeFish = true;
                        fc.playDead();
                        let itemList = [];
                        itemList.push({ id: GameConstant_1.default.ITEMTYPE.REDPACK, desc: this.newbee.redCount });
                        itemList.push({ id: GameConstant_1.default.ITEMTYPE.COIN, desc: GameSettings_1.default.coinDropSetting[this.newbee.coinCount] });
                        let startPoint = new Laya.Point(Laya.stage.width / 2, Laya.stage.height / 2);
                        this.drop.flyItems(itemList, startPoint);
                        this.drop.onFishDead(fc.fishType, this.newbee.coinCount, startPoint);
                        //this.nowUser.redPacketCnt = 0
                        this.nowUser.coin = this.newbee.coinCount;
                        this.newbee.waitFunction();
                    }
                    else {
                        if (this.status.isOnMission && this.nowMissionBulletDic[param.bulletId]) {
                            this.nowMissionBulletCount -= 1;
                            delete this.nowMissionBulletDic[param.bulletId];
                            let ishitMissionFish = false;
                            this.nowMissionTargetFishIdList.forEach(element => {
                                if (fc.fishId == element) {
                                    ishitMissionFish = true;
                                    this.nowMissionHitFishCount -= 1;
                                    fc.playDead();
                                    if (this.nowMissionHitFishCount <= 0) {
                                        console.log("MISSIONSPECIAL_END0");
                                        this.status.isOnMission = false;
                                        this.msgOut({
                                            type: GameConstant_1.default.MESSAGETYPE.MISSIONSPECIALEND,
                                            state: 1
                                        });
                                    }
                                }
                            });
                            if (!ishitMissionFish) {
                                if (this.nowMissionBulletCount <= 0 || (this.nowMissionHitFishCount > this.nowMissionBulletCount)) {
                                    console.log("MISSIONSPECIAL_END1");
                                    this.status.isOnMission = false;
                                    this.msgOut({
                                        type: GameConstant_1.default.MESSAGETYPE.MISSIONSPECIALEND,
                                        state: 0
                                    });
                                }
                            }
                        }
                    }
                    arr.push(fc);
                }
                else if (setting.multiHit && setting.checkRadius > 0) {
                    if (element.sprite.hitTestPoint(setting.x + setting.checkRadius, setting.y)
                        || element.sprite.hitTestPoint(setting.x - setting.checkRadius, setting.y)
                        || element.sprite.hitTestPoint(setting.x, setting.y + setting.checkRadius)
                        || element.sprite.hitTestPoint(setting.x, setting.y - setting.checkRadius)
                        || Math.sqrt((element.sprite.x - setting.x) * (element.sprite.x - setting.x) + (element.sprite.y - setting.y) * (element.sprite.y - setting.y)) <= setting.checkRadius) {
                        arr.push(fc);
                    }
                }
                if (this.status.isOnMission || isNewbeeFish) {
                    setting.report = false;
                }
                else if (setting.isBullet) {
                    this.userBulletCount = Math.max(0, this.userBulletCount - 1);
                }
                // if(!setting.multiHit){
                //     break
                // }
            }
        }
        if (setting.report && arr.length > 0) {
            if (setting.bulletId.indexOf("robot") != -1) {
                this.robot.checkHit(arr);
            }
            else {
                let types = [];
                let ids = [];
                arr.forEach(element => {
                    types.push(`${element.fishType}`);
                    ids.push(`${element.fishId}`);
                });
                this.msgOut({
                    type: GameConstant_1.default.MESSAGETYPE.USERHIT,
                    bullet_id: setting.bulletId,
                    fish_types: types.join('|'),
                    fish_ids: ids.join('|')
                });
            }
        }
        return arr;
    }
    msgOut(msg) {
        this.postOffice.sendMessage(msg);
    }
    retryServerLogin() {
        const _this = this;
        this.platform.login({
            success: (res) => {
                _this.serverLogin(res.code, this.loginInfo.nickName, this.loginInfo.avatar, this.loginInfo.openId);
            }
        });
        // this.serverLogin(this.loginInfo.code,this.loginInfo.nickName,this.loginInfo.avatar)
    }
    serverLogin(code, nickName, avatar, openId = '', unionId = '') {
        if (GameSettings_1.default.isSendTrack) {
            this.sendTrace({
                eventId: GameConstant_1.default.TRACKEVENTID.LOGIN
            });
        }
        this.loginInfo = {
            code: code,
            nickName: nickName,
            avatar: avatar,
            openId: openId,
            unionId: unionId
        };
        if (GameSettings_1.default.isCenterHttp) {
            this.status.setLoading(true, { text: '正在登录中心服务器' });
            TarsisHttp_1.default.StartHttpCall({
                url: GameSettings_1.default.centerHttpAddr,
                data: {
                    version: Math.ceil(GameSettings_1.default.nowVersion * 100),
                    time: new Date().getTime()
                },
                onSuccess: (data) => {
                    const result = JSON.parse(data);
                    if (result.code == 200) {
                        GameSettings_1.default.serverSocket = result.info.webSocket;
                        this.socketLogin(code, nickName, avatar, openId, unionId);
                    }
                    else {
                        console.log(`HTTP Responsed : ${result.code} :: ${result.msg}`);
                        this.status.setAlert({
                            sureCallback: () => {
                                this.retryServerLogin();
                            }, desc: result.msg
                        });
                    }
                },
                onError: (e) => {
                    this.status.setAlert({
                        sureCallback: () => {
                            this.retryServerLogin();
                        }, desc: GameConstant_1.default.PROMOTIONTEXT.LOGINFAIL
                    });
                }
            });
        }
        else {
            this.socketLogin(code, nickName, avatar, openId, unionId);
        }
    }
    socketLogin(code, nickName, avatar, openId, unionId) {
        this.status.setLoading(true, { text: '正在登录游戏服务器' });
        Laya.timer.loop(1000, this, this.checkLoginStatus);
        const inviteId = this.inviteId;
        console.log(`[GameCenter][INVITE] inivite Id is ${inviteId}`);
        this.postOffice.startNet(() => {
            this.msgOut({
                type: GameConstant_1.default.MESSAGETYPE.AUTH,
                code: code,
                nick_name: nickName,
                img_url: avatar,
                unionid: unionId,
                openid: openId,
                invite_uid: inviteId
            });
        }, (msg) => {
            this.dealPostMessage(msg);
        }, (e) => {
            this.status.setLoading(false);
        }, () => {
            this.status.isOnOffline = true;
            this.status.reset();
            this.fireStatus.auto = false;
            this.status.setAlert({
                sureCallback: () => {
                    this.retryServerLogin();
                }, desc: GameConstant_1.default.PROMOTIONTEXT.OFFLINE
            });
        });
    }
    sendTrace(info) {
        let uuid = Laya.LocalStorage.getItem(GameConstant_1.default.LOCALSTORAGEKEY.UUID);
        if (!uuid) {
            uuid = Tarsis_1.default.uuid();
            Laya.LocalStorage.setItem(GameConstant_1.default.LOCALSTORAGEKEY.UUID, uuid);
            Laya.LocalStorage.setItem(GameConstant_1.default.LOCALSTORAGEKEY.NICKNAME, `Captain-${uuid.substr(0, 8)}`);
        }
        const data = Object.assign({ ver: GameSettings_1.default.nowVersionStr, eventId: GameConstant_1.default.TRACKEVENTID.START, gameId: '1', guid: uuid, currentTime: Tarsis_1.default.FormatDate('yyyy-MM-dd HH:mm:ss') }, info);
        TarsisHttp_1.default.StartHttpCall({
            url: GameSettings_1.default.trackAddress,
            data: data
        });
    }
    dealPostMessage(msg) {
        // if(msg.type != GameConstant.MESSAGETYPE.BARRAGE){
        //     console.log(msg)
        // }
        switch (msg.type) {
            case GameConstant_1.default.MESSAGETYPE.AUTH:
                if (msg.status == "0") {
                    this.status.isUserLogin = true;
                }
                else {
                    // this.showAlert(msg.desc)
                    this.status.setAlert({
                        sureCallback: () => {
                            this.retryServerLogin();
                        }, desc: GameConstant_1.default.PROMOTIONTEXT.LOGINFAIL
                    });
                }
                break;
            case GameConstant_1.default.MESSAGETYPE.USERDATA:
                this.nowUser = JSON.parse(msg.user_jsonData);
                this.status.isGotUserData = true;
                this.setBattery(this.nowUser.curBatteryid);
                this.msgOut({
                    type: GameConstant_1.default.MESSAGETYPE.SYSTEMCONFIG
                });
                if (GameSettings_1.default.isSendTrack) {
                    this.sendTrace({
                        eventId: GameConstant_1.default.TRACKEVENTID.LOGINDONE,
                        uid: this.nowUser.uid
                    });
                    GameSettings_1.default.isSendTrack = false;
                    Laya.LocalStorage.setItem(GameConstant_1.default.LOCALSTORAGEKEY.TRACE, GameConstant_1.default.TRACKEVENTID.LOGINDONE);
                }
                break;
            case GameConstant_1.default.MESSAGETYPE.UPDATEUSERBATTERYLIST:
                if (msg.user_id == this.nowUser.uid) {
                    this.nowUser.batteryList = JSON.parse(msg.user_batteryData);
                }
                break;
            case GameConstant_1.default.MESSAGETYPE.UPDATECOIN:
                if (msg.user_id == this.nowUser.uid) {
                    this.nowUser.coin = msg.coin;
                }
                break;
            case GameConstant_1.default.MESSAGETYPE.UPDATEDIAMOND:
                if (msg.user_id == this.nowUser.uid) {
                    this.nowUser.diamond = msg.diamond;
                }
                break;
            case GameConstant_1.default.MESSAGETYPE.UPDATELEVEL:
                // add_hp: "153"
                // exp_cur: "11903.58"
                // exp_max: "11903.58"
                // lv: "4"
                // type: "update_lv"
                // uid: "40""40"
                // unclock_batteryLv: "100"
                if (msg.uid == this.nowUser.uid) {
                    if (this.nowUser.lv != msg.lv) {
                        let param = {
                            levelUpInfo: msg,
                            isTouchClose: false,
                            type: GameConstant_1.default.POPUPTYPE.LEVELUP
                        };
                        this.loadViewByNeed(GameConstant_1.default.GAMECOMPONENT.POPUP, () => {
                            this.status.setPopup(param);
                        });
                        //this.popup.setShow(true,GameConstant.POPUPTYPE.LEVELUP,msg)
                    }
                    this.nowUser.lv = msg.lv;
                    //exp_cur,exp_max 未使用
                }
                break;
            case GameConstant_1.default.MESSAGETYPE.SYSTEMCONFIG:
                this.status.isGotSystemConfig = true;
                GameSettings_1.default.isBarrageOpen = msg.barrage_switch == '1';
                GameSettings_1.default.isMissionOpen = msg.mi_switch == '1';
                GameSettings_1.default.isBuyBatteryOpen = msg.buy_battery_lv_switch == "1";
                GameSettings_1.default.isRealPay = msg.is_realPay == '1';
                GameSettings_1.default.isShareNewOpen = msg.invite_new_switch == '1';
                GameSettings_1.default.itemInfo = JSON.parse(msg.prop_info);
                GameSettings_1.default.missionPrize = msg.mi_total_prize;
                GameSettings_1.default.IOSshopLabel = msg.ios_pay_msg.split(',');
                GameSettings_1.default.supportBatteryList = JSON.parse(msg.support_battery);
                GameSettings_1.default.isAquamanRankOpen = msg.aqua_man_rank_switch == '1';
                this.aquaManRankInfo.desc = msg.aqua_man_rank_desc || '';
                break;
            case GameConstant_1.default.MESSAGETYPE.UPDATEUSERBATTERYID:
                if (msg.user_id == this.nowUser.uid) {
                    this.setBattery(msg.user_equipBatid);
                    if (msg.time != '-1') {
                        this.userInfoZone.setFreeBatteryEquip(msg.user_equipBatid, parseInt(msg.time));
                    }
                }
                break;
            case GameConstant_1.default.MESSAGETYPE.GUNVALUEEXCHANGE:
                if (msg.status == '-2' && GameSettings_1.default.isBuyBatteryOpen && msg.costDiamond > 0) { //
                    //提示用户可以购买炮台等级
                    this.status.setAlert({
                        title: `购买炮台`,
                        desc: `是否消耗${msg.costDiamond}钻石，提升一级炮台等级?`,
                        suerText: '购买',
                        needCancel: true,
                        sureCallback: () => {
                            this.msgOut({ type: GameConstant_1.default.MESSAGETYPE.BUYBATTERYLV });
                        }
                    });
                }
                else if (msg.status != '0') {
                    this.status.setAlert({
                        desc: msg.desc
                    });
                }
                break;
            // case GameConstant.MESSAGETYPE.BATTERYEQUIPT:
            //     if(msg.status != '0'){
            //         this.status.setAlert({
            //             desc:msg.desc
            //         })
            //     }
            //     break
            case GameConstant_1.default.MESSAGETYPE.UPDATEGUNVALUE:
                if (msg.user_id == this.nowUser.uid) {
                    this.nowUser.curBatteryLv = msg.battery_lv;
                }
                break;
            case GameConstant_1.default.MESSAGETYPE.BARRAGE:
                let barrageInfo = msg.info;
                let speed = 2;
                switch (parseInt(msg.barrage_type)) {
                    case GameConstant_1.default.BARRAGETYPE.USERGOTREDPACK:
                        barrageInfo = `恭喜玩家&nbsp;<span style="color:#00ff00">${msg.nick_name}</span>&nbsp;获得&nbsp;<span style="color:#ff0000">${msg.cnt}</span>&nbsp;个红包`;
                        speed = 4;
                        break;
                    case GameConstant_1.default.BARRAGETYPE.SYSTEM:
                        break;
                    case GameConstant_1.default.BARRAGETYPE.PK:
                        break;
                    case GameConstant_1.default.BARRAGETYPE.CUSTOM:
                        break;
                }
                this.status.setBarrage({
                    text: barrageInfo,
                    speed: speed
                });
                break;
            case GameConstant_1.default.MESSAGETYPE.UPDATEVIPINFO:
                this.nowUser.vip = parseInt(msg.vip);
                this.nowUser.sumRecharge = parseInt(msg.sumRecharge);
                //TODO: vip更新消息增加最低领取值
                this.nowUser.minVipRec = parseInt(msg.minVipRec);
                //ENDTODO
                break;
            case GameConstant_1.default.MESSAGETYPE.VIPREC:
                if (msg.status == "0") {
                    const prize = JSON.parse(msg.prize);
                    this.status.setGetItem({
                        itemList: prize
                    });
                    prize.forEach(element => {
                        if (element.id == GameConstant_1.default.ITEMTYPE.RAGE) {
                            this.userGetItem(element.id, parseInt(element.desc));
                        }
                    });
                }
                else {
                    this.status.setAlert({
                        desc: msg.desc
                    });
                }
                //vipList
                break;
            case GameConstant_1.default.MESSAGETYPE.USERHIT:
                if (this.fishList[msg.fish_id]) {
                    const fc = this.fishList[msg.fish_id].sprite.getComponent(FishControl_1.default);
                    fc.playDead();
                    const itemList = JSON.parse(msg.fish_item);
                    let fish = this.getFish(msg.fish_id);
                    if (fish) {
                        const point = new Laya.Point(fish.x, fish.y);
                        itemList.push({ id: GameConstant_1.default.ITEMTYPE.COIN, desc: GameSettings_1.default.coinDropSetting[msg.fish_type] });
                        this.drop.flyItems(itemList, point);
                        this.drop.onFishDead(msg.fish_type, msg.fish_coin, point);
                    }
                }
                break;
            case GameConstant_1.default.MESSAGETYPE.SKLLSWITCH:
                const result = `${msg.switch}` == '1';
                if (msg.status == '0') {
                    switch (parseInt(msg.skill_type)) {
                        case GameConstant_1.default.SKILLSWITCHTYPE.RAGE:
                            if (result) {
                                this.userCostItem(GameConstant_1.default.ITEMTYPE.RAGE);
                            }
                            this.fireStatus.rage = result;
                            break;
                    }
                }
                else {
                    // console.log(`Try to swith ${result ? 'on' : 'off'} on skill [${msg.skill_type}] fail with desc : ${msg.desc}`)
                    this.status.setAlert({
                        desc: msg.desc
                    });
                }
                break;
            case GameConstant_1.default.MESSAGETYPE.MISSIONINIT:
                if (this.robot) {
                    this.robot.visible = false;
                }
                this.missionList = JSON.parse(msg.info);
                if (this.mission) {
                    this.mission.MissionList = this.missionList;
                }
                this.msgOut({
                    type: GameConstant_1.default.MESSAGETYPE.MISSIONUPDATE
                });
                break;
            case GameConstant_1.default.MESSAGETYPE.MISSIONUPDATE:
                this.missionData = JSON.parse(msg.info);
                if ((this.missionData.mainState == 1 && this.missionData.miState > 0) || (this.missionData.mainState == 2 && this.missionData.miState == 0)) {
                    this.status.missionViewState = 0;
                }
                else if (this.missionData.mainState == 3) {
                    this.status.missionViewState = 2;
                }
                else if (this.missionData.mainState == 5) {
                    this.status.missionViewState = 3;
                }
                if (this.status.isUserServerLoginDone) {
                    if (this.mission) {
                        this.mission.MissionData = this.missionData;
                    }
                    this.userInfoZone.setMission(this.missionData, this.getMission());
                }
                break;
            case GameConstant_1.default.MESSAGETYPE.MISSIONPROGRESS:
                this.missionData.progress = msg.cnt;
                if (this.mission) {
                    this.mission.MissionData.progress = msg.cnt;
                }
                this.userInfoZone.setMission(this.missionData, this.getMission());
                break;
            case GameConstant_1.default.MESSAGETYPE.MISSIONSTART:
                if (msg.status == '0') {
                }
                break;
            case GameConstant_1.default.MESSAGETYPE.MISSIONSPECIALEND:
                this.status.isOnMission = false;
                this.status.isOnCountDown = false;
                this.robot.isActivate = true;
                if (msg.status == '0') {
                    let param = {
                        isTouchClose: true,
                        type: msg.state == "1" ? GameConstant_1.default.POPUPTYPE.MISSIONSUCCESS : GameConstant_1.default.POPUPTYPE.MISSIONFIAL,
                        onClose: () => {
                            this.status.isOnPopup = false;
                        }
                    };
                    this.loadViewByNeed(GameConstant_1.default.GAMECOMPONENT.POPUP, () => {
                        this.status.setPopup(param);
                    });
                }
                break;
            case GameConstant_1.default.MESSAGETYPE.MISSIOBIGPRIZE:
                if (msg.status == '0') {
                    this.status.setGetItem({
                        type: 0, itemList: [
                            { "id": "REDPACKET", "desc": msg.prize }
                        ], autoClose: 4
                    });
                }
                break;
            case GameConstant_1.default.MESSAGETYPE.PAYREDPACKET:
                if (msg.status == '0') {
                    this.userCostItem(GameConstant_1.default.ITEMTYPE.REDPACK, parseInt(msg.use_redPack));
                }
                this.status.setAlert({
                    desc: msg.status == '0' ? '兑换成功' : msg.desc
                });
                break;
            case GameConstant_1.default.MESSAGETYPE.REDPACKETREC:
                //this.nowUser.redPacketCnt = parseInt(msg.cur_redPacket)
                this.status.setAlert({
                    desc: msg.status == '0' ? '兑换成功' : msg.desc,
                    sureCallback: () => {
                        const _this = this;
                        if (msg.status == '-2') {
                            _this.status.closeRedPackShop();
                            this.loadViewByNeed(GameConstant_1.default.GAMECOMPONENT.SHOP, () => {
                                _this.status.openShop(GameConstant_1.default.SHOPTYPE.VIP);
                            });
                        }
                    }
                });
                break;
            case GameConstant_1.default.MESSAGETYPE.PAYDIAMOND:
                this.status.setAlert({
                    desc: msg.status == '0' ? '兑换成功' : msg.desc
                });
                break;
            case GameConstant_1.default.MESSAGETYPE.BAIDUORDER:
                break;
            case GameConstant_1.default.MESSAGETYPE.SHARE:
                if (msg.is_show == 0) {
                    this.loadViewByNeed(GameConstant_1.default.GAMECOMPONENT.SHOP, () => {
                        this.status.openShop(GameConstant_1.default.SHOPTYPE.DIAMOND);
                    });
                    let param = {
                        type: GameConstant_1.default.POPUPTYPE.REDPACKSHOPTIP,
                        isTouchClose: true
                    };
                    this.loadViewByNeed(GameConstant_1.default.GAMECOMPONENT.POPUP, () => {
                        this.status.setPopup(param);
                    });
                }
                else if (msg.is_show == 2) {
                    this.loadViewByNeed(GameConstant_1.default.GAMECOMPONENT.SHOP, () => {
                        this.status.openShop(GameConstant_1.default.SHOPTYPE.COIN);
                    });
                }
                else {
                    let param = {
                        JIUJIBI_Info: msg,
                        isTouchClose: msg.is_show == 3 ? true : false,
                        type: GameConstant_1.default.POPUPTYPE.JIUJIBI,
                        onClose: () => {
                            if (msg.is_show == 1) {
                                this.msgOut({
                                    type: GameConstant_1.default.MESSAGETYPE.SHAREREC,
                                    share_type: 2
                                });
                                this.status.isOnPopup = false;
                            }
                        }
                    };
                    this.loadViewByNeed(GameConstant_1.default.GAMECOMPONENT.POPUP, () => {
                        this.status.setPopup(param);
                    });
                }
                break;
            case GameConstant_1.default.MESSAGETYPE.SHAREREC:
                this.status.setAlert({
                    desc: msg.status == '0' ? '领取成功' : msg.desc
                });
                break;
            case GameConstant_1.default.MESSAGETYPE.PAY:
                switch (GameSettings_1.default.platType) {
                    case GameConstant_1.default.PLATTYPE.NATIVE:
                        break;
                    case GameConstant_1.default.PLATTYPE.WECHAT:
                        if (msg.status == 0) {
                            this.status.setAlert({
                                desc: msg.status == '0' ? '充值成功' : msg.desc,
                                sureCallback: () => {
                                    if (GameSettings_1.default.isShareNewOpen) {
                                        this.showInviteIntro();
                                    }
                                }
                            });
                        }
                        else if (msg.status == -50) {
                            let num = null;
                            GameSettings_1.default.diamondGoods.forEach(element => {
                                if (element.id == msg.goods_id) {
                                    num = element.price * 10;
                                }
                            });
                            const _this = this;
                            this.platform.requestMidasPayment(Object.assign(Object.assign({ buyQuantity: num }, GameSettings_1.default.wxPayParam), { success: function (res) {
                                }, fail: function (res) {
                                }, complete: function (res) {
                                    if (res.errCode) {
                                        if (res.errCode == 1) {
                                            return;
                                        }
                                    }
                                    if (res.errMsg) {
                                        if (res.errMsg.match("ok") == "ok") {
                                            //instance.send(instance.SendType.wx_smPay, instance.payIndex);
                                            _this.msgOut({
                                                type: GameConstant_1.default.MESSAGETYPE.PAY,
                                                goods_id: msg.goods_id
                                            });
                                        }
                                    }
                                } }));
                        }
                        else {
                            this.status.setAlert({
                                desc: msg.status == '0' ? '充值异常' : msg.desc
                            });
                        }
                        break;
                    case GameConstant_1.default.PLATTYPE.BAIDU:
                        this.status.setAlert({
                            desc: msg.status == '0' ? '充值成功' : msg.desc
                        });
                        break;
                }
                break;
            case GameConstant_1.default.MESSAGETYPE.IOSPAYCHECK:
                this.status.setAlert({
                    desc: msg.status == '0' ? '购买成功' : msg.desc
                });
                break;
            case GameConstant_1.default.MESSAGETYPE.ROBOTCONFIG:
                var data = JSON.parse(msg.robotConfig);
                let setting = this.robot.robotSetting;
                setting.lvDiff = data.lvDiff;
                setting.changeGunAngleInterval = data.angleTime;
                setting.batteryData = data.battery.split('|');
                setting.coinRuleData = data.coin.split('|');
                setting.exchangeBatteryAngleRate = data.exchangeBatteryAngleRate;
                setting.exchangeRobotTime = data.exchangeRobotTime;
                setting.shootTimeData = data.shootTime.split('-');
                this.robot.robotFishDaedRate = JSON.parse(msg.fishRate);
                this.robot.robotBatteryLvList = JSON.parse(msg.batteryConfig);
                this.robot.setRobotInfo();
                break;
            case GameConstant_1.default.MESSAGETYPE.AQUAMANRANKLIST:
                this.aquaManRankInfo.info = JSON.parse(msg.info);
                this.aquaManRankInfo.self = JSON.parse(msg.myInfo);
                if (this.userInfoZone) {
                    this.userInfoZone.setAquaManRank(this.aquaManRankInfo.self.seq);
                }
                if (GameSettings_1.default.isAquamanRankOpen && this.status.isUserServerLoginDone) {
                    Laya.timer.once(GameSettings_1.default.aquaManRankDuration, this, () => {
                        this.msgOut({
                            type: GameConstant_1.default.MESSAGETYPE.AQUAMANRANKLIST
                        });
                    });
                }
                break;
            case GameConstant_1.default.MESSAGETYPE.AQUAMANRANKPRIZE:
                console.log(`SHOW RANK PRIZE WITH REDPACK : ${msg.prize}`);
                let param = {
                    seq: msg.seq,
                    redPack: msg.prize,
                    type: GameConstant_1.default.POPUPTYPE.AQUAMANPRIZE,
                    callBack: () => {
                        // this.msgOut({type:GameConstant.MESSAGETYPE.AQUAMANRANKPRIZEREC})
                        this.status.setAlert({
                            desc: `领取成功，红包数${msg.prize}`
                        });
                        this.userGetItem(GameConstant_1.default.ITEMTYPE.REDPACK, parseInt(msg.prize));
                    }
                };
                this.loadViewByNeed(GameConstant_1.default.GAMECOMPONENT.POPUP, () => {
                    this.status.setPopup(param);
                });
                break;
            case GameConstant_1.default.MESSAGETYPE.AQUAMANRANKPRIZEREC:
                this.status.setAlert({
                    desc: msg.status == '0' ? `领取成功，红包数${msg.prize}` : msg.desc
                });
                break;
            case GameConstant_1.default.MESSAGETYPE.INVITENEWINFO:
                if (msg.status == '0') {
                    const list = JSON.parse(msg.info);
                    const prize = msg.prize;
                    // list item type 
                    // uid	string	用户id	
                    // nick	string	昵称	
                    // proxyLv	int	代理等级	0
                    // redPack	int	红包(奖励)	0
                    if (this.share) {
                        this.share.setList(list);
                    }
                }
                else {
                    console.log(`#### show error ${msg.desc}`);
                    this.share.setList([]);
                }
                break;
            case GameConstant_1.default.MESSAGETYPE.INVITENEWREC:
                // if(msg.status == '0'){
                //     console.log('#### 显示奖励 ${msg.prize}个红包')
                // }else{
                //     this.status.setAlert({
                //         desc: msg.desc
                //     })
                // }
                this.status.setAlert({
                    desc: msg.status == '0' ? `领取成功，红包数${msg.prize}` : msg.desc
                });
                if (msg.status == '0') {
                    // this.msgOut({
                    //     type:GameConstant.MESSAGETYPE.INVITENEWINFO
                    // })
                    this.share.setList([]);
                    this.userGetItem(GameConstant_1.default.ITEMTYPE.REDPACK, parseInt(msg.prize));
                }
                break;
            case GameConstant_1.default.MESSAGETYPE.BUYBATTERYLV:
                if (msg.status != '0') {
                    this.status.setAlert({
                        desc: msg.desc
                    });
                }
                break;
            case GameConstant_1.default.MESSAGETYPE.UPDATEREDPACKET:
                if (msg.redPack) {
                    this.nowUser.redPacketCnt = msg.redPack;
                }
                break;
        }
    }
    getMission(code = null) {
        let mission = null;
        code = code || this.missionData.miCode;
        this.missionList["list"].forEach(element => {
            if (element.code == code) {
                mission = element;
            }
        });
        return mission;
    }
    setMission() {
        // 加鱼 返回任务子弹计数
        const bulletCount = this.fishManager.addMission();
        // 设置任务子弹数
        this.fireStatus.bulletCountDown = bulletCount;
    }
    checkLoginStatus() {
        if (this.status.isUserServerLoginDone) {
            Laya.timer.clear(this, this.checkLoginStatus);
            if (GameSettings_1.default.isAquamanRankOpen) {
                this.msgOut({ type: GameConstant_1.default.MESSAGETYPE.AQUAMANRANKLIST });
                this.msgOut({
                    type: GameConstant_1.default.MESSAGETYPE.AQUAMANRANKPRIZE
                });
            }
            if (this.nowScene == GameConstant_1.default.SCENETYPE.LOADING) {
                this.changeScene(GameConstant_1.default.SCENETYPE.GAME, () => {
                });
            }
            else {
                this.status.setLoading(false);
                this.status.isOnOffline = false;
            }
        }
    }
    showAlert(desc) {
        console.log(`GamCetner Alert :: ${desc}`);
    }
    showInviteIntro() {
        let param = {
            type: GameConstant_1.default.POPUPTYPE.INVITEINTRO
        };
        this.loadViewByNeed(GameConstant_1.default.GAMECOMPONENT.POPUP, () => {
            this.status.setPopup(param);
        });
    }
    getItemDropTarget(itemType) {
        let point = null;
        for (let i = 0; i < this.dropTargetHolderList.length; i++) {
            const element = this.dropTargetHolderList[i];
            point = element.getDropTarget(itemType);
            if (point)
                break;
        }
        return point;
    }
    ////////////////////////////
    //  内部操作 包装
    ////////////////////////////
    setBattery(id) {
        this.nowBatterySetting = this.getBatterySetting(id);
        this.nowUser.curBatteryid = id;
        this.fireStatus.setRate(this.nowBatterySetting);
    }
    isBulletEnough() {
        const cost = this.nowUser.curBatteryLv * this.nowBatterySetting.costRatio * (this.fireStatus.rage ? 2 : 1);
        return parseInt(this.nowUser.coin) >= cost;
    }
    userCostItem(itemType, count = 1) {
        if (itemType == GameConstant_1.default.ITEMTYPE.REDPACK) {
            //this.nowUser.redPacketCnt -= count
        }
        else {
            let arr = [];
            this.nowUser.propList.forEach(element => {
                if (element.id == itemType) {
                    element.cnt = Math.max(element.cnt - count, 0);
                }
                if (element.cnt > 0) {
                    arr.push(element);
                }
            });
            this.nowUser.propList = arr;
        }
    }
    userGetItem(itemType, count) {
        if (itemType == GameConstant_1.default.ITEMTYPE.REDPACK) {
            //this.nowUser.redPacketCnt += count
        }
        else {
            let found = false;
            let arr = [];
            this.nowUser.propList.forEach(element => {
                if (element.id == itemType) {
                    element.cnt += count;
                    found = true;
                }
                arr.push(element);
            });
            if (!found) {
                arr.push({
                    id: itemType,
                    cnt: count
                });
            }
            this.nowUser.propList = arr;
        }
    }
    stringifyCoinValue(coin) {
        return coin >= 10000000 ? `${(coin / 10000).toFixed(0)}万` : coin.toString();
    }
    isUserHasVipPrize() {
        return this.nowUser && this.nowUser.vip > this.nowUser.minVipRec;
    }
    ////////////////////////////
    //  GameSettings 包装
    ////////////////////////////
    getBatterySetting(id) {
        let setting = GameSettings_1.default.batterySetting['battery_1'];
        if (GameSettings_1.default.batterySetting[`battery_${id}`]) {
            setting = GameSettings_1.default.batterySetting[`battery_${id}`];
        }
        return setting;
    }
    getOutsideImage(url, callback) {
        TarsisHttp_1.default.StartHttpCall({
            url: url,
            responseType: 'arraybuffer',
            onSuccess: (data) => {
                var byte = new Laya.Byte(data); //Byte数组接收arraybuffer
                byte.writeArrayBuffer(data, 4); //从第四个字节开始读取数据
                var blob = new Laya.Browser.window.Blob([data], { type: "image/png" });
                var url = Laya.Browser.window.URL.createObjectURL(blob); //创建一个url对象；
                if (callback) {
                    callback(url);
                }
            }
        });
    }
}
exports.default = GameCenter;
},{"../GameConstant":10,"../GameSettings":11,"../element/FishControl":27,"../utils/Tarsis":66,"../utils/TarsisHttp":67,"./AudioManager":1,"./FireStatus":2,"./IntentControl":4,"./StatusCenter":8}],4:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const GameCenter_1 = require("./GameCenter");
class IntentControl {
    static onShow() {
        alert("Java 调用 Laya onShow()");
    }
    static onHide() {
        alert("Java 调用 Laya onHide()");
    }
    static onPayResult(data) {
        GameCenter_1.default.instance.checkPayResult(data);
    }
    //进入游戏后，执行init函数
    static init() {
        console.log('INTENT CONTROL INIT');
        if (Laya.Browser.window.conch) {
            this.os = Laya.Browser.window.conchConfig.getOS();
            if (this.os == IntentControl.conchIOS) {
                console.log('INTENT CONTROL INIT ===  IOS');
                this.isOnIos = true;
                this.bridge = Laya.PlatformClass.createClass("JSBridge");
                this.bridge.call("initGame:");
            }
            else if (this.os == IntentControl.conchAndroid) {
                console.log('INTENT CONTROL WECHAT LOGIN  ===  ANDROID');
                this.isOnAndroid = true;
                this.bridge = Laya.PlatformClass.createClass("demo.JSBridge");
                this.bridge.call("initGame");
            }
        }
    }
    static wechatLogin(callback) {
        if (this.isOnIos) {
            console.log('INTENT CONTROL WECHAT LOGIN  ===  IOS');
            this.bridge.callWithBack(function (value) {
                var data = JSON.parse(value);
                callback(data);
            }, "wechatLogin:");
        }
        if (this.isOnAndroid) {
            console.log('INTENT CONTROL WECHAT LOGIN  ===  ANDROID');
            // this.bridge.callWithBack(function(value) {
            //   var data = JSON.parse(value)
            //   callback(data);
            //   },"wechatLogin");
            this.loginCallback = callback;
            this.bridge.call("wechatLogin");
        }
    }
    static wechatLoginResult(str) {
        const resultJson = JSON.stringify(str);
        const resultStr = JSON.parse(resultJson);
        console.log(`login Result : ${str}`);
        if (this.loginCallback) {
            this.loginCallback(resultStr);
            this.loginCallback = null;
        }
    }
    static testFunc(str) {
        const result = JSON.stringify(str);
        console.log(`login Result : ${str}`);
    }
    static openUrl(address) {
        if (this.isOnIos) {
            console.log(`INTENT CONTROL WEBVIEW  ===  IOS address:${address}`);
            this.bridge.call("openWeb", address);
        }
        if (this.isOnAndroid) {
            console.log(`INTENT CONTROL WEBVIEW  ===  ANDROID address:${address}`);
            this.bridge.call("openWeb", address);
        }
    }
    static iosPay(goodsId) {
        if (this.isOnIos) {
            console.log(`INTENT CONTROL IOS PAY  ===  IOS goods:${goodsId}`);
            this.bridge.call('iosPay:', goodsId);
        }
    }
}
exports.default = IntentControl;
IntentControl.conchIOS = "Conch-ios";
IntentControl.conchAndroid = "Conch-android";
IntentControl.os = "";
IntentControl.bridge = null;
IntentControl.isOnIos = false;
IntentControl.isOnAndroid = false;
IntentControl.loginCallback = null;
IntentControl.payResultJson = "";
if (Laya.Browser.window) {
    Laya.Browser.window.IntentControl = IntentControl;
}
},{"./GameCenter":3}],5:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-28 15:58:44
 * @Last Modified by:   Odie Robin
 * @Last Modified time: 2019-05-28 15:58:44
 */
Object.defineProperty(exports, "__esModule", { value: true });
const Tarsis_1 = require("../utils/Tarsis");
class PahtControl extends Laya.View {
    constructor() {
        super();
        this.nowIndex = 0;
    }
    onEnable() {
        Laya.loader.load("settings/pathFull.json", Laya.Handler.create(this, (path) => {
            this.allPath = path.pathList;
            const scaleY = Math.max(1, Laya.stage.height / 1920);
            this.allPath.forEach(p => {
                p.smoothPoints.forEach(q => {
                    q.y *= scaleY;
                });
            });
            // 从旧路径导成新路径
            // this.allPath.forEach(element => {
            //     let path = Tarsis.BezierCurvePath(Tarsis.BezierCurvePoints(element.points,element.points.length,30),element.right)
            //     element.smoothPoints = path.points
            //     let arr = []
            //     path.pointLenInPath.forEach(element => {
            //         element = element as Number
            //         element = Number(element.toFixed(2))
            //         arr.push(element)
            //     });
            //     element.pointLenInPath = arr
            //     element.pathLen = Number(path.pathLen.toFixed(2))
            //     element.smoothPoints.forEach(element => {
            //         element = element as Laya.Point
            //         element.x = Number(element.x.toFixed(2))
            //         element.y = Number(element.y.toFixed(2))
            //     });
            // });
            // console.log(JSON.stringify(this.allPath))
            PahtControl.instanse = this;
            this.drawOneLineWithIndex(0);
            // path.pathList.forEach(element => {
            //     const color = Tarsis.RGBToHex([Math.random() * 255,Math.random() * 255,Math.random()* 255])
            //     let sprite = new Laya.Sprite()
            //     let newPoints = Tarsis.BezierCurvePoints(element.points,element.points.length - 2,20)
            //     for (let index = 0; index < newPoints.length; index++) {
            //         const point = newPoints[index];
            //         sprite.graphics.drawCircle(point.x,point.y,5,color)
            //         if(index > 0){
            //             const prePoint = newPoints[index - 1];
            //             sprite.graphics.drawLine(point.x,point.y,prePoint.x,prePoint.y,color,3)
            //         }
            //     }
            //     this.addChild(sprite)
            // });
        }));
    }
    drawNow() {
        this.drawOneLineWithIndex(this.nowIndex);
    }
    drawNext() {
        this.nowIndex = this.nowIndex + 1 < this.allPath.length ? this.nowIndex + 1 : 0;
        this.drawNow();
    }
    drawPrev() {
        this.nowIndex = this.nowIndex - 1 >= 0 ? this.nowIndex - 1 : this.allPath.length - 1;
        this.drawNow();
    }
    drawOneLineWithIndex(index) {
        this.removeChildren();
        let path = this.allPath[index];
        // let points = this.allPath[index].points
        // this.graphics.clear()
        // const path = Tarsis.BezierCurvePath(Tarsis.BezierCurvePoints(points,points.length,20),this.allPath[index].id.substr(0,1) == "R")
        // this.graphics.fillText(`${index} : ${this.allPath[index].id} \r\n Length : ${path.pathLen}`,100,200,'30px Arial','#FFFFFF','left')
        this.drawOneLine(path.points);
        this.drawOneLine(path.smoothPoints);
        if (this.pathCallback) {
            this.pathCallback(path);
        }
    }
    drawOneLineWithName(name) {
        this.removeChildren();
        let points = this.getLinePoints(name);
        this.graphics.clear();
        this.graphics.fillText(name, 100, 200, '30px Arial', '#FFFFFF', 'left');
        this.drawOneLine(points);
        this.drawOneLine(Tarsis_1.default.BezierCurvePoints(points, points.length, 20));
    }
    getLinePoints(name) {
        let result = [];
        this.allPath.forEach(element => {
            if (element.id == name) {
                result = element.points;
            }
        });
        return result;
    }
    drawOneLine(points) {
        const color = Tarsis_1.default.RGBToHex([Math.random() * 255, Math.random() * 255, Math.random() * 255]);
        let sprite = new Laya.Sprite();
        for (let index = 0; index < points.length; index++) {
            const point = points[index];
            sprite.graphics.drawCircle(point.x, point.y, 5, color);
            if (index > 0) {
                const prePoint = points[index - 1];
                sprite.graphics.drawLine(point.x, point.y, prePoint.x, prePoint.y, color, 3);
            }
        }
        this.addChild(sprite);
    }
}
exports.default = PahtControl;
},{"../utils/Tarsis":66}],6:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-28 15:58:48
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-12-12 18:08:37
 */
Object.defineProperty(exports, "__esModule", { value: true });
const Tarsis_1 = require("../utils/Tarsis");
const GameConstant_1 = require("../GameConstant");
const GameSettings_1 = require("../GameSettings");
const IntentControl_1 = require("./IntentControl");
class PlatformNative {
    getSetting(param = null) {
        if (param && param.success) {
            let authSetting = {};
            authSetting['scope.userInfo'] = true;
            param.success({
                authSetting: authSetting
            });
        }
    }
    getSystemInfo(param = null) {
        if (param && param.success) {
            param.success({
                screenWidth: Laya.stage.width,
                screenHeight: Laya.stage.height,
                platform: 'Native'
            });
        }
    }
    login(param = null) {
        if (GameSettings_1.default.isNative) {
            IntentControl_1.default.wechatLogin((data) => {
                if (data.result == 0) {
                    if (param && param.success) {
                        param.success({
                            code: data.access_token,
                            nickName: data.nick_name,
                            avatar: data.avatar || '',
                            openId: data.openid,
                            unionId: data.unionid
                        });
                    }
                }
                else {
                    if (param && param.fail) {
                        param.fail(data.result);
                    }
                }
            });
        }
        else {
            let uuid = Laya.LocalStorage.getItem(GameConstant_1.default.LOCALSTORAGEKEY.UUID);
            if (!uuid) {
                uuid = Tarsis_1.default.uuid();
                Laya.LocalStorage.setItem(GameConstant_1.default.LOCALSTORAGEKEY.UUID, uuid);
                Laya.LocalStorage.setItem(GameConstant_1.default.LOCALSTORAGEKEY.NICKNAME, `Captain-${uuid.substr(0, 8)}`);
            }
            if (param && param.success) {
                param.success({
                    code: uuid
                });
            }
        }
    }
    getUserInfo(param = null) {
        if (param && param.success) {
            param.success({
                userInfo: {
                    nickName: Laya.LocalStorage.getItem(GameConstant_1.default.LOCALSTORAGEKEY.NICKNAME),
                    avatarUrl: ""
                }
            });
        }
    }
    requestMidasPayment(param = null) {
        if (param && param.complete) {
            param.complete({
                res: {
                    errMsg: "ok",
                    errCode: 0 //1 异常  
                }
            });
        }
    }
    setKeepScreenOn(param = null) {
        if (param && param.keepScreenOn) {
            param.keepScreenOn = true;
        }
    }
    getLaunchOptionsSync() {
        return null;
    }
    vibrateShort() {
        console.log('Native Shock Short');
    }
    vibrateLong() {
        console.log('Native Shock Long');
    }
    shareAppMessage(shareInfo) {
        console.log(`Native Start Share!`);
    }
}
exports.default = PlatformNative;
},{"../GameConstant":10,"../GameSettings":11,"../utils/Tarsis":66,"./IntentControl":4}],7:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-28 15:58:53
 * @Last Modified by:   Odie Robin
 * @Last Modified time: 2019-05-28 15:58:53
 */
Object.defineProperty(exports, "__esModule", { value: true });
const GameConstant_1 = require("../GameConstant");
const GameSettings_1 = require("../GameSettings");
const GameCenter_1 = require("./GameCenter");
const TarsisSocket_1 = require("../utils/TarsisSocket");
class PostOffice {
    constructor() {
        this.isSocketOpen = false;
        this.testNumber = 100;
        this.onHeartFail = null;
        PostOffice.instance = this;
        this.GC = GameCenter_1.default.instance;
        // this.socket = new TarsisSocket()
    }
    startNet(onOpenCallback = null, onMessageCallbck = null, onSocetError = null, onHeartFail = null) {
        this.socket = new TarsisSocket_1.default();
        this.onHeartFail = onHeartFail;
        this.socket.init(GameSettings_1.default.socketAddress, () => {
            this.onOpen();
            if (onOpenCallback) {
                onOpenCallback();
            }
        }, (e) => {
            this.onError(e);
            if (onSocetError) {
                onSocetError(e);
            }
        }, () => {
            this.onClose();
        }, (data) => {
            this.onMessage(data, onMessageCallbck);
        });
    }
    sendMessage(msg) {
        if (this.isSocketOpen) {
            msg.ACTION_NAME = "USER_ACTION";
            switch (msg.type) {
                case GameConstant_1.default.MESSAGETYPE.AUTH:
                    //code
                    //nick_name
                    msg.wx_type = GameSettings_1.default.loginType;
                    msg.device_type = this.GC.systemInfo.platform;
                    msg.place_type = GameSettings_1.default.channelId;
                    break;
            }
            if (GameSettings_1.default.debug.showOutMessage) {
                if (msg.type !== GameConstant_1.default.MESSAGETYPE.PING) {
                    console.log(`Msg Out : ${JSON.stringify(msg)}`);
                }
            }
            this.socket.sendMessge(msg);
        }
    }
    onOpen() {
        this.isSocketOpen = true;
        Laya.timer.loop(5000, this, this.heartBeat);
    }
    onError(res) {
        console.log(`Socket On Error :: ${res}`);
    }
    onMessage(data, onMessageCallbck = null) {
        let msg = JSON.parse(data);
        if (GameSettings_1.default.debug.showInMessage) {
            if (msg.type !== GameConstant_1.default.MESSAGETYPE.PING) {
                console.log(msg);
            }
        }
        if (msg.type == GameConstant_1.default.MESSAGETYPE.PING) {
            Laya.timer.clear(this, this.heartBeatFail);
        }
        else {
            this.dealMessage(msg);
            if (onMessageCallbck) {
                onMessageCallbck(msg);
            }
        }
    }
    onClose() {
        this.isSocketOpen = false;
        Laya.timer.clear(this, this.heartBeat);
        if (this.onHeartFail) {
            this.onHeartFail();
        }
    }
    heartBeat() {
        if (this.isSocketOpen) {
            this.sendMessage({ type: GameConstant_1.default.MESSAGETYPE.PING });
            Laya.timer.once(4000, this, this.heartBeatFail);
        }
    }
    heartBeatFail() {
        this.socket.close();
        if (this.onHeartFail) {
            this.onHeartFail();
        }
    }
    dealMessage(msg) {
    }
}
exports.default = PostOffice;
},{"../GameConstant":10,"../GameSettings":11,"../utils/TarsisSocket":68,"./GameCenter":3}],8:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const GameConstant_1 = require("../GameConstant");
const GameSettings_1 = require("../GameSettings");
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-28 15:59:03
 * @Last Modified by: ZZL
 * @Last Modified time: 2019-12-17 15:21:14
 */
class StatusCenter {
    constructor() {
        /**
         * 当前是断线状态
         */
        this.isOnOffline = false;
        /**
         * 平台授权成功
         */
        this.isPlatformAuth = false;
        /**
         * 平台用户数据获得
         */
        this.isPlatformUserData = false;
        /**
         * 服务器用户登录
         */
        this.isUserLogin = false;
        /**
         * 服务器用户数据获得
         */
        this.isGotUserData = false;
        /**
         * 服务器设置获得
         */
        this.isGotSystemConfig = false;
        /**
         * Loading信息：是否显示
         */
        this.isOnLoading = false;
        /**
         * Loading信息：默认配置
         */
        this.loadingInfoTempalte = {
            text: "载入中....",
            backup: "载入中....",
            progress: 0,
            useText: true,
            useProgress: false,
            purpose: 'Normal'
        };
        /**
         * Alert信息：是否显示
         */
        this.isOnAlert = false;
        /**
         * Alert信息：默认配置信息
         */
        this.alertInfoTemplate = {
            title: '游戏提示',
            desc: '提示内容',
            needCancel: false,
            sureText: '确定',
            cancelText: '取消',
            sureCallback: null,
            cancelCallback: null
        };
        /**
         * Coving信息：是否显示
         */
        this.isOnCoving = false;
        this.covingZorder = 50;
        /**
         * Barrage信息：是否显示
         */
        this.isOnBarrage = false;
        /**
         * Barrage信息：默认配置信息
         */
        this.barrageInfoTemplate = {
            text: '弹幕来了。。。',
            speed: 1
        };
        /**
         * Shop信息：是否显示
         */
        this.isOnShop = false;
        /**
         * Shop信息：当前显示类型
         */
        this.nowShopType = 0;
        /**
         * Shop信息：当前显示类型
         */
        this.nowRechargeType = 0;
        /**
         * 红包Shop信息：是否显示
         */
        this.isOnRedPackShop = false;
        /**
         * 红包Shop信息：当前显示类型
         */
        this.nowRedPackShopType = 1;
        /**
         * 获得奖励窗口：是否显示
         */
        this.isOnGetItem = false;
        /**
         * 获得奖励窗口：显示的信息
         */
        this.getItemInfo = null;
        /**
         * 获得奖励窗口：显示的信息模板
         */
        this.getItemInfoTemplate = {
            itemList: [],
            title: '恭喜获得',
            desc: '',
            callBack: null,
            autoClose: -1
        };
        /**
         * 获得奖励窗口：是否显示
         */
        this.isOnMission = false;
        this.isOnMissionView = false;
        /**
         * 任务窗口状态
         */
        this.missionViewState = 0; // 0 1 2
        /**
         * 任务信息
         * duration
         */
        this.missInfo = {};
        /**
         * 任务信息
         * duration
         */
        this.countDownInfo = {};
        this.isOnNewbee = true;
        this.isOnPopup = false;
        this.popupInfoTemplate = {
            type: -1,
            levelInfo: {},
            versionInfo: {},
            JIUJIBI_Info: {}
        };
        this.popupInfo = null;
        this.isOnCountDown = false;
        /**
         * 游戏中状态（本地参数）
         * GameConstant.GAMESTATETYPE
         */
        this._gameState = 0;
        /**
         * 是否显示海王榜
         */
        this.isOnAquaManRank = false;
        this.isOnShare = false;
    }
    /**
     * 平台登录成功标志
     * 平台授权成功 && 平台用户数据获得
     */
    get isUserPlatformLoginDone() {
        return this.isPlatformAuth && this.isPlatformUserData;
    }
    /**
     * 游戏服务器登录成功标志
     * 服务器socket连接成功 && 用户数据获得
     */
    get isUserServerLoginDone() {
        return this.isUserLogin && this.isGotUserData && this.isGotSystemConfig;
    }
    /**
     * 重置所有
     */
    reset() {
        this.isPlatformAuth = false;
        this.isPlatformUserData = false;
        this.isUserLogin = false;
        this.isGotUserData = false;
        this.isGotSystemConfig = false;
        this.isOnShop = false;
        this.isOnRedPackShop = false;
        this.isOnBarrage = false;
        this.isOnLoading = false;
        this.isOnAlert = false;
        this.isOnCoving = false;
    }
    /**
     * 设置Loading
     */
    setLoading(isLoading = true, param = null) {
        this.isOnLoading = isLoading;
        if (isLoading) {
            this.loadingInfo = Object.assign(Object.assign({}, this.loadingInfoTempalte), param);
            this.loadingInfo.backup = this.loadingInfo.text;
        }
    }
    /**
     * 更新Loading文字
     */
    setLoadingText(text) {
        if (this.isOnLoading) {
            this.loadingInfo.text = text;
        }
    }
    /**
     * 更新Loading进度
     */
    setLoadingProgress(progress) {
        if (this.isOnLoading) {
            this.loadingInfo.progress = progress;
            if (this.loadingInfo.useProgress && this.loadingInfo.useText) {
                this.loadingInfo.text = `${this.loadingInfo.backup}  ${this.loadingInfo.progress * 100}%`;
            }
        }
    }
    /**
     * 拉起警告显示
     * @param param 设置属性
     * title || desc || addon || needCancel || sureText || cancelText || sureCallback || cancelCallback
     */
    setAlert(param) {
        this.alertInfo = Object.assign(Object.assign({ addon: `${GameConstant_1.default.PROMOTIONTEXT.CUSTOMQQ.replace('$qq$', GameSettings_1.default.customQQ)}\n${GameConstant_1.default.PROMOTIONTEXT.PUBLICACCOUNT.replace('$pa$', GameSettings_1.default.wechatPublicAccount)}`, onSure: () => {
                this.isOnAlert = false;
                this.setLoading(false);
                if (this.alertInfo.sureCallback) {
                    this.alertInfo.sureCallback();
                }
            }, onCancel: () => {
                this.isOnAlert = false;
                this.setLoading(false);
                if (this.alertInfo.cancelCallback) {
                    this.alertInfo.cancelCallback();
                }
            } }, this.alertInfoTemplate), param);
        this.isOnAlert = true;
        this.setLoading(true);
    }
    closeAlert() {
        this.isOnAlert = false;
    }
    setCoving(flag = true) {
        this.isOnCoving = flag;
    }
    /**
     *
     * @param flag 是否显示
     * @param param 属性设置
     * text || speed : 1
     */
    setBarrage(param, flag = true) {
        this.isOnBarrage = flag;
        if (this.isOnBarrage) {
            this.barrageInfo = Object.assign(Object.assign({ onFinish: () => {
                    this.isOnBarrage = false;
                    if (this.barrageInfo.callback) {
                        this.barrageInfo.callback();
                    }
                } }, this.barrageInfoTemplate), param);
        }
    }
    openShop(shopType = 0) {
        this.isOnCoving = true;
        this.nowShopType = shopType;
        this.isOnShop = true;
    }
    closeShop() {
        this.isOnCoving = false;
        this.isOnShop = false;
    }
    setShop(shopType = 0) {
        this.nowShopType = shopType;
    }
    //充值活动
    openRechargeActivity(Type = 0) {
        this.isOnCoving = true;
        this.nowRechargeType = Type;
        this.isOnShop = true;
    }
    closeRechargeActivity() {
        this.isOnCoving = false;
        this.isOnShop = false;
    }
    setRechargeActivity(Type = 0) {
        this.nowRechargeType = Type;
    }
    openRedPackShop(shopType = 1) {
        this.isOnCoving = true;
        this.nowRedPackShopType = shopType;
        this.isOnRedPackShop = true;
    }
    closeRedPackShop() {
        this.isOnCoving = false;
        this.isOnRedPackShop = false;
    }
    setRedPackShop(shopType = 1) {
        this.nowRedPackShopType = shopType;
    }
    setGetItem(param) {
        this.getItemInfo = Object.assign(Object.assign({ onFinish: () => {
                this.isOnGetItem = false;
                if (this.getItemInfo.callback) {
                    this.getItemInfo.callback();
                }
            } }, this.getItemInfoTemplate), param);
        this.isOnGetItem = true;
    }
    setMission(param) {
        this.missInfo = Object.assign({}, param);
        this.isOnMission = true;
    }
    setCountDown(param) {
        this.countDownInfo = Object.assign({}, param);
        this.isOnCountDown = true;
    }
    setMissionView(flag) {
        //this.isOnMissionView = flag
        this.isOnCoving = flag;
    }
    setPopup(param) {
        this.popupInfo = Object.assign(Object.assign({ onClose: () => {
                this.isOnPopup = false;
                if (param.callBack) {
                    param.callBack();
                }
            } }, this.popupInfoTemplate), param);
        this.isOnPopup = true;
    }
    /**
     * 游戏中状态
     * GameConstant.GAMESTATETYPE
     */
    get gameState() {
        return this._gameState;
    }
    /**
     * 游戏中状态
     * GameConstant.GAMESTATETYPE
     */
    set gameState(state) {
        this._gameState = state;
    }
    openAquaMan(setting) {
        this.aquaManRankSetting = setting;
        this.isOnCoving = true;
        this.isOnAquaManRank = true;
    }
    closeAquaMan() {
        this.isOnCoving = false;
        this.isOnAquaManRank = false;
    }
    openShare() {
        this.isOnCoving = true;
        this.isOnShare = true;
    }
    closeShare() {
        this.isOnCoving = false;
        this.isOnShare = false;
    }
}
exports.default = StatusCenter;
},{"../GameConstant":10,"../GameSettings":11}],9:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
/**This class is automatically generated by LayaAirIDE, please do not make any modifications. */
const LoadingScene_1 = require("./element/LoadingScene");
const GameScene_1 = require("./element/GameScene");
const TouchControl_1 = require("./element/TouchControl");
const TestScene_1 = require("./element/TestScene");
const BulletControl_1 = require("./element/BulletControl");
const FishNetControl_1 = require("./element/FishNetControl");
const PathMove_1 = require("./element/PathMove");
const FishControl_1 = require("./element/FishControl");
const FishGatherControl_1 = require("./element/FishGatherControl");
const FishAnimationControl_1 = require("./element/FishAnimationControl");
const DropControl_1 = require("./element/DropControl");
const DropItemInfo_1 = require("./element/DropItemInfo");
const testFishItemSceneControl_1 = require("./test/testFishItemSceneControl");
const ExtBaseButton_1 = require("./extends/ExtBaseButton");
const PathControl_1 = require("./Control/PathControl");
const AlertControl_1 = require("./element/AlertControl");
const BarrageControl_1 = require("./element/BarrageControl");
const CovingControl_1 = require("./element/CovingControl");
const EnemyInfoZone_1 = require("./element/EnemyInfoZone");
const FishManager_1 = require("./element/FishManager");
const FishSettings_1 = require("./element/FishSettings");
const GetItemControl_1 = require("./element/GetItemControl");
const LoadingControl_1 = require("./element/LoadingControl");
const LogoZone_1 = require("./element/LogoZone");
const MainBgControl_1 = require("./element/MainBgControl");
const CountDownControl_1 = require("./element/CountDownControl");
const MissionControl_1 = require("./element/MissionControl");
const Newbee_1 = require("./element/Newbee");
const PopupControl_1 = require("./element/PopupControl");
const AquaManRankControl_1 = require("./element/AquaManRankControl");
const RechargeActivity_1 = require("./element/RechargeActivity");
const RedPackShopControl_1 = require("./element/RedPackShopControl");
const RobotControl_1 = require("./element/RobotControl");
const robotShipControl_1 = require("./element/robotShipControl");
const BatteryControl_1 = require("./element/BatteryControl");
const BatteryComponent_1 = require("./extends/BatteryComponent");
const BatteryInfo_1 = require("./extends/BatteryInfo");
const ShareRedPackPrizeItemControl_1 = require("./element/ShareRedPackPrizeItemControl");
const ShareRedPackPrizeControl_1 = require("./element/ShareRedPackPrizeControl");
const ShipControl_1 = require("./element/ShipControl");
const ShopControl_1 = require("./element/ShopControl");
const SystemMenuControl_1 = require("./element/SystemMenuControl");
const UserInfoZone_1 = require("./element/UserInfoZone");
const UserLoginZone_1 = require("./element/UserLoginZone");
const AquaManRankItemControl_1 = require("./element/AquaManRankItemControl");
const CoinDisplayControl_1 = require("./element/CoinDisplayControl");
const FlyControl_1 = require("./element/FlyControl");
const FishBingoControl_1 = require("./element/FishBingoControl");
const FishDropItemControl_1 = require("./element/FishDropItemControl");
const RedPackShopItemControl_1 = require("./shop/RedPackShopItemControl");
const ShareIntroControl_1 = require("./element/ShareIntroControl");
const ShopItemControl_1 = require("./shop/ShopItemControl");
const VipPrizeItemControl_1 = require("./shop/VipPrizeItemControl");
/*
* 游戏初始化配置;
*/
class GameConfig {
    constructor() {
    }
    static init() {
        var reg = Laya.ClassUtils.regClass;
        reg("element/LoadingScene.ts", LoadingScene_1.default);
        reg("element/GameScene.ts", GameScene_1.default);
        reg("element/TouchControl.ts", TouchControl_1.default);
        reg("element/TestScene.ts", TestScene_1.default);
        reg("element/BulletControl.ts", BulletControl_1.default);
        reg("element/FishNetControl.ts", FishNetControl_1.default);
        reg("element/PathMove.ts", PathMove_1.default);
        reg("element/FishControl.ts", FishControl_1.default);
        reg("element/FishGatherControl.ts", FishGatherControl_1.default);
        reg("element/FishAnimationControl.ts", FishAnimationControl_1.default);
        reg("element/DropControl.ts", DropControl_1.default);
        reg("element/DropItemInfo.ts", DropItemInfo_1.default);
        reg("test/testFishItemSceneControl.ts", testFishItemSceneControl_1.default);
        reg("extends/ExtBaseButton.ts", ExtBaseButton_1.default);
        reg("Control/PathControl.ts", PathControl_1.default);
        reg("element/AlertControl.ts", AlertControl_1.default);
        reg("element/BarrageControl.ts", BarrageControl_1.default);
        reg("element/CovingControl.ts", CovingControl_1.default);
        reg("element/EnemyInfoZone.ts", EnemyInfoZone_1.default);
        reg("element/FishManager.ts", FishManager_1.default);
        reg("element/FishSettings.ts", FishSettings_1.default);
        reg("element/GetItemControl.ts", GetItemControl_1.default);
        reg("element/LoadingControl.ts", LoadingControl_1.default);
        reg("element/LogoZone.ts", LogoZone_1.default);
        reg("element/MainBgControl.ts", MainBgControl_1.default);
        reg("element/CountDownControl.ts", CountDownControl_1.default);
        reg("element/MissionControl.ts", MissionControl_1.default);
        reg("element/Newbee.ts", Newbee_1.default);
        reg("element/PopupControl.ts", PopupControl_1.default);
        reg("element/AquaManRankControl.ts", AquaManRankControl_1.default);
        reg("element/RechargeActivity.ts", RechargeActivity_1.default);
        reg("element/RedPackShopControl.ts", RedPackShopControl_1.default);
        reg("element/RobotControl.ts", RobotControl_1.default);
        reg("element/robotShipControl.ts", robotShipControl_1.default);
        reg("element/BatteryControl.ts", BatteryControl_1.default);
        reg("extends/BatteryComponent.ts", BatteryComponent_1.default);
        reg("extends/BatteryInfo.ts", BatteryInfo_1.default);
        reg("element/ShareRedPackPrizeItemControl.ts", ShareRedPackPrizeItemControl_1.default);
        reg("element/ShareRedPackPrizeControl.ts", ShareRedPackPrizeControl_1.default);
        reg("element/ShipControl.ts", ShipControl_1.default);
        reg("element/ShopControl.ts", ShopControl_1.default);
        reg("element/SystemMenuControl.ts", SystemMenuControl_1.default);
        reg("element/UserInfoZone.ts", UserInfoZone_1.default);
        reg("element/UserLoginZone.ts", UserLoginZone_1.default);
        reg("element/AquaManRankItemControl.ts", AquaManRankItemControl_1.default);
        reg("element/CoinDisplayControl.ts", CoinDisplayControl_1.default);
        reg("element/FlyControl.ts", FlyControl_1.default);
        reg("element/FishBingoControl.ts", FishBingoControl_1.default);
        reg("element/FishDropItemControl.ts", FishDropItemControl_1.default);
        reg("shop/RedPackShopItemControl.ts", RedPackShopItemControl_1.default);
        reg("element/ShareIntroControl.ts", ShareIntroControl_1.default);
        reg("shop/ShopItemControl.ts", ShopItemControl_1.default);
        reg("shop/VipPrizeItemControl.ts", VipPrizeItemControl_1.default);
    }
}
exports.default = GameConfig;
GameConfig.width = 1080;
GameConfig.height = 1920;
GameConfig.scaleMode = "fixedwidth";
GameConfig.screenMode = "vertical";
GameConfig.alignV = "middle";
GameConfig.alignH = "center";
GameConfig.startScene = "scene/Loading.scene";
GameConfig.sceneRoot = "";
GameConfig.debug = false;
GameConfig.stat = false;
GameConfig.physicsDebug = false;
GameConfig.exportSceneToJson = true;
GameConfig.init();
},{"./Control/PathControl":5,"./element/AlertControl":13,"./element/AquaManRankControl":14,"./element/AquaManRankItemControl":15,"./element/BarrageControl":16,"./element/BatteryControl":17,"./element/BulletControl":18,"./element/CoinDisplayControl":19,"./element/CountDownControl":20,"./element/CovingControl":21,"./element/DropControl":22,"./element/DropItemInfo":23,"./element/EnemyInfoZone":24,"./element/FishAnimationControl":25,"./element/FishBingoControl":26,"./element/FishControl":27,"./element/FishDropItemControl":28,"./element/FishGatherControl":29,"./element/FishManager":30,"./element/FishNetControl":31,"./element/FishSettings":32,"./element/FlyControl":33,"./element/GameScene":34,"./element/GetItemControl":35,"./element/LoadingControl":36,"./element/LoadingScene":37,"./element/LogoZone":38,"./element/MainBgControl":39,"./element/MissionControl":40,"./element/Newbee":42,"./element/PathMove":43,"./element/PopupControl":44,"./element/RechargeActivity":45,"./element/RedPackShopControl":46,"./element/RobotControl":47,"./element/ShareIntroControl":48,"./element/ShareRedPackPrizeControl":49,"./element/ShareRedPackPrizeItemControl":50,"./element/ShipControl":51,"./element/ShopControl":52,"./element/SystemMenuControl":53,"./element/TestScene":54,"./element/TouchControl":55,"./element/UserInfoZone":56,"./element/UserLoginZone":57,"./element/robotShipControl":58,"./extends/BatteryComponent":59,"./extends/BatteryInfo":60,"./extends/ExtBaseButton":61,"./shop/RedPackShopItemControl":62,"./shop/ShopItemControl":63,"./shop/VipPrizeItemControl":64,"./test/testFishItemSceneControl":65}],10:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-06-01 18:44:20
 * @Last Modified by: ZZL
 * @Last Modified time: 2019-12-26 14:02:22
 */
Object.defineProperty(exports, "__esModule", { value: true });
class GameConstant {
}
exports.default = GameConstant;
GameConstant.GAMESTATETYPE = {
    NORMAL: 0,
    PKFREE: 1,
    PK: 2,
    MISSION: 3
};
/**
 * 对齐方式（obsolete）
 */
GameConstant.ANCHORPOSITION = {
    TOP: 0,
    TOPRIGHT: 1,
    RIGHT: 2,
    BOTTOMRIGHT: 3,
    BOTTOM: 4,
    BOTTOMLEFT: 5,
    LEFT: 6,
    TOPLEFT: 7,
    CENTER: 8
};
/**
 * 层级ZOrder列表
 */
GameConstant.LAYERZORDER = {
    FISHMANAGER: 20,
    USERINFO: 30,
    SYSTEMMENU: 40,
    COVER: 50,
    SHOP: 60,
    BARRAGE: 70,
    TEMPCOVER: 75,
    GETITEM: 80,
    LOADING: 100,
    ALERT: 110
};
/**
 * 获得道具展示类型
 */
GameConstant.GETITEMTYPE = {
    VIPPRIZE: 0,
    FIRSTRECHARGEPRIZE: 1,
    ACTIVITYPRIZE: 2
};
/**
 * 场景类型
 */
GameConstant.SCENETYPE = {
    LOADING: 0,
    GAME: 1
};
/**
 * 炮台附件类型
 */
GameConstant.BATTERYCOMPONENT = {
    NONE: 'NONE',
    BODY: 'BODY',
    BARREL: 'BARREL',
    FIRE: 'FIRE'
};
/**
 * 打包平台类型
 */
GameConstant.PLATTYPE = {
    NATIVE: 0,
    WECHAT: 1,
    BAIDU: 2,
    NATIVEIOS: 3,
    NATIVEANDROID: 4
};
/**
 * 触摸层返回消息类型
 */
GameConstant.TOUCHACTIONTYPE = {
    ROTATE: 0,
    FIRE: 1,
    LOCK: 2
};
/**
 * 用户操作返回消息类型
 */
GameConstant.USERACTIONTYPE = {
    LOGIN: 0,
    USERINFOCOIN: 1,
    USERINFODIAMOND: 2,
    USERINFOREDPACK: 3,
    GUNVALUEPLUS: 4,
    GUNVALUEMINUS: 5,
    CHANGESHOPTYPE: 6,
    CLOSESHOP: 7,
    CHANGEREDPACKSHOPTYPE: 8,
    CLOSEREDPACKSHOP: 9,
    SWITCHBATTERY: 10,
    MISSON: 11,
    GRANDREWARD: 12,
    MEDIASETTING: 13,
    SKILLSWITCH: 14,
    COLLECTIONDROPITEM: 15,
    MISSIONSTART: 16,
    MISSIONRECBIGPRIZE: 17,
    MUSIC: 18,
    SOUND: 19,
    VIBR: 20,
    USERVIPREC: 21,
    REDPACKPURCH: 22,
    SHOPPURCH: 23,
    CLOSEMISSION: 24,
    NEWBEE: 25,
    AQUAMANRANK: 26,
    CLOSEAQUAMANRANK: 27,
    SHARENEW: 28,
    SHANRNEWREC: 29,
    OPENSHARENEW: 30,
    USERINFOVIP: 31,
    RECHARGEACTIVITY: 32
};
/**
 * 媒体控制类型
 */
GameConstant.MEDIASETTINGTYPE = {
    MUSIC: 0,
    SOUND: 1,
    VERB: 2
};
/**
 * 技能开关类型
 */
GameConstant.SKILLSWITCHTYPE = {
    AUTO: 0,
    RAGE: 1,
    PKFREE: 2,
    RAGECOOLDOWN: 101
};
/**
 * 用户加减炮台操作类型
 */
GameConstant.USERGUNVALUECHANGETYPE = {
    MINUS: 0,
    PLUS: 1
};
/**
 * GameCenter注册组件类型
 */
GameConstant.GAMECOMPONENT = {
    MAINBG: 0,
    TOUCH: 1,
    USERINFO: 2,
    USERSHIP: 3,
    FISHMANAGER: 4,
    SHOP: 5,
    REDPACKSHOP: 6,
    SYSTEMMENU: 7,
    ENEMYINFO: 8,
    DROP: 9,
    MISSION: 10,
    POPUP: 11,
    COUNTDOWN: 12,
    NEWBEE: 13,
    ROBOTSHIP: 14,
    ROBOTINFO: 15,
    AQUAMAN: 16,
    SHARENEW: 17,
    RECHARGEACTIVITY: 18
};
/**
 * 消息类型
 */
GameConstant.MESSAGETYPE = {
    AUTH: "wx_auth",
    PAY: "wx_smPay",
    UPDATECOIN: "update_coin",
    UPDATEDIAMOND: "update_diamond",
    UPDATEUSERBATTERYLIST: "update_userBattery",
    UPDATEUSERBATTERYID: "update_curEquipBatid",
    UPDATEGUNVALUE: "update_batteryLv",
    UPDATECOINCALLBACK: "update_coin_callBack",
    UPDATELEVEL: "update_lv",
    UPDATEVIPINFO: "update_vipInfo",
    // UPDATEONEREDPACKETCOUNT : "update_oneMoneyRecCnt",
    VIPREC: "vip_upRec",
    GIFTCODEREC: "giftCode_rec",
    BARRAGE: "barrage",
    SYSTEMCONFIG: "system_config",
    // PROPINIT : "prop_init",
    USERSHOOT: "user_shoot",
    USERHIT: "user_hit",
    USERFIRETORPEDO: "torpedo_use",
    ROBOTHIT: "robot_hit",
    BATTERYBUY: "battery_buy",
    BATTERYEQUIPT: "battery_equip",
    GUNVALUEEXCHANGE: "battery_exchange",
    USERDATA: "user_data",
    USERSTATUS: "userStatus_find",
    USERSTATUSMODIFIED: "userStatus_update",
    USERGETUNIONID: "get_unionId",
    // MATCHJOIN : "match_join",
    // MATCHREADY : "match_ready",
    // MATCHSTART : "match_start",
    // MATCHEND : "match_end",
    // MATCHMESSAGE : "userMatch_msgReq",
    // MATCHHP : "userMatch_update_hp",
    // MATCHRESURGENCE : "match_resurgence",
    PAYDIAMOND: "pay_diamond",
    PAYREDPACKET: "pay_redPacket",
    SHARE: "share",
    SHAREREC: "share_rec",
    REDPACKETREC: "redPacket_rec",
    RANKLIST: "rank_list",
    INVITEINFO: "invite_info",
    INVITEREC: "invite_rec",
    INVITERECNEWUSER: "invite_rec_new",
    INVITEINFOREDPACKET: "redPacket_invite_info",
    BAIDUORDER: "baidu_orderCreate",
    PING: 'heatbeat',
    SKLLSWITCH: 'skill_switch',
    MISSIONPROGRESS: "mi_progress",
    MISSIONINIT: "mi_init",
    MISSIONUPDATE: "mi_update",
    MISSIONSPECIALEND: "mi_specialEnd",
    MISSIONSTART: "mi_start",
    MISSIOBIGPRIZE: "mi_recBigPrize",
    HELPCOIN: 'helpCoin_rec',
    IOSPAYCHECK: 'ios_pay_check',
    ROBOTCONFIG: "robot_config",
    AQUAMANRANKPRIZE: 'consume_rank_prize',
    AQUAMANRANKPRIZEREC: 'consume_rank_prize_rec',
    AQUAMANRANKLIST: 'consume_rank_info',
    INVITENEWINFO: 'invite_new_info',
    INVITENEWREC: 'invite_new_rec',
    BUYBATTERYLV: 'buy_lv',
    UPDATEREDPACKET: 'update_redPack'
};
/**
 * 道具列表
 */
GameConstant.ITEMTYPE = {
    COIN: 'COIN',
    ROBOTCOIN: 'ROBOTCOIN',
    DIAMOND: 'DIAMOND',
    BATTERY: 'BATTERY',
    RAGE: 'PROP_RAGE',
    TORPEDO_1: 'PROP_TORPEDO_1',
    TORPEDO_2: 'PROP_TORPEDO_2',
    TORPEDO_3: 'PROP_TORPEDO_3',
    TORPEDO_4: 'PROP_TORPEDO_4',
    TORPEDO_5: 'PROP_TORPEDO_5',
    PKFREE: 'PROP_REST',
    GUN02: 'BATTERY_2',
    GUN03: 'BATTERY_3',
    GUN04: 'BATTERY_4',
    GUN05: 'BATTERY_5',
    GUN06: 'BATTERY_6',
    GUN07: 'BATTERY_7',
    GUN08: 'BATTERY_8',
    GUN09: 'BATTERY_9',
    GUN10: 'BATTERY_10',
    REDPACK: 'REDPACKET',
    VIP: 'VIP',
};
/**
 * 登录类型
 */
GameConstant.LOGINTYPE = {
    WECHAT_XIHUAN: 0,
    WECHAT: 1,
    ALIPAY: 2,
    WECHAT_5124: 3,
    BAIDU: 4,
    GUSET: 6,
    APP_WECHAT: 7
};
/**
 * 本地存储key
 */
GameConstant.LOCALSTORAGEKEY = {
    UUID: 'UUID',
    NICKNAME: 'NickName',
    VERSION: 'Version',
    AVATARURL: 'AvatarUrl',
    MUSIC: 'Music',
    SOUND: 'Sound',
    VIBR: 'Vibr',
    VERSIONINFO: 'VersionInfo',
    NEWBEE: "Newbee",
    TRACE: "TraceState",
    FIRSTOPENSHARE: "FirstOpenShare"
};
/**
 * 弹幕类型
 */
GameConstant.BARRAGETYPE = {
    USERGOTREDPACK: 0,
    SYSTEM: 1,
    PK: 2,
    CUSTOM: 3
};
/**
 * 商城商品类型
 */
GameConstant.SHOPGOODSTYPE = {
    COIN: 0,
    DIAMOND: 1,
    REDPACK: 2,
    REDPACKCOIN: 3,
    REDPACKVIP: 4
};
/**
 * 普通商城Tab类型
 */
GameConstant.SHOPTYPE = {
    COIN: 0,
    VIP: 1,
    DIAMOND: 2
};
/**
 * 充值获得Tab类型
 */
GameConstant.RECHARGEACTIVITYTYPE = {
    FIRST: 0,
    FREE: 1
};
/**
 * 红包商城Tab类型
 */
GameConstant.REDPACKSHOPTYPE = {
    REDPACK: 0,
    COIN: 1,
    VIP: 2
};
/**
 * 出错提示信息列表
 */
GameConstant.ERRORDESC = {
    SocketConnectFail: '服务器登录失败，请稍后重试！'
};
/**
 * 话术列表
 */
GameConstant.PROMOTIONTEXT = {
    CUSTOMQQ: '官方客服QQ: $qq$',
    PUBLICACCOUNT: '获取更多金币关注公众号：$pa$',
    OFFLINE: '失去网络链接，请重新登录。',
    LOGINFAIL: '登录服务器失败，请重试。'
};
/**
 * 子弹后缀列表
 */
GameConstant.BULLETSUFFIXLIST = ['a', 'b', 'c', 'd', 'e', 'f'];
GameConstant.BATTERYITEMLIST = {
    BATTERY_1: 1,
    BATTERY_2: 2,
    BATTERY_3: 3,
    BATTERY_4: 4,
    BATTERY_5: 5
};
GameConstant.FLAYITEMTYPE = {
    COIN: 0,
    REDPACK: 1,
    RAGE: 2
};
GameConstant.FISHANIMATIONKEY = {
    SWIM: 'Swim',
    HIT: 'hit',
    DEAD: 'dead'
};
GameConstant.POPUPTYPE = {
    MISSIONFIAL: 0,
    MISSIONSUCCESS: 1,
    LEVELUP: 2,
    VERSIONINFO: 3,
    JIUJIBI: 4,
    AQUAMANPRIZE: 5,
    INVITEINTRO: 6,
    SHOPTIP: 7,
    REDPACKSHOPTIP: 8
};
GameConstant.MUSICTYPE = {
    BGM: 'bgm',
    COIN: 'coin',
    TOUCH: 'touch',
    SHOOT: 'shoot',
    BOOM: 'boom',
    BIGFISHDEAD: 'bigfishdead',
    BIGFISHCOIN: 'bigfishcoin',
    FAIL: 'fail'
};
GameConstant.NEWBEEINFO = {
    fishID: '233666',
    bulletID: '666233',
    fishType: 'F006'
};
GameConstant.TRACKEVENTID = {
    START: '10001',
    AUTH: '10002',
    AUTHDONE: '10003',
    LOGIN: '10004',
    LOGINDONE: '10005',
    FIRE: '10006'
};
GameConstant.SHIPTYPE = {
    ROBOT: "robot",
    USER: "user"
};
},{}],11:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-06-01 10:35:52

 * @Last Modified by: ZZL
 * @Last Modified time: 2019-12-19 16:23:26
 */
Object.defineProperty(exports, "__esModule", { value: true });
/**
 * 服务器控制参数逻辑
 * isCenterHttp : 是否走中心服务器
 * isLocalTest : 是否本地测试
 *     (isCenterHttp true) 区分_centerHttpAddr的中心服务器配置
 *     (isCenterHttp false) 区分_socketAddress的socket服务器配置
 * isTest : 是否是测试服
 *     (isCenterHttp true) 这个参数会随http消息传过去
 *     (isCenterHttp false) 区分_socketAddress的时候会参考
 * isAudit : 是否是审核，中心服务器返回结果
 */
class GameSettings {
    /**
     * 获取中心服务器地址
     */
    static get centerHttpAddr() {
        return this.isLocalTest
            ? this._centerHttpAddr.local
            : this._centerHttpAddr.public;
    }
    static get basePath() {
        // return this.isTest ? this._basePath.test : this._basePath.public
        return `${this._basePath.public}${this.nowVersionStr}/`;
    }
    static get nowVersionInfo() {
        return this.versionInfo && this.versionInfo.info[this.nowVersionStr] ? this.versionInfo.info[this.nowVersionStr] : null;
    }
    /**
     * Socket 地址公开方法
     */
    static get socketAddress() {
        return this.isCenterHttp
            ? this.serverSocket
            : this.isLocalTest
                ? this._socketAddress.local
                : this.isTest
                    ? this._socketAddress.test
                    : this._socketAddress.publish;
    }
    static get versionInfoAddress() {
        return 'https://xiazai.shycgame.com/config/gameVersion.json';
    }
    static get musicList() {
        if (!this._realMusicList) {
            this._realMusicList = {};
            Object.keys(this._musicList).forEach(element => {
                this._realMusicList[element] = `${this._musicList[element]}.${this.musicType}`;
            });
        }
        return this._realMusicList;
    }
}
exports.default = GameSettings;
GameSettings.debug = {
    showOutMessage: false,
    showInMessage: false,
    showFishLoading: false
};
/**
 * 当前版本号
 */
GameSettings.nowVersion = 2.14;
GameSettings.nowVersionStr = '2.14';
GameSettings.nowSubVersion = '2825e7d';
/**
 * 是否是本地测试
 */
GameSettings.isLocalTest = false;
/**
 * 是否网络测试
 */
GameSettings.isTest = true;
/**
 * 是否审核
 */
GameSettings.isAudit = false;
/**
 * 是否需要中心服务器预先登录
 */
GameSettings.isCenterHttp = true;
/**
 * 中心服务器地址配置
 */
GameSettings._centerHttpAddr = {
    local: 'http://10.10.10.136:9200/get_server',
    //public : 'https://loginshuban.shycgame.com/get_server'
    public: 'https://login.ifishbox.com:9200/get_server'
};
/**
 * 中心服务器返回的Socket地址
 */
GameSettings.serverSocket = '';
/**
 * 登录类型：
 * WECHAT_XIHUAN : 0,
 * WECHAT : 1,
 * ALIPAY : 2,
 * WECHAT_5124 : 3,
 * BAIDU : 4,
 * GUSET : 6,
 * APP_WECHAT : 7
 */
GameSettings.loginType = 6;
/**
 * 平台类型
 * NATIVE : 0,
 * WECHAT : 1,
 * BAIDU : 2
 */
GameSettings.platType = 0;
/**
 * 渠道号
 */
GameSettings.channelId = 'nativeTest01';
/**
 * 是否支持分享
 */
GameSettings.isNeedCheckShare = false;
/**
 *
 * 需要绑定的微信公众号
 */
GameSettings.wechatPublicAccount = '喜欢捕鱼';
/**
 * 登录按钮文字
 */
GameSettings.IOSshopLabel = null;
/**
 * 登录按钮文字
 */
GameSettings.loginBtnLabel = '测试登录';
/**
 * Logo地址
 */
GameSettings.logoAddress = 'logo/Logo_01.png';
GameSettings.isAutoLogin = true;
GameSettings.isUseBasePath = false;
GameSettings.versionInfo = null;
//微信从libs/settings.json中载入 2.11开始使用https://baidutestimg.shycgame.com/res_version/${nowVersionStr}
//上传的目录为 /res_update，运维移动资源到/res_version/${nowVersionStr}
GameSettings._basePath = {
    test: 'https://baidutestimg.shycgame.com/res_version/',
    public: 'https://baidutestimg.shycgame.com/res_version/'
};
/**
* Socket 地址设置
*/
GameSettings._socketAddress = {
    local: 'wss://zfb.shycgame.com:9002',
    test: 'wss://baidu-localtest.shycgame.com:8741',
    publish: 'wss://baidushuban.shycgame.com:8731'
};
GameSettings.audio = {
    music: 1,
    sound: 1
};
GameSettings.customQQ = '1966466364';
GameSettings.maxVip = 9;
/**
 * FishId的最大值
 */
GameSettings.maxFishId = 80000;
/**
 * Bulletd的最大值
 */
GameSettings.maxBulletId = 9000;
/**
 * 用户最多子弹数
 * -1 表示不限制
 */
GameSettings.maxUserBulletCount = -1;
/**
 * 是否使用真实支付
 */
GameSettings.isRealPay = false;
/**
 * 是否显示弹幕
 */
GameSettings.isBarrageOpen = false;
/**
 * 是否开启任务
 */
GameSettings.isMissionOpen = false;
/**
 * 是否开启购买炮台等级
 */
GameSettings.isBuyBatteryOpen = false;
/**
 * 是否开启新手任务
 */
GameSettings.isNewbeeOpen = false;
/**
 * 是否开启海王榜
 */
GameSettings.isAquamanRankOpen = true;
/**
 * 海王榜更新间隔
 */
GameSettings.aquaManRankDuration = 60000;
GameSettings.isShareNewOpen = false;
/**
 * 场景默认载入view的列表
 */
GameSettings.sceneViewList = {
    Loading: [
        'view/MainBg.scene',
        'view/Coving.scene',
        'view/Loading.scene',
        'view/AlertWindow.scene',
        'view/LogoArea.scene'
    ],
    Game: [
        'view/SystemMenu.scene',
        // 'view/MainBg.scene',
        'view/UserInfo.scene',
        'view/FishManager.scene',
        'view/Barrage.scene',
        'view/Coving.scene',
        // 'view/Loading.scene',
        'view/GetItemAward.scene',
        'view/AlertWindow.scene',
        // 'view/Shop.scene',
        // 'view/RedPackShop.scene',
        'view/Drop.scene'
        // 'view/Popup.scene',
    ],
    Shop: 'view/Shop.scene',
    RedPackShop: 'view/RedPackShop.scene',
    Mission: 'view/MissionWindow.scene',
    MissonAddon: [
        'view/MissionCountDown.scene'
    ],
    POPUP: 'view/Popup.scene',
    GETITEM: 'view/GetItemAward.scene',
    NEWBEE: "view/Newbee.scene",
    RobotUI: 'view/RobotInfo.scene',
    AQUAMAN: 'view/Rank.scene',
    SHARENEW: 'view/Share.scene',
    RechargeActivity: 'view/RechargeActivity.scene'
};
GameSettings.fishSpeedUpSpeed = 800;
GameSettings.durationList = {
    fishHitAnimation: 500,
    fishDeadAnimation: 1000,
    btnPublicCD: 1000,
    dropFlyJumpAnimation: 200,
    dropFlyJumpBackAnimation: 350,
    dropFlyWaitMoveToEndAnimation: 250,
    dropFlyToEndPosAnimation: 250,
    dropFlyInterval: 100,
    dropMultiple: 2500
};
GameSettings.goodsHasBonus = {
    coinGoods: false,
    diamondGoods: true,
    redPackRmbGoods: false,
    redPackCoinGoods: true,
    redPackVipGoods: false
};
GameSettings.coinGoods = [
    { id: 1, price: 5, value: 60000, bonus: 0 },
    { id: 2, price: 20, value: 240000, bonus: 0 },
    { id: 3, price: 100, value: 1200000, bonus: 0 },
    { id: 4, price: 200, value: 2400000, bonus: 0 },
    { id: 5, price: 500, value: 6000000, bonus: 0 },
    { id: 6, price: 1000, value: 12000000, bonus: 0 }
];
GameSettings.diamondGoods = [
    { id: 1, price: 3, value: 18, bonus: 0 },
    { id: 2, price: 12, value: 75, bonus: 3 },
    { id: 3, price: 30, value: 190, bonus: 6 },
    { id: 4, price: 108, value: 705, bonus: 9 },
    { id: 5, price: 328, value: 2205, bonus: 12 },
    { id: 6, price: 648, value: 4500, bonus: 15 }
];
GameSettings.redPackRmbGoods = [
    { id: 1, price: 100, value: 1, bonus: 0 },
    { id: 2, price: 1000, value: 10, bonus: 0 },
    { id: 3, price: 5000, value: 50, bonus: 0 },
    { id: 4, price: 20000, value: 200, bonus: 0 }
];
GameSettings.redPackCoinGoods = [
    { id: 1, price: 100, value: 74000, bonus: 3, iconId: 1 },
    { id: 2, price: 1500, value: 1128600, bonus: 4.5, iconId: 2 },
    { id: 3, price: 10800, value: 8825800, bonus: 13.5, iconId: 3 },
    { id: 4, price: 64800, value: 57153600, bonus: 22.5, iconId: 4 }
];
GameSettings.redPackVipGoods = [
    { id: 100, price: 1200, value: 14, bonus: 20 },
    { id: 101, price: 10800, value: 162, bonus: 50 },
    { id: 102, price: 32800, value: 558, bonus: 70 },
    { id: 103, price: 64800, value: 1296, bonus: 100 }
];
GameSettings.vipInfo = [
    {
        id: 1,
        value: 10,
        benfit: [
            '救济币次数增加5次',
            '红包可兑换次数增加1次'
        ],
        prize: [
            { id: 'COIN', count: '10万' },
            { id: 'DIAMOND', count: '5' },
            { id: 'GUN02', count: '' },
            { id: 'GUNDIAMOND', count: '10' }
        ]
    },
    {
        id: 2,
        value: 30,
        benfit: [
            '救济币次数增加15次',
            '红包可兑换次数增加9次'
        ],
        prize: [
            { id: 'COIN', count: '45万' },
            { id: 'DIAMOND', count: '10' },
            { id: 'GUNDIAMOND', count: '15' }
        ]
    },
    {
        id: 3,
        value: 100,
        benfit: [
            '救济币次数增加30次',
            '红包可兑换次数无限制'
        ],
        prize: [
            { id: 'COIN', count: '150万' },
            { id: 'DIAMOND', count: 50 },
            { id: 'GUN03', count: '' },
            { id: 'GUNDIAMOND', count: '20' }
        ]
    },
    {
        id: 4,
        value: 400,
        benfit: [
            '救济币次数增加45次',
            '略微增加钻石掉率'
        ],
        prize: [
            { id: 'COIN', count: '600万' },
            { id: 'DIAMOND', count: '100' },
            { id: 'GUNDIAMOND', count: '25' }
        ]
    },
    {
        id: 5,
        value: 1000,
        benfit: [
            '增加红包掉率',
            '增加钻石掉率'
        ],
        prize: [
            { id: 'COIN', count: '1500万' },
            { id: 'DIAMOND', count: '200' },
            { id: 'GUN04', count: '' },
            { id: 'GUNDIAMOND', count: '25' }
        ]
    },
    {
        id: 6,
        value: 2000,
        benfit: [
            '增加红包掉率',
            '增加钻石掉率'
        ],
        prize: [
            { id: 'COIN', count: '3000万' },
            { id: 'DIAMOND', count: '300' },
            { id: 'GUNDIAMOND', count: '25' }
        ]
    },
    {
        id: 7,
        value: 4000,
        benfit: [
            '大幅增加红包掉率',
            '大幅增加钻石掉率'
        ],
        prize: [
            { id: 'COIN', count: '6000万' },
            { id: 'DIAMOND', count: '500' },
            { id: 'GUNDIAMOND', count: '30' }
        ]
    },
    {
        id: 8,
        value: 10000,
        benfit: [
            '大幅增加红包掉率',
            '大幅增加钻石掉率'
        ],
        prize: [
            { id: 'COIN', count: '10000万' },
            { id: 'DIAMOND', count: '1000' },
            { id: 'GUNDIAMOND', count: '30' }
        ]
    },
    {
        id: 9,
        value: 30000,
        benfit: [
            '大幅增加红包掉率',
            '大幅增加钻石掉率'
        ],
        prize: [
            { id: 'COIN', count: '22500万' },
            { id: 'DIAMOND', count: '2000' },
            { id: 'GUN05', count: '' },
            { id: 'GUNDIAMOND', count: '50' }
        ]
    }
];
GameSettings.batterySetting = {
    battery_1: {
        bulletSpeed: 20,
        normalRate: 8,
        autoRate: 8,
        rageRate: 2,
        costRatio: 1
    },
    battery_2: {
        bulletSpeed: 10,
        normalRate: 8,
        autoRate: 6,
        rageRate: 2,
        costRatio: 1
    },
    battery_3: {
        bulletSpeed: 10,
        normalRate: 10,
        autoRate: 10,
        rageRate: 2,
        costRatio: 1
    },
    battery_4: {
        bulletSpeed: 30,
        normalRate: 8,
        autoRate: 8,
        rageRate: 2,
        costRatio: 1
    },
    battery_5: {
        bulletSpeed: 20,
        normalRate: 8,
        autoRate: 6,
        rageRate: 2,
        costRatio: 5
    }
};
GameSettings.itemIconList = {
    COIN: 'item/Itemcoin.png',
    DIAMON: 'item/Itemdiamond.png',
    DIAMOND: 'item/Itemdiamond.png',
    BATTERY: 'item/Itemcoin.png',
    PROP_RAGE: 'item/Itemgundiamond.png',
    PROP_TORPEDO_1: 'item/Itemcoin.png',
    PROP_TORPEDO_2: 'item/Itemcoin.png',
    PROP_TORPEDO_3: 'item/Itemcoin.png',
    PROP_TORPEDO_4: 'item/Itemcoin.png',
    PROP_TORPEDO_5: 'item/Itemcoin.png',
    PROP_REST: 'item/Itemcoin.png',
    BATTERY_2: 'item/Itemgun03.png',
    BATTERY_3: 'item/Itemgun02.png',
    BATTERY_4: 'item/Itemgun04.png',
    BATTERY_5: 'item/Itemgun05.png',
    BATTERY_6: 'item/Itemgun06.png',
    BATTERY_7: 'item/Itemgun07.png',
    BATTERY_8: 'item/Itemgun08.png',
    BATTERY_9: 'item/Itemgun09.png',
    BATTERY_10: 'item/Itemgun10.png',
    REDPACKET: 'item/DropItemredpack.png',
    VIP: 'item/Itemcoin.png',
    DROP_REDPACKET: 'item/DropItemredpack.png',
    DROP_DIAMOND: 'item/DropItemdiamond.png',
    DROP_PROP_RAGE: 'item/DropItemrage.png',
    DROP_BATTERY_2: 'gun/gun_02_on.png',
    DROP_BATTERY_3: 'gun/gun_03_on.png',
    DROP_BATTERY_4: 'gun/gun_04_on.png',
    DROP_BATTERY_5: 'gun/gun_05_on.png',
    DROP_ROBOTCOIN: 'item/Itemcoin.png',
};
GameSettings.itemInfo = [
    {
        propId: 'PROP_RAGE',
        currencyValue: 3,
        name: '狂暴',
        propDesc: '使用后可以获得金币*2,发炮速度变快',
        timeOfDuration: 30
    },
    {
        propId: 'PROP_REST',
        currencyValue: 0,
        name: '免战牌',
        propDesc: '免战',
        timeOfDuration: 31536000
    }
];
GameSettings.missionPrize = "";
GameSettings.supportBatteryList = [1, 2, 3, 4, 5];
GameSettings.fishSettingPrefix = 'fish/set/';
GameSettings.fishBingoPrefix = 'bingo/set2/';
GameSettings.useWindowDebug = false;
GameSettings.isEditorTest = false;
GameSettings.editorTestViewList = [
    'testScene/test_fish_drop_item.scene'
];
GameSettings.coinDropSetting = {
    F001: 5,
    F002: 5,
    F003: 5,
    F004: 5,
    F005: 5,
    F006: 5,
    F007: 5,
    F008: 5,
    F009: 5,
    F010: 5,
    F011: 5,
    F012: 5,
    F013: 5,
    F014: 5,
    F015: 5,
    F016: 5,
    F017: 5,
    F018: 5
};
GameSettings.fishHasBingoList = ['F006', 'F007', 'F008', 'F009', 'F012', 'F021', 'F022', 'F023', 'F024', 'F025', 'F026', 'F027'];
GameSettings.fishIsGatherList = ['F023', 'F024', 'F025', 'F026', 'F027'];
GameSettings.fishRandomDuration = 1000;
GameSettings.fishDefalutScale = 2;
GameSettings.bulletDefaultSpeed = 5;
GameSettings.userMaxBulletCount = 50;
GameSettings.MISSIONFISHTIPS = {
    // 'F003':{"tipsText":"鲸鱼需达到5级才会出现","fishIcon":"mission/task_01.png"},
    // 'F004':{"tipsText":"鲸鱼需达到5级才会出现","fishIcon":"mission/task_02.png"},
    // 'F005':{"tipsText":"鲸鱼需达到5级才会出现","fishIcon":"mission/task_03.png"},
    // 'F006':{"tipsText":"鲸鱼需达到5级才会出现","fishIcon":"mission/meiriF009_01.png"},
    // 'F007':{"tipsText":"鲸鱼需达到5级才会出现","fishIcon":"mission/meiriF009_01.png"},
    'F008': { "tipsText": "金蟾需达到11级才会出现", "fishIcon": "mission/meiriF008_01.png" },
    'F009': { "tipsText": "鲸鱼需达到6级才会出现", "fishIcon": "mission/meiriF009_01.png" }
};
GameSettings.MISSIONSPICONPATH = {
    'F011': 'mission/task_01.png',
    'F012': 'mission/task_02.png',
    'F013': 'mission/task_03.png',
};
GameSettings.POPUPBG = {
    FAIL: 'popup/jiqiaoshibai_01.png',
    WIN: 'popup/jiqiaochenggong_01.png'
};
GameSettings.POPUPTIPS = {
    MISSIONFAIL: '很遗憾，任务失败 \n 请从前置任务重新开始',
    MISSIONWIN: '挑战成功,\n 明日登录领取奖励'
};
GameSettings.MISSIONBTNPATH = {
    Finish: 'mission/buttonjiqiao_01.png',
    F008: 'mission/meiriF008_01.png',
    F009: 'mission/meiriF009_01.png'
};
GameSettings.MISSIONWAITTIME = 5000; //5秒
GameSettings.musicType = 'ogg';
GameSettings._musicList = {
    bgm: `music/bgm`,
    boom: `music/boom`,
    coin: `music/coin`,
    shoot: `music/shoot`,
    yuleiboom: `music/yuleiboom`,
    touch: `music/touch`,
    shipdead: `music/shipdead`,
    pkwin: `music/PKWinBg`,
    bigfishdead: `music/largeFishDead`,
    bigfishcoin: `music/largeFishDeadDropCoin`,
    fail: `music/fail`
};
GameSettings._realMusicList = null;
GameSettings.wxPayParam = {
    mode: 'game',
    offerId: '1450016426',
    currencyType: 'CNY',
    zoneId: 1,
    platform: "android",
    env: 0,
};
GameSettings.DropItemFishList = {
    F006: 'REDPACKET',
    F007: 'REDPACKET',
    F008: 'REDPACKET',
    F009: 'REDPACKET',
    F022: 'REDPACKET'
};
GameSettings.isNative = false;
GameSettings.isNativeIos = false;
GameSettings.isNativeAndroid = false;
GameSettings.nativeChargeAddres = '';
GameSettings.isSendTrack = true;
GameSettings.trackAddress = 'http://10.10.10.136:9300/track';
},{}],12:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie.Robin
 * @Date: 2019-05-28 15:54:58
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-12-02 15:42:03
 */
Object.defineProperty(exports, "__esModule", { value: true });
const GameConfig_1 = require("./GameConfig");
const GameSettings_1 = require("./GameSettings");
const GameCenter_1 = require("./Control/GameCenter");
const PostOffice_1 = require("./Control/PostOffice");
const PlatformNative_1 = require("./Control/PlatformNative");
const GameConstant_1 = require("./GameConstant");
const TarsisHttp_1 = require("./utils/TarsisHttp");
const IntentControl_1 = require("./Control/IntentControl");
class Main {
    constructor() {
        //根据IDE设置初始化引擎		
        if (window["Laya3D"])
            Laya3D.init(GameConfig_1.default.width, GameConfig_1.default.height);
        else
            Laya.init(GameConfig_1.default.width, GameConfig_1.default.height, Laya["WebGL"]);
        Laya["Physics"] && Laya["Physics"].enable();
        Laya["DebugPanel"] && Laya["DebugPanel"].enable();
        Laya.stage.scaleMode = GameConfig_1.default.scaleMode;
        Laya.stage.screenMode = GameConfig_1.default.screenMode;
        //兼容微信不支持加载scene后缀场景
        Laya.URL.exportSceneToJson = GameConfig_1.default.exportSceneToJson;
        //打开调试面板（通过IDE设置调试模式，或者url地址增加debug=true参数，均可打开调试面板）
        if (GameConfig_1.default.debug || Laya.Utils.getQueryString("debug") == "true")
            Laya.enableDebugPanel();
        if (GameConfig_1.default.physicsDebug && Laya["PhysicsDebugDraw"])
            Laya["PhysicsDebugDraw"].enable();
        if (GameConfig_1.default.stat)
            Laya.Stat.show();
        Laya.alertGlobalError = true;
        //激活资源版本控制，version.json由IDE发布功能自动生成，如果没有也不影响后续流程
        Laya.ResourceVersion.enable("version.json", Laya.Handler.create(this, this.onVersionLoaded), Laya.ResourceVersion.FILENAME_VERSION);
    }
    onVersionLoaded() {
        //激活大小图映射，加载小图的时候，如果发现小图在大图合集里面，则优先加载大图合集，而不是小图
        Laya.AtlasInfoManager.enable("fileconfig.json", Laya.Handler.create(this, this.onConfigLoaded));
    }
    onConfigLoaded() {
        Laya.loader.load("settings/systemSettings.json", Laya.Handler.create(this, (settings) => {
            GameSettings_1.default.coinGoods = settings.coinGoods;
            GameSettings_1.default.diamondGoods = settings.diamondGoods;
            GameSettings_1.default.vipInfo = settings.vipInfo;
            GameSettings_1.default.redPackCoinGoods = settings.redPackCoinGoods;
            GameSettings_1.default.redPackRmbGoods = settings.redPackRmbGoods;
            GameSettings_1.default.redPackVipGoods = settings.redPackVipGoods;
            GameSettings_1.default.goodsHasBonus = settings.goodsHasBonus;
            GameSettings_1.default.batterySetting = settings.batterySetting;
        }));
        TarsisHttp_1.default.StartHttpCall({
            url: GameSettings_1.default.versionInfoAddress,
            data: {
                time: new Date().getTime()
            },
            onSuccess: (data) => {
                // console.log(data)
                // console.log(JSON.parse(data))
                GameSettings_1.default.versionInfo = JSON.parse(data);
                console.log("GameSettings.isTest:", GameSettings_1.default.isTest);
                GameSettings_1.default.isTest = GameSettings_1.default.versionInfo.testServer[GameSettings_1.default.nowVersionStr];
            },
            onError: (e) => {
                console.log(e);
            }
        });
        let gc = new GameCenter_1.default();
        let po = new PostOffice_1.default();
        gc.postOffice = po;
        window['GameSettings'] = GameSettings_1.default;
        window['GameConstant'] = GameConstant_1.default;
        window['GameCenter'] = gc;
        gc.nowScene = GameConstant_1.default.SCENETYPE.LOADING;
        if (window['PlatformSettings']) {
            const settings = window['PlatformSettings'];
            Object.keys(settings).forEach(element => {
                if (GameSettings_1.default.hasOwnProperty(element)) {
                    GameSettings_1.default[element] = settings[element];
                }
            });
        }
        if (Laya.Browser.window.conch) {
            GameSettings_1.default.isNative = true;
            let settingsAdd = null;
            const os = Laya.Browser.window.conchConfig.getOS();
            if (os == 'Conch-ios') {
                console.log('[PF] Run On IOS System');
                GameSettings_1.default.isNativeIos = true;
                settingsAdd = 'settings/nativeIosSettings.json';
            }
            else if (os == 'Conch-android') {
                console.log('[PF] Run On Android System');
                GameSettings_1.default.isNativeAndroid = true;
                settingsAdd = 'settings/nativeAndroidSettings.json';
            }
            if (settingsAdd) {
                Laya.loader.load(settingsAdd, Laya.Handler.create(this, (settings) => {
                    Object.keys(settings).forEach(element => {
                        if (GameSettings_1.default.hasOwnProperty(element)) {
                            GameSettings_1.default[element] = settings[element];
                        }
                    });
                    IntentControl_1.default.init();
                }));
            }
        }
        if (Laya.LocalStorage.getItem(GameConstant_1.default.LOCALSTORAGEKEY.TRACE)) {
            GameSettings_1.default.isSendTrack = false;
        }
        if (GameSettings_1.default.isSendTrack) {
            gc.sendTrace({
                eventId: GameConstant_1.default.TRACKEVENTID.START
            });
        }
        // 测试载入资源重写GameSettings Native Settings
        // GameSettings.isNative = true
        // GameSettings.isNativeIos = true
        // const tempAdd = 'settings/nativeIosSettings.json'
        // Laya.loader.load(tempAdd,Laya.Handler.create(this,(settings)=>{
        // 	Object.keys(settings).forEach(element => {
        // 		if(GameSettings[element]){
        // 			GameSettings[element] = settings[element]
        // 		}
        // 	})
        // }))
        gc.platform = new PlatformNative_1.default();
        gc.inviteId = '';
        switch (GameSettings_1.default.platType) {
            case GameConstant_1.default.PLATTYPE.WECHAT:
                gc.platform = window['wx'];
                //获取渠道名
                let channelInfo = gc.platform.getLaunchOptionsSync();
                console.log('===== getLaunchOptionsSync info is : ');
                console.log(channelInfo);
                if (channelInfo) {
                    if (channelInfo.query.channel) {
                        GameSettings_1.default.channelId = channelInfo.query.channel;
                    }
                    if (channelInfo.query.inviteId) {
                        gc.inviteId = channelInfo.query.inviteId;
                    }
                }
                break;
            case GameConstant_1.default.PLATTYPE.BAIDU:
                gc.platform = window['swan'];
                break;
        }
        gc.platform.setKeepScreenOn({
            keepScreenOn: true
        });
        gc.platform.getSystemInfo({
            success: (res) => {
                gc.systemInfo = res;
            }
        });
        //设置远程地址
        if (GameSettings_1.default.isUseBasePath) {
            // Laya.URL.basePath = "https://baidutestimg.shycgame.com/res/newui/"
            Laya.URL.basePath = GameSettings_1.default.basePath;
        }
        //判断是否是编辑修改模式
        if (GameSettings_1.default.isEditorTest) {
            Laya.Scene.open('scene/Test.scene');
        }
        else {
            //加载IDE指定的场景
            GameConfig_1.default.startScene && Laya.Scene.open(GameConfig_1.default.startScene);
        }
    }
}
//激活启动类
new Main();
},{"./Control/GameCenter":3,"./Control/IntentControl":4,"./Control/PlatformNative":6,"./Control/PostOffice":7,"./GameConfig":9,"./GameConstant":10,"./GameSettings":11,"./utils/TarsisHttp":67}],13:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-28 20:43:35
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-05-29 10:56:45
 */
Object.defineProperty(exports, "__esModule", { value: true });
const GameCenter_1 = require("../Control/GameCenter");
const ExtBaseButton_1 = require("../extends/ExtBaseButton");
const GameConstant_1 = require("../GameConstant");
const GameSettings_1 = require("../GameSettings");
class AlertControl extends Laya.Script {
    constructor() {
        super();
        this.isShowing = false;
    }
    onEnable() {
        this.GC = GameCenter_1.default.instance;
        this.self = this.owner;
        this.componentTitle = this.self['title'];
        this.componentDesc = this.self['desc'];
        this.componentAddonDesc = this.self['addon'];
        this.componentAddonDesc1 = this.self['addon1'];
        this.componentBtnSure = this.self['sure'];
        this.componentBtnSureExt = this.componentBtnSure.getComponent(ExtBaseButton_1.default);
        this.componentBtnCancel = this.self['cancel'];
        this.componentBtnCancelExt = this.componentBtnCancel.getComponent(ExtBaseButton_1.default);
        this.setAlert(false);
    }
    onUpdate() {
        if (this.isShowing != this.GC.status.isOnAlert) {
            this.setAlert(this.GC.status.isOnAlert);
        }
    }
    setAlert(flag) {
        this.isShowing = flag;
        if (this.isShowing) {
            const info = this.GC.status.alertInfo;
            this.componentTitle.text = info.title;
            this.componentDesc.text = info.desc;
            this.componentAddonDesc.text = GameConstant_1.default.PROMOTIONTEXT.PUBLICACCOUNT.replace('$pa$', GameSettings_1.default.wechatPublicAccount);
            this.componentAddonDesc1.text = GameConstant_1.default.PROMOTIONTEXT.CUSTOMQQ.replace('$qq$', GameSettings_1.default.customQQ); //info.addon
            this.componentBtnCancel.visible = info.needCancel;
            this.componentBtnSure.pos(info.needCancel ? 650 : 450, this.componentBtnSure.y);
            this.componentBtnSureExt.setLabelText(info.sureText);
            this.componentBtnSureExt.setCallback(() => {
                info.onSure();
            });
            this.componentBtnCancelExt.setLabelText(info.cancelText);
            this.componentBtnCancelExt.setCallback(() => {
                info.onCancel();
            });
        }
        this.self.visible = flag;
    }
}
exports.default = AlertControl;
},{"../Control/GameCenter":3,"../GameConstant":10,"../GameSettings":11,"../extends/ExtBaseButton":61}],14:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const GameConstant_1 = require("../GameConstant");
const AquaManRankItemControl_1 = require("./AquaManRankItemControl");
const ExtBaseButton_1 = require("../extends/ExtBaseButton");
const GameCenter_1 = require("../Control/GameCenter");
const Tarsis_1 = require("../utils/Tarsis");
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-12-02 15:43:55
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-12-02 17:51:23
 */
class AquaManRankControl extends Tarsis_1.ViewControl {
    constructor() {
        super(...arguments);
        this.handler = null;
        this.rankItemPosListY = [
            350, 470, 590, 710, 830, 950, 1070, 1190, 1310, 1430
        ];
        this.rankItemPopX = 55;
        this.rankItemList = [];
        this.isShow = false;
        this.isRuleShow = false;
    }
    onEnable() {
        super.onEnable();
        this.GC = GameCenter_1.default.instance;
        this.filtAllChildren(this.onFilterChildren);
        for (let index = 0; index < 10; index++) {
            const item = this.getRankItem();
            this.self.addChild(item.pos(this.rankItemPopX, this.rankItemPosListY[index]));
            this.rankItemList.push(item.getComponent(AquaManRankItemControl_1.default));
        }
        window['aquaman'] = this;
        this.setShow(false);
        this.GC.registComponent(GameConstant_1.default.GAMECOMPONENT.AQUAMAN, this, (handler) => {
            this.handler = handler;
        });
    }
    onFilterChildren(element, view) {
        switch (element.name) {
            // case 'RankRewardDescLabel':
            //   view.rankDescLabel = element as Laya.Label
            //   break
            case 'User':
                for (let index = 0; index < element.numChildren; index++) {
                    const el = element.getChildAt(index);
                    view.onFilterChildren(el, view);
                }
                break;
            case 'NoRank':
                view.selfNoRankLabel = element;
                break;
            case 'SelfRankLabel':
                view.selfRankLabel = element;
                break;
            case 'SelfCountLabel':
                view.selfCountLabel = element;
                break;
            case 'SelfRewardLabel':
                view.selfRewardLabel = element;
                break;
            case 'close':
                view.closeButton = element.getComponent(ExtBaseButton_1.default);
                view.closeButton.setCallback(() => {
                    let handler = view.handler;
                    if (handler) {
                        handler.runWith(GameConstant_1.default.USERACTIONTYPE.CLOSEAQUAMANRANK);
                    }
                });
                break;
            case 'noListBg':
                view.noListBg = element;
                break;
            case 'ruleImage':
                view.ruleImage = element;
                view.ruleImage.visible = false;
                break;
            case 'ruleBg':
                view.ruleBg = element;
                view.ruleBg.visible = false;
                view.ruleBg.on(Laya.Event.CLICK, this, () => {
                    view.showRule(false);
                });
                break;
            case 'btnRule':
                view.ruleBtn = element.getComponent(ExtBaseButton_1.default);
                view.ruleBtn.setCallback(() => {
                    view.showRule(!view.isRuleShow);
                });
        }
    }
    showRule(flag = true) {
        this.ruleBg.visible = flag;
        this.ruleImage.visible = flag;
    }
    onUpdate() {
        if (this.isShow != this.GC.status.isOnAquaManRank) {
            this.isShow = this.GC.status.isOnAquaManRank;
            if (this.isShow) {
                this.setInfo(this.GC.status.aquaManRankSetting);
            }
            this.setShow(this.isShow);
        }
    }
    getRankItem() {
        return Laya.Pool.getItemByCreateFun(`AquaManRankItem`, this.rankItem.create, this.rankItem);
    }
    setInfo(info) {
        let list = info.info.sort((a, b) => { return a.seq < b.seq ? -1 : 1; });
        for (let index = 0; index < this.rankItemList.length; index++) {
            const element = this.rankItemList[index];
            if (index < list.length) {
                element.setInfo(list[index]);
                element.view.visible = true;
            }
            else {
                element.view.visible = false;
            }
        }
        // uid	string	用户id	
        // nick	string	昵称	
        // consume	long	流水	0
        // redPack	int	红包(奖励)	0
        // seq	int	名次	
        this.selfRankLabel.value = "";
        if (info.self.seq > 0) {
            this.selfNoRankLabel.visible = false;
            this.selfRankLabel.value = `第${info.self.seq}名`;
        }
        else {
            this.selfNoRankLabel.visible = true;
        }
        this.selfCountLabel.value = (`${info.self.consume}`);
        this.selfRewardLabel.value = (info.self.redPack > 0 ? `${info.self.redPack}红包` : '无');
        //this.rankDescLabel.value(info.desc)
        this.noListBg.visible = list.length == 0;
    }
}
exports.default = AquaManRankControl;
},{"../Control/GameCenter":3,"../GameConstant":10,"../extends/ExtBaseButton":61,"../utils/Tarsis":66,"./AquaManRankItemControl":15}],15:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const Tarsis_1 = require("../utils/Tarsis");
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-12-02 15:55:21
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-12-02 17:51:25
 */
class AquaManRankItemControl extends Tarsis_1.ViewControl {
    onEnable() {
        super.onEnable();
        this.filtAllChildren(this.onFilteElement);
    }
    onFilteElement(element, view) {
        switch (element.name) {
            case 'Rankicon':
                view.rankIcon = element;
                break;
            case 'RankLabel':
                view.rankLabel = element;
                break;
            case 'NameLabel':
                view.nameLabel = element;
                break;
            case 'CountLabel':
                view.countLabel = element;
                break;
            case 'rewardLabel':
                view.rewardLabel = element;
                break;
            case 'Rankbg':
                view.rankBg = element;
                break;
        }
    }
    setInfo(info) {
        // uid	string	用户id	
        // nick	string	昵称	
        // consume	long	流水	0
        // redPack	int	红包(奖励)	0
        // seq	int	名次	
        this.rankLabel.changeText(`${info.seq}`);
        this.nameLabel.changeText(info.nick.length > 8 ? `${info.nick.substr(0, 6)}...` : `${info.nick}`);
        this.countLabel.changeText(`${info.consume}`);
        this.rewardLabel.changeText(`${info.redPack}`);
        this.rankIcon.visible = info.seq <= 3;
        this.rankLabel.visible = info.seq > 3;
        this.rankBg.skin = `rank/Rankitembg_04.png`;
        if (info.seq <= 3) {
            this.rankIcon.skin = `rank/Rank_0${info.seq}.png`;
            this.rankBg.skin = `rank/Rankitembg_0${info.seq}.png`;
        }
    }
}
exports.default = AquaManRankItemControl;
},{"../utils/Tarsis":66}],16:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-29 14:43:48
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-05-29 15:17:20
 */
Object.defineProperty(exports, "__esModule", { value: true });
const GameCenter_1 = require("../Control/GameCenter");
class BarrageControl extends Laya.Script {
    constructor() {
        super();
        this.isShowing = false;
        this.length = 900;
        this.percentOnFihish = 0.7;
    }
    onEnable() {
        this.GC = GameCenter_1.default.instance;
        this.self = this.owner;
        this.html = this.self['barrageTextHtml'];
        this.html.style.fontSize = 50;
        this.html.style.color = "#FFFFFF";
        this.html.style.wordWrap = false;
        this.setBarrage(false);
    }
    onUpdate() {
        if (this.isShowing != this.GC.status.isOnBarrage) {
            this.setBarrage(this.GC.status.isOnBarrage);
        }
        if (this.isShowing) {
            this.html.pos(this.html.x - this.speed, this.html.y);
            if (this.html.x + this.html.width * this.percentOnFihish <= 0) {
                this.onFinish();
            }
        }
    }
    setBarrage(flag) {
        this.isShowing = flag;
        this.self.visible = flag;
        if (this.isShowing) {
            const info = this.GC.status.barrageInfo;
            this.html.innerHTML = info.text;
            this.html.pos(this.length, this.html.y);
            this.speed = info.speed;
            this.onFinish = info.onFinish;
        }
    }
}
exports.default = BarrageControl;
},{"../Control/GameCenter":3}],17:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie.Robin
 * @Date: 2019-05-28 15:55:56
 * @Last Modified by: ZZL
 * @Last Modified time: 2019-11-08 16:12:06
 */
Object.defineProperty(exports, "__esModule", { value: true });
const BatteryComponent_1 = require("../extends/BatteryComponent");
const GameConstant_1 = require("../GameConstant");
const BatteryInfo_1 = require("../extends/BatteryInfo");
const BulletControl_1 = require("./BulletControl");
const GameCenter_1 = require("../Control/GameCenter");
var Pool = Laya.Pool;
const AudioManager_1 = require("../Control/AudioManager");
class BatteryControl extends Laya.Sprite {
    constructor() {
        super();
        this.barrelList = [];
        this.barrelPosList = [];
        this.fireList = [];
        this.batteryInfo = null;
        this.isInit = false;
        this.fireAnimationPlaying = false;
    }
    onEnable() {
        this.GC = GameCenter_1.default.instance;
        if (!this.isInit) {
            this.init();
        }
    }
    init() {
        this.batteryInfo = this.getComponent(BatteryInfo_1.default);
        this._children.forEach(element => {
            let sprite = element;
            let info = sprite.getComponent(BatteryComponent_1.default);
            if (info) {
                switch (info.componentType) {
                    case GameConstant_1.default.BATTERYCOMPONENT.BARREL:
                        this.barrelList.push(sprite);
                        this.barrelPosList.push(new Laya.Point(sprite.x, sprite.y));
                        break;
                    case GameConstant_1.default.BATTERYCOMPONENT.FIRE:
                        if (this.batteryInfo) {
                            let fire = new Laya.Image(this.batteryInfo.fireImage);
                            fire.pivot(fire.width / 2, fire.height).scale(this.batteryInfo.fireScale, this.batteryInfo.fireScale).pos(sprite.x, sprite.y);
                            fire.rotation = sprite.rotation;
                            this.addChild(fire);
                            fire.scale(0, 0);
                            this.fireList.push(fire);
                        }
                        break;
                }
            }
        });
        this.isInit = true;
    }
    fireOnce(bulletId) {
        if (!this.fireAnimationPlaying) {
            //[AUDIO]=======[AUDIO]
            AudioManager_1.default.instance.playSound(GameConstant_1.default.MUSICTYPE.SHOOT);
            this.fireAnimationPlaying = true;
            const aniTotalDuration = 1000 / this.GC.fireStatus.rate * 0.9;
            for (let index = 0; index < this.barrelList.length; index++) {
                const element = this.barrelList[index];
                const point = this.barrelPosList[index];
                Laya.Tween.to(element, { y: point.y + this.batteryInfo.barrelMoveLength }, aniTotalDuration * 0.2, Laya.Ease.bounceIn);
                Laya.Tween.to(element, { y: point.y }, aniTotalDuration * 0.7, Laya.Ease.bounceOut, null, aniTotalDuration * 0.5);
            }
            this.fireList.forEach(element => {
                element.scale(0, 0);
                Laya.timer.once(aniTotalDuration * 0.2, this, () => {
                    element.scale(this.batteryInfo.fireScale, this.batteryInfo.fireScale);
                    Laya.timer.once(aniTotalDuration * 0.3, this, () => {
                        element.scale(0, 0);
                    });
                });
            });
            Laya.timer.once(aniTotalDuration, this, () => {
                this.fireAnimationPlaying = false;
            });
        }
        if (this.fireList.length > 0 && this.GC.bulletHolder) {
            let idList = [bulletId];
            const count = this.fireList.length;
            if (count > 1) {
                for (let i = 0; i < count - 1; i++) {
                    idList.push(`${bulletId}-${GameConstant_1.default.BULLETSUFFIXLIST[i]}`);
                }
            }
            for (let index = 0; index < this.fireList.length; index++) {
                const element = this.fireList[index];
                let firePos = this.localToGlobal(new Laya.Point(element.x, element.y));
                let barrelPos = this.batteryInfo.isParallelBarrel
                    ? this.localToGlobal(new Laya.Point(element.x, this.pivotY))
                    : this.localToGlobal(new Laya.Point(this.pivotX, this.pivotY));
                let bullet = this.getBullet(bulletId);
                bullet.zOrder = 5;
                let firDir = new Laya.Vector2(firePos.x - barrelPos.x, firePos.y - barrelPos.y);
                this.GC.bulletHolder.addChild(bullet.pos(firePos.x, firePos.y));
                let bc = bullet.getComponent(BulletControl_1.default);
                bc.init(idList[index], 50, firDir, this.batteryInfo.fishNetScale);
            }
        }
    }
    getBullet(bulletId) {
        let bullet;
        if (this.GC.fireStatus.rage && bulletId.indexOf("robot") == -1) {
            bullet = Pool.getItemByCreateFun(this.batteryInfo.diamondBulletTypeId, this.batteryInfo.diamondBullet.create, this.batteryInfo.diamondBullet);
            bullet.scale(this.batteryInfo.diamondBulletScale, this.batteryInfo.diamondBulletScale);
        }
        else {
            bullet = Pool.getItemByCreateFun(this.batteryInfo.normalBulletTypeId, this.batteryInfo.normalBullet.create, this.batteryInfo.normalBullet);
            bullet.scale(this.batteryInfo.normalBulletScale, this.batteryInfo.normalBulletScale);
        }
        let bc = bullet.getComponent(BulletControl_1.default);
        bc.speed = this.GC.fireStatus.speed;
        return bullet;
    }
}
exports.default = BatteryControl;
},{"../Control/AudioManager":1,"../Control/GameCenter":3,"../GameConstant":10,"../extends/BatteryComponent":59,"../extends/BatteryInfo":60,"./BulletControl":18}],18:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-28 15:58:20
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-07-05 20:47:44
 */
Object.defineProperty(exports, "__esModule", { value: true });
var Pool = Laya.Pool;
var Vector2 = Laya.Vector2;
const Tarsis_1 = require("../utils/Tarsis");
const GameCenter_1 = require("../Control/GameCenter");
const FishNetControl_1 = require("./FishNetControl");
class BulletControl extends Laya.Script {
    constructor() {
        super();
        this.isInit = false;
        this.isMainUser = true;
        this.gunValue = 50;
        this.isLockFish = false;
        this.lockedFish = null;
        this.fishNetScale = 1;
    }
    init(id, gunValue, dir, fishNetScale = 1, isMainUser = true, lockedFish = null) {
        this.bulletId = id;
        this.direction = dir;
        this.gunValue = gunValue;
        this.isMainUser = isMainUser;
        this.isLockFish = lockedFish ? true : false;
        this.lockedFish = lockedFish;
        this.fishNetScale = fishNetScale;
        this.self = this.owner;
        this.isInit = true;
    }
    onEnable() {
        this.GC = GameCenter_1.default.instance;
    }
    onUpdate() {
        if (this.isInit) {
            if (this.isLockFish && this.lockedFish && !this.lockedFish.isDead) {
                this.checkDir();
            }
            else {
                this.isLockFish = false;
            }
            this.bulletMove();
            this.checkBorder();
            this.checkHit();
        }
    }
    onDisable() {
        Pool.recover(this.bulletType, this.owner);
    }
    removeBullet() {
        this.playDead();
    }
    checkDir() {
        let pos = new Laya.Point(this.lockedFish.owner.x, this.lockedFish.owner.y);
        let localPos = this.self.globalToLocal(new Laya.Point(pos.x, pos.y));
        let selfPos = this.self.globalToLocal(new Laya.Point(this.self.x, this.self.y));
        this.direction = Tarsis_1.default.Vector2Normalize(new Vector2(localPos.x - selfPos.x, localPos.y - selfPos.y));
        this.setRotation();
    }
    bulletMove() {
        let d = this.speed * Laya.timer.delta / 1000;
        let v = new Vector2(this.direction.x * d, this.direction.y * d);
        this.self.pos(this.self.x + v.x, this.self.y + v.y);
    }
    checkBorder() {
        if ((this.self.x > Laya.stage.width && this.direction.x > 0) || (this.self.x < 0 && this.direction.x < 0)) {
            this.direction = new Vector2(-this.direction.x, this.direction.y);
        }
        else if ((this.self.y > Laya.stage.height && this.direction.y > 0) || (this.self.y < 0 && this.direction.y < 0)) {
            this.direction = new Vector2(this.direction.x, -this.direction.y);
        }
        this.setRotation();
    }
    checkHit() {
        const fishList = this.GC.checkHit({
            x: this.self.x,
            y: this.self.y,
            multiHit: this.isMuiltHit,
            checkRadius: this.self.width / 2 * 0.9,
            report: this.isReportHit,
            bulletId: this.bulletId
        });
        if (fishList.length > 0) {
            if (this.isReportHit) {
                fishList.forEach((element) => {
                    element.playHit();
                });
            }
            const net = this.getFishNet();
            net.zOrder = 5;
            this.GC.fishHolder.addChild(net.pos(this.self.x, this.self.y));
            const nc = net.getComponent(FishNetControl_1.default);
            nc.playEffect(this.bulletId, this.gunValue, this.fishNetScale);
            this.playDead();
        }
    }
    setRotation() {
        let degree = Tarsis_1.default.Vector2Angle(new Vector2(0, -1), this.direction);
        if (this.direction.x < 0) {
            degree = -degree;
        }
        this.self.rotation = degree;
    }
    playDead() {
        this.isInit = false;
        this.owner.removeSelf();
    }
    getFishNet() {
        return Pool.getItemByCreateFun(this.fishNetType, this.fishNet.create, this.fishNet);
    }
}
exports.default = BulletControl;
},{"../Control/GameCenter":3,"../utils/Tarsis":66,"./FishNetControl":31}],19:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-06-20 15:23:21
 * @Last Modified by: ZZL
 * @Last Modified time: 2019-06-21 14:34:13
 */
class CoinDisplayControl extends Laya.FontClip {
    onEnable() {
    }
    setup(settings) {
        this.value = settings.value;
        Laya.timer.once(settings.timeOut * 1000, this, this.removeSelf, null, false);
    }
    onDisable() {
        Laya.Pool.recover("CoinDisplay", this);
    }
}
exports.default = CoinDisplayControl;
},{}],20:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const GameCenter_1 = require("../Control/GameCenter");
const GameConstant_1 = require("../GameConstant");
/*
 * @Author: ZZL
 * @Date: 2019-06-28 14:15:35
 * @Last Modified by: ZZL
 * @Last Modified time: 2019-07-05 14:04:08
 */
class CountDownControl extends Laya.View {
    constructor() {
        super(...arguments);
        this.isInit = false;
        this.missionState = 0; // 0  1  2
        this.timeleft = 0;
    }
    onEnable() {
        this.GC = GameCenter_1.default.instance;
        this.GC.registComponent(GameConstant_1.default.GAMECOMPONENT.COUNTDOWN, this, (handler) => {
        });
        this.isInit = true;
        this.visible = false;
        Laya.timer.frameLoop(1, this, this.update); //loop(100,this,this.update);
    }
    update() {
        if (this.isInit) {
            if (!this.GC.status.isOnCountDown) {
                this.timeleft = 0;
                if (this.visible) {
                    this.visible = false;
                }
                return;
            }
            if (!this.visible && this.GC.status.isOnCountDown) {
                this.visible = this.GC.status.isOnCountDown;
                this.timeleft = this.GC.status.countDownInfo.time;
            }
            if (this.visible && this.timeleft > 0) {
                this.timeleft -= Laya.timer.delta;
                this['clip'].value = Math.floor(this.timeleft / 1000);
                if (this.timeleft <= 0) {
                    this.GC.status.isOnCountDown = false;
                }
            }
        }
    }
}
exports.default = CountDownControl;
},{"../Control/GameCenter":3,"../GameConstant":10}],21:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-29 10:30:51
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-05-29 11:19:17
 */
Object.defineProperty(exports, "__esModule", { value: true });
const GameCenter_1 = require("../Control/GameCenter");
class CovingControl extends Laya.Script {
    constructor() {
        super();
        this.isShowing = false;
    }
    onEnable() {
        this.GC = GameCenter_1.default.instance;
        this.self = this.owner;
        this.componentCover = this.self['cover'];
        this.self.size(Laya.stage.width, Laya.stage.height);
        if (this.componentCover) {
            this.componentCover.size(Laya.stage.width, Laya.stage.height).pos(0, 0);
        }
        this.setCoving(false);
    }
    onUpdate() {
        if (this.isShowing != this.GC.status.isOnCoving) {
            this.setCoving(this.GC.status.isOnCoving);
        }
    }
    setCoving(flag) {
        this.isShowing = flag;
        this.self.visible = flag;
        this.self.mouseThrough = !this.isShowing;
        this.self.mouseEnabled = this.isShowing;
    }
}
exports.default = CovingControl;
},{"../Control/GameCenter":3}],22:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-06-20 14:43:18
 * @Last Modified by: ZZL
 * @Last Modified time: 2019-11-06 14:51:37
 */
Object.defineProperty(exports, "__esModule", { value: true });
const GameCenter_1 = require("../Control/GameCenter");
const GameSettings_1 = require("../GameSettings");
const GameConstant_1 = require("../GameConstant");
const FlyControl_1 = require("./FlyControl");
const DropItemInfo_1 = require("./DropItemInfo");
const AudioManager_1 = require("../Control/AudioManager");
class DropControl extends Laya.View {
    constructor() {
        super(...arguments);
        this.setting = {
            start: null,
            end: null,
            itemType: 'DIAMOND',
            callback: null,
            item: null
        };
    }
    onEnable() {
        this.GC = GameCenter_1.default.instance;
        this.dropItemInfo = this.getComponent(DropItemInfo_1.default);
        this.GC.registComponent(GameConstant_1.default.GAMECOMPONENT.DROP, this, (handler) => {
            this.callback = handler;
        });
        // const fishType = 'F011'
        // this['bingoBg'].skin =`${GameSettings.fishBingoPrefix}bingo${fishType}.png`
        // this['bingoValue'].value = 999
    }
    onUserClickItem(item, count) {
        if (this.callback) {
            this.callback.runWith([GameConstant_1.default.USERACTIONTYPE.COLLECTIONDROPITEM, { id: item, count: count }]);
        }
    }
    getFlyItem(type) {
        let name = '';
        let prefab = null;
        switch (type) {
            case GameConstant_1.default.ITEMTYPE.COIN:
                name = this.dropItemInfo.coinPoolName;
                prefab = this.dropItemInfo.coinPrefab;
                break;
            case GameConstant_1.default.ITEMTYPE.ROBOTCOIN:
                name = this.dropItemInfo.coinPoolName;
                prefab = this.dropItemInfo.coinPrefab;
                break;
            default:
                name = this.dropItemInfo.itemPoolName;
                prefab = this.dropItemInfo.itemPrefab;
                break;
        }
        if (name && prefab) {
            const sp = Laya.Pool.getItemByCreateFun(name, prefab.create, prefab);
            sp.pos(-1000, -1000);
            return sp.getComponent(FlyControl_1.default);
        }
        else {
            return null;
        }
    }
    flyItems(dropData, start) {
        for (let i = 0; i < dropData.length; i++) {
            const data = Object.assign({ start: start }, dropData[i]);
            Laya.timer.once(GameSettings_1.default.durationList.dropFlyJumpAnimation * i, this, this.flyItem, [data], false);
        }
    }
    flyItem(data) {
        data.end = this.GC.getItemDropTarget(data.id);
        data.itemType = "DROP_" + data.id;
        if (data.id == GameConstant_1.default.ITEMTYPE.RAGE) {
            data.isWaitOnclick = true;
        }
        if (data.id == GameConstant_1.default.ITEMTYPE.REDPACK || data.id == GameConstant_1.default.ITEMTYPE.COIN || data.id == GameConstant_1.default.ITEMTYPE.ROBOTCOIN) {
            let number = parseInt(data.desc);
            let num = number > 100 ? 100 : number;
            data.desc = num;
            let LastData = null;
            for (let i = 0; i < num; i++) {
                let fc = this.getFlyItem(data.id);
                this.addChild(fc.owner);
                if (i == (num - 1) && data.id == GameConstant_1.default.ITEMTYPE.REDPACK) {
                    let lastData = Object.assign({ callback: () => {
                            if (data.id == GameConstant_1.default.ITEMTYPE.REDPACK) {
                                this.GC.userGetItem(GameConstant_1.default.ITEMTYPE.REDPACK, num);
                                this.GC.userInfoZone.getRedPacketAnimation();
                            }
                        } }, data);
                    Laya.timer.once(GameSettings_1.default.durationList.dropFlyInterval * i, fc, fc.startFlyLast, [lastData], false);
                }
                else {
                    Laya.timer.once(GameSettings_1.default.durationList.dropFlyInterval * i, fc, fc.startFly, [data], false);
                }
            }
        }
        else {
            let fc = this.getFlyItem(data.id);
            this.addChild(fc.owner);
            data.callback = () => {
                // if(data.id ==  GameConstant.ITEMTYPE.REDPACK){
                //     this.GC.userGetItem(GameConstant.ITEMTYPE.REDPACK,1)
                //     this.GC.userInfoZone.getRedPacketAnimation()
                // }else 
                if (GameConstant_1.default.BATTERYITEMLIST[data.id]) {
                    this.GC.userInfoZone.setFreeBattery(GameConstant_1.default.BATTERYITEMLIST[data.id], 60);
                }
                else if (data.id == GameConstant_1.default.ITEMTYPE.RAGE) {
                    // fc.owner.on(Laya.Event.MOUSE_DOWN,fc,fc.moveEndPos)
                    this.GC.userGetItem(GameConstant_1.default.ITEMTYPE.RAGE, 1);
                }
            };
            fc.startFly(data);
        }
    }
    onFishDead(fishType, coin, startPos) {
        let settings = {
            fishType: fishType,
            timeOut: 2,
            value: this.GC.stringifyCoinValue(coin)
        };
        if (GameSettings_1.default.fishHasBingoList.indexOf(fishType) >= 0) {
            const bingo = Laya.Pool.getItemByCreateFun(this.dropItemInfo.fishBingoName, this.dropItemInfo.fishBingoPrefab.create, this.dropItemInfo.fishBingoPrefab);
            this.addChild(bingo.pos(startPos.x, startPos.y));
            //[AUDIO]=======[AUDIO]
            AudioManager_1.default.instance.playSound(GameConstant_1.default.MUSICTYPE.BIGFISHDEAD);
            bingo.setup(settings);
            //[AUDIO]=======[AUDIO]
            AudioManager_1.default.instance.playSound(GameConstant_1.default.MUSICTYPE.BIGFISHCOIN);
            //[AUDIO]=======[AUDIO]
            AudioManager_1.default.instance.playVibr(200);
        }
        else {
            const displayCoin = Laya.Pool.getItemByCreateFun(this.dropItemInfo.dropDisplayCoinName, this.dropItemInfo.dropDisplayCoinPrefab.create, this.dropItemInfo.dropDisplayCoinPrefab);
            this.addChild(displayCoin.pos(startPos.x, startPos.y));
            //[AUDIO]=======[AUDIO]
            AudioManager_1.default.instance.playSound(GameConstant_1.default.MUSICTYPE.COIN);
            displayCoin.setup(settings);
        }
    }
}
exports.default = DropControl;
},{"../Control/AudioManager":1,"../Control/GameCenter":3,"../GameConstant":10,"../GameSettings":11,"./DropItemInfo":23,"./FlyControl":33}],23:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-06-20 15:26:02
 * @Last Modified by: ZZL
 * @Last Modified time: 2019-06-20 15:27:27
 */
Object.defineProperty(exports, "__esModule", { value: true });
class DropItemInfo extends Laya.Script {
}
exports.default = DropItemInfo;
},{}],24:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-06-13 16:47:04
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-06-14 10:29:27
 */
Object.defineProperty(exports, "__esModule", { value: true });
//////////*************暂时不做PK */
const GameCenter_1 = require("../Control/GameCenter");
const GameConstant_1 = require("../GameConstant");
class EnemyInfoZone extends Laya.View {
    constructor() {
        super();
        this.isShowing = false;
        this.labelSet = {
            level: null,
            name: null,
            gunValue: null,
            hp: null,
            coin: null,
            avatar: null
        };
        this.GC = GameCenter_1.default.instance;
    }
    onEnable() {
        this.GC.registComponent(GameConstant_1.default.GAMECOMPONENT.ENEMYINFO, this, (getInfo, getImage) => {
            this.getInfo = getInfo;
            this.getImage = getImage;
        });
        this.labelSet.name = this['enemyName'];
        this.labelSet.level = this['enemyLevel'];
        this.labelSet.gunValue = this['enemyGunValue'];
        this.labelSet.hp = this['enemyHP'];
        this.labelSet.coin = this['enemyCoin'];
        this.labelSet.avatar = this['avatar'];
        // this.setZone(false)
    }
    _update() {
        if ((this.GC.status.gameState == GameConstant_1.default.GAMESTATETYPE.PK) != this.isShowing) {
            this.setZone(this.GC.status.gameState == GameConstant_1.default.GAMESTATETYPE.PK);
        }
        if (this.isShowing && this.getInfo) {
            const info = this.getInfo();
            this.labelSet.coin.value = `${info.coin}`;
            this.labelSet.gunValue.value = `${info.curBatteryLv}`;
            this.labelSet.hp.value = `${info.hp}`;
            this.labelSet.level.text = `${info.lv}`;
            this.labelSet.name.text = `${info.nickName}`;
        }
    }
    setZone(show) {
        this.isShowing = show;
        this.visible = show;
        if (this.isShowing) {
            const imgUrl = this.getInfo().imgUrl;
            if (this.getImage) {
                this.getImage(imgUrl, (url) => {
                    this.labelSet.avatar.loadImage(url);
                });
            }
        }
    }
}
exports.default = EnemyInfoZone;
// TarsisHttp.StartHttpCall({
// 	url:`https://wx.qlogo.cn/mmopen/vi_32/Q0j4TwGTfTIyeYdSW0w1TZmIvAibmUpGkIfnBchdSHlmoicdePcsTZNcILxggYnA6Lgib8HIeVTo2fiazibaugFyeVQ/132`,
// 	onSuccess:(data)=>{
// 		console.log(`On Success : ${data}`)
// 		var byte = new Laya.Byte(data);//Byte数组接收arraybuffer
// 		byte.writeArrayBuffer(data,4);//从第四个字节开始读取数据
// 		var blob = new Laya.Browser.window.Blob([data], { type: "image/png" });
// 		var url = Laya.Browser.window.URL.createObjectURL(blob);//创建一个url对象；
// 		////我们先用第一种方式显示图片到舞台；
// 		var sp = new Laya.Sprite();
// 		sp.loadImage(url);
// 		Laya.stage.addChild(sp);//添加到舞台
// 	},
// 	responseType:'arraybuffer'
// })
},{"../Control/GameCenter":3,"../GameConstant":10}],25:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-07-08 12:30:35
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-07-08 15:52:34
 */
Object.defineProperty(exports, "__esModule", { value: true });
const GameConstant_1 = require("../GameConstant");
const GameCenter_1 = require("../Control/GameCenter");
class FishAnimationControl extends Laya.Script {
    constructor() {
        super(...arguments);
        this.animation = null;
    }
    onEnable() {
        this.GC = GameCenter_1.default.instance;
        this.animation = this.owner;
        this.animation.interval = 100;
        this.swimKey = `${this.fishType}-${GameConstant_1.default.FISHANIMATIONKEY.SWIM}`;
        this.hitKey = `${this.fishType}-${GameConstant_1.default.FISHANIMATIONKEY.HIT}`;
        this.deadKey = `${this.fishType}-${GameConstant_1.default.FISHANIMATIONKEY.DEAD}`;
        if (!Laya.Animation.framesMap[this.swimKey]) {
            this.GC.fishManager.checkFishResource(this.fishType, () => {
                this.setSwim();
            });
        }
    }
    setSwim() {
        this.animation.play(0, true, this.swimKey);
    }
    setHit() {
        this.animation.play(0, true, this.hitKey);
    }
    setDead() {
        this.animation.play(0, true, this.deadKey);
    }
}
exports.default = FishAnimationControl;
},{"../Control/GameCenter":3,"../GameConstant":10}],26:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const GameSettings_1 = require("../GameSettings");
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-06-20 15:23:21
 * @Last Modified by: ZZL
 * @Last Modified time: 2019-06-21 14:34:13
 */
class FishBingoControl extends Laya.Image {
    onEnable() {
        this._children.forEach((element) => {
            switch (element.name) {
                case 'bingoValue':
                    this.coinValue = element;
                    break;
            }
        });
    }
    setup(settings) {
        const fishType = GameSettings_1.default.fishIsGatherList.indexOf(settings.fishType) >= 0 ? 'F023' : settings.fishType;
        this.skin = `${GameSettings_1.default.fishBingoPrefix}bingo${fishType}.png`;
        this.coinValue.value = settings.value;
        this.scaleBig();
        if (this.x - this.width * 0.7 < 0) {
            this.x = this.width * 0.7;
        }
        if (this.x + this.width * 0.7 > Laya.stage.width) {
            this.x = Laya.stage.width - this.width * 0.7;
        }
        if (this.y - this.height * 0.7 < 0) {
            this.y = this.height * 0.7;
        }
        if (this.y + this.height * 0.7 > Laya.stage.height) {
            this.y = Laya.stage.height - this.height * 0.7;
        }
        Laya.timer.once((settings.timeOut * 1000), this, this.removeSelf, null, false);
    }
    onDisable() {
        this.scale(0, 0);
        Laya.Pool.recover("FishBingo", this);
    }
    scaleSmall() {
        Laya.Tween.to(this, { scaleX: 2, scaleY: 2 }, 200);
    }
    scaleBig() {
        Laya.Tween.to(this, { scaleX: 2.5, scaleY: 2.5 }, 200, null, Laya.Handler.create(this, this.scaleSmall));
    }
}
exports.default = FishBingoControl;
},{"../GameSettings":11}],27:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie.Robin
 * @Date: 2019-05-28 15:56:19
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-07-17 17:10:56
 */
Object.defineProperty(exports, "__esModule", { value: true });
var Pool = Laya.Pool;
const GameConstant_1 = require("../GameConstant");
const GameCenter_1 = require("../Control/GameCenter");
const GameSettings_1 = require("../GameSettings");
const PathMove_1 = require("./PathMove");
const MissionFishControl_1 = require("./MissionFishControl");
const FishGatherControl_1 = require("./FishGatherControl");
class FishControl extends Laya.Script {
    constructor() {
        super(...arguments);
        /** @prop {name:speed,tips:"鱼速度",type:Int}*/
        this.speed = 20;
        /** @prop {name:fishScale,tips:"鱼缩放",type:Int}*/
        this.fishScale = 2;
        this.isDead = true;
        this.animation = null;
        this.isInitPathMove = false;
        this.isInitMissionFishControl = false;
        this.isOnHitAnimation = false;
        this.isOnDeadAnimation = false;
        this.isMissionFish = false;
    }
    onEnable() {
        this.GC = GameCenter_1.default.instance;
        this.owner._children.forEach(element => {
            if (element.name == 'fishAni') {
                this.animation = element;
            }
            else if (element.name == 'hitArea') {
                let sp = this.owner;
                sp.hitArea = new Laya.Rectangle(element.x, element.y, element.width, element.height);
            }
        });
        this.animation.interval = 1000 / 10;
        this.swimKey = `${this.animationFishType}-${GameConstant_1.default.FISHANIMATIONKEY.SWIM}`;
        this.hitKey = `${this.animationFishType}-${GameConstant_1.default.FISHANIMATIONKEY.HIT}`;
        this.deadKey = `${this.animationFishType}-${GameConstant_1.default.FISHANIMATIONKEY.DEAD}`;
        if (this.isGatherFish) {
            this.gatherControl = this.owner.getComponent(FishGatherControl_1.default);
        }
    }
    onUpdate() {
    }
    onDisable() {
        Pool.recover(this.fishType, this.owner);
    }
    setup(id, path = null, delay = 0, missionFish = false, isTargetFish = false) {
        this.fishId = id;
        this.isMissionFish = missionFish;
        if (missionFish) {
            if (!this.isInitMissionFishControl) {
                this.missionFish = this.owner.addComponent(MissionFishControl_1.default);
                this.isInitMissionFishControl = true;
                this.missionFish.setup(this.fishType, this.fishScale);
            }
            this.missionFish.init(id, path, isTargetFish, delay);
        }
        else {
            if (!this.isInitPathMove) {
                this.pm = this.owner.addComponent(PathMove_1.default);
                this.pm.setup(this.fishType, this.speed, this.fishScale);
                this.isInitPathMove = true;
            }
            if (path) {
                this.pm.init(id, path, delay, this.isGatherFish);
            }
        }
        this.isDead = false;
        this.setSwim();
    }
    speedUp(isMission = false) {
        if (this.isMissionFish != isMission) {
            return;
        }
        if (isMission) {
            this.missionFish.speedUp();
        }
        else {
            this.pm.speedUp();
        }
    }
    setSwim() {
        this.animation.play(0, true, this.swimKey);
        if (this.gatherControl) {
            this.gatherControl.setSwim();
        }
    }
    setHit() {
        this.animation.play(0, true, this.hitKey);
        if (this.gatherControl) {
            this.gatherControl.setHit();
        }
    }
    setDead() {
        if (this.isHasDeadAni) {
            this.animation.play(0, true, this.deadKey);
            if (this.gatherControl) {
                this.gatherControl.setDead();
            }
        }
    }
    playHit() {
        if (!this.isOnHitAnimation) {
            this.setHit();
            this.isOnHitAnimation = true;
            Laya.timer.once(GameSettings_1.default.durationList.fishHitAnimation, this, () => {
                this.setSwim();
                this.isOnHitAnimation = false;
            });
        }
    }
    playDead() {
        this.isOnDeadAnimation = true;
        this.isDead = true;
        if (!GameSettings_1.default.fishHasBingoList.indexOf(this.fishType)) {
            this.setDead();
        }
        if (this.isMissionFish) {
            this.missionFish.onDead();
        }
        else {
            this.pm.onDead(GameSettings_1.default.durationList.fishDeadAnimation);
        }
        Laya.timer.once(GameSettings_1.default.durationList.fishDeadAnimation, this, () => {
            this.setSwim();
        });
    }
    reset() {
        this.isOnHitAnimation = false;
        this.isOnDeadAnimation = false;
    }
}
exports.default = FishControl;
},{"../Control/GameCenter":3,"../GameConstant":10,"../GameSettings":11,"./FishGatherControl":29,"./MissionFishControl":41,"./PathMove":43}],28:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const GameSettings_1 = require("../GameSettings");
const FishControl_1 = require("./FishControl");
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-06-03 14:28:25
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-06-06 17:20:01
 */
class FishDropItemControl extends Laya.Script {
    constructor() {
        super(...arguments);
        this.isInit = false;
        this.selfScaleY = 1;
        this.selfPos = { x: 0, y: 0 };
    }
    onEnable() {
        this.self = this.owner;
        this.self._children.forEach((element) => {
            switch (element.name) {
                case 'icon':
                    this.icon = element;
                    break;
            }
        });
        this.fish = this.self.parent;
        const fc = this.fish.getComponent(FishControl_1.default);
        this.selfScaleY = 1 / fc.fishScale;
        this.parentScaleY = this.fish.scaleY;
        this.setPos();
    }
    onUpdate() {
        if (this.isInit) {
            if (this.parentScaleY != this.fish.scaleY) {
                this.parentScaleY = this.fish.scaleY;
                this.setPos();
            }
        }
    }
    setInfo(item, pos = null) {
        this.icon.skin = GameSettings_1.default.itemIconList[item] || GameSettings_1.default.itemIconList['REDPACKET'];
        if (pos) {
            this.selfPos = pos || { x: 0, y: 0 };
            this.setPos();
        }
        this.isInit = true;
    }
    setPos() {
        this.self.pos(this.fish.pivotX + this.selfPos.x, this.parentScaleY > 0 ? this.fish.pivotY + this.selfPos.y : this.fish.pivotY - this.selfPos.y);
        this.self.scale(this.selfScaleY, this.parentScaleY > 0 ? 1 / this.parentScaleY : -1 / this.parentScaleY);
    }
    onDisable() {
        this.isInit = false;
        Laya.Pool.recover('FishDropItem', this.self);
    }
}
exports.default = FishDropItemControl;
},{"../GameSettings":11,"./FishControl":27}],29:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-07-05 14:16:00
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-07-08 12:38:08
 */
Object.defineProperty(exports, "__esModule", { value: true });
const GameCenter_1 = require("../Control/GameCenter");
const FishControl_1 = require("./FishControl");
const FishAnimationControl_1 = require("./FishAnimationControl");
class FishGatherControl extends Laya.Script {
    constructor() {
        super(...arguments);
        this.posList = [];
        this.fishList = [];
        this.nowSelfFishIndex = 0;
        this.selfFishToatal = 0;
        this.fishIdList = [];
        this.fishScale = 2;
        this.animationList = [];
    }
    onEnable() {
        this.GC = GameCenter_1.default.instance;
        this.fishControl = this.owner.getComponent(FishControl_1.default);
        if (this.fishControl) {
            this.fishScale = this.fishControl.fishScale;
        }
        this.animationList = [];
        this.owner._children.forEach(element => {
            if (element.name == 'posFishAni') {
                this.animationList.push(element.getComponent(FishAnimationControl_1.default));
            }
        });
    }
    setSwim() {
        this.animationList.forEach(ani => {
            ani.setSwim();
        });
    }
    setHit() {
        this.animationList.forEach(ani => {
            ani.setHit();
        });
    }
    setDead() {
        this.animationList.forEach(ani => {
            ani.setDead();
        });
    }
}
exports.default = FishGatherControl;
},{"../Control/GameCenter":3,"./FishAnimationControl":25,"./FishControl":27}],30:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-06-01 10:13:09
 * @Last Modified by: ZZL
 * @Last Modified time: 2019-07-22 18:04:34
 */
Object.defineProperty(exports, "__esModule", { value: true });
var Pool = Laya.Pool;
var Sprite = Laya.Sprite;
const GameCenter_1 = require("../Control/GameCenter");
const GameConstant_1 = require("../GameConstant");
const FishControl_1 = require("./FishControl");
const GameSettings_1 = require("../GameSettings");
const Tarsis_1 = require("../utils/Tarsis");
const FishSettings_1 = require("./FishSettings");
const FishDropItemControl_1 = require("./FishDropItemControl");
class FishManager extends Laya.View {
    constructor() {
        super();
        this.missionSetting = [];
        this.pathSetting = [];
        this.fishSetting = [];
        this.smllPathIds = [];
        this.middlePathIds = [];
        this.largePathIds = [];
        this.gatherPathIds = [];
        this.isOnMission = false;
        this.missionInfo = null;
        this.fishAddSettingAll = [];
        this.fishAddSetting = [];
        this.fishAddSettingTotalRathio = 170;
        this.fishLoadedList = [];
        this.fishLoadingDic = [];
        this.isLoadingFish = false;
        this.fishHolder = this.addChild(new Sprite());
        this.bulletHolder = this.addChild(new Sprite());
    }
    onEnable() {
        this.GC = GameCenter_1.default.instance;
        this.GC.fishHolder = this.fishHolder;
        this.GC.bulletHolder = this.bulletHolder;
        this.fishSettings = this.getComponent(FishSettings_1.default);
        Laya.loader.load("settings/missionSetting.json", Laya.Handler.create(this, (path) => {
            this.missionSetting = path;
        }));
        Laya.loader.load("settings/pathFull4.json", Laya.Handler.create(this, (path) => {
            const scaleY = Math.max(1, Laya.stage.height / 1920);
            path.groupList.forEach(element => {
                element.pathLength = element.pathList.length;
                if (element.pathLength > 0) {
                    element.pathList.forEach(child => {
                        child.pointsList.forEach(q => {
                            q.y *= scaleY;
                        });
                        child.isInterpolated = false;
                    });
                    this.pathSetting[element.id] = element;
                    if (element.id.startsWith('A')) {
                        this.smllPathIds.push(element.id);
                    }
                    else if (element.id.startsWith('B')) {
                        this.middlePathIds.push(element.id);
                    }
                    else if (element.id.startsWith('C')) {
                        this.largePathIds.push(element.id);
                    }
                    else {
                        this.gatherPathIds.push(element.id);
                    }
                }
            });
            Laya.loader.load("settings/fishSettings.json", Laya.Handler.create(this, (f) => {
                this.fishAddSettingAll = f.fishPathSetting;
                GameSettings_1.default.fishRandomDuration = f.fishRandomDuration;
                this.checkFishPathSetting();
                f.fishList.forEach(element => {
                    this.fishSetting[element.id] = element;
                });
                this.GC.registComponent(GameConstant_1.default.GAMECOMPONENT.FISHMANAGER, this);
                this.randomAddFish();
                Laya.timer.loop(GameSettings_1.default.fishRandomDuration, this, () => {
                    this.checkFishPathSetting();
                    this.randomAddFish();
                });
            }));
        }));
    }
    GetMissionInfo(missionType = 1) {
        console.log('GetMissionInfo');
        let mission = this.missionSetting[`type${missionType}`];
        this.missionInfo = mission;
        let hitCount = 1;
        if (this.missionInfo.hitFishCount) {
            hitCount = this.missionInfo.hitFishCount;
        }
        this.GC.setMissionInfoCount(mission.bulletCount, hitCount);
    }
    addMission() {
        this.missionInfo.Fish.forEach(element => {
            const type = element.fishName;
            this.checkFishResource(type, () => {
                this.getFish(type);
                let waitTime = 0;
                if (element.waitTime) {
                    waitTime = element.waitTime;
                }
                this.addFish(type, element.pathPos, waitTime, true, element.isTarget);
            });
        });
        return this.missionInfo.bulletCount;
    }
    checkFishPathSetting() {
        const level = parseInt(this.GC.nowUser.lv);
        if (level) {
            this.fishAddSetting = this.fishAddSettingAll[0];
            this.fishAddSettingAll.forEach(setting => {
                if (level >= setting.level.min && level <= setting.level.max) {
                    this.fishAddSetting = setting.setting;
                }
            });
            this.fishAddSettingTotalRathio = 0;
            this.fishAddSetting.forEach((element) => {
                this.fishAddSettingTotalRathio += element.rathio;
            });
        }
    }
    interpolationPath(path) {
        path.smoothPoints = Tarsis_1.default.CubicCurveAlgorithmInterpolation(path.pointsList, 20);
        path.pathLen = 0;
        path.pointLenInPath = [];
        for (let i = 0; i < path.smoothPoints.length; i++) {
            const element = path.smoothPoints[i];
            let prev = i > 0 ? path.smoothPoints[i - 1] : element;
            const temp = Math.sqrt((element.x - prev.x) * (element.x - prev.x) + (element.y - prev.y) * (element.y - prev.y));
            path.pathLen += temp;
            path.pointLenInPath.push(path.pathLen);
        }
        path.isInterpolated = true;
        return path;
    }
    getRandomFish() {
        const r = Math.floor(Math.random() * this.fishAddSettingTotalRathio);
        let rathio = 0;
        let result = { type: 'F001', count: 1, size: 0 };
        for (let i = 0; i < this.fishAddSetting.length; i++) {
            const element = this.fishAddSetting[i];
            rathio += element.rathio;
            if (r <= rathio) {
                const type = element.fishList[Math.floor(Math.random() * element.fishList.length)];
                const count = Math.floor(Math.random() * (element.max - element.min + 1)) + element.min;
                result = { type: type, count: count, size: element.fishSize };
                break;
            }
        }
        return result;
    }
    randomAddFish() {
        if (this.isOnMission != this.GC.status.isOnMission) {
            this.GC.speedUpFish(this.isOnMission);
            this.isOnMission = this.GC.status.isOnMission;
            if (this.isOnMission) {
                this.bulletHolder.removeChildren();
            }
        }
        if (this.GC.status.isOnNewbee) {
            return;
        }
        if (this.isOnMission || this.GC.status.isOnOffline) {
            return;
        }
        const random = this.getRandomFish();
        let pathId;
        if (random.size == 0) {
            pathId = this.smllPathIds[Math.floor(Math.random() * this.smllPathIds.length)];
        }
        else if (random.size == 1) {
            pathId = this.middlePathIds[Math.floor(Math.random() * this.middlePathIds.length)];
        }
        else if (random.size == 2) {
            pathId = this.largePathIds[Math.floor(Math.random() * this.largePathIds.length)];
        }
        else {
            pathId = this.gatherPathIds[Math.floor(Math.random() * this.gatherPathIds.length)];
        }
        this.checkFishResource(random.type, () => {
            this.doRandomAddFish(random, pathId);
        });
    }
    checkFishResource(type, callback) {
        const setting = this.fishSetting[type];
        if (setting.isGatherFish) {
            if (this.fishLoadedList.indexOf(type) >= 0) {
                let arr = [];
                setting.childFish.forEach(element => {
                    if (this.fishLoadedList.indexOf(element) < 0) {
                        arr.push(element);
                    }
                });
                if (arr.length > 0) {
                    this.checkFishResource(arr[0], () => {
                        this.checkFishResource(type, callback);
                    });
                }
                else {
                    callback();
                }
            }
            else {
                // this.loadFishAniResource(type,()=>{
                //     this.checkFishResource(type,callback)
                // })
                this.addLoadingFish(type, () => {
                    this.checkFishResource(type, callback);
                });
            }
        }
        else if (this.fishLoadedList.indexOf(type) >= 0) {
            callback();
        }
        else {
            // this.loadFishAniResource(type,callback)
            this.addLoadingFish(type, callback);
        }
    }
    addLoadingFish(type, callback) {
        this.fishLoadingDic.push({
            type: type,
            callback: callback
        });
        this.checkFishLoadingList();
    }
    checkFishLoadingList() {
        // console.log(`checkFishLoadingList ${this.fishLoadingDic.length}`)
        if (this.fishLoadingDic.length > 0) {
            const f = this.fishLoadingDic.shift();
            this.loadFishAniResource(f.type, f.callback);
        }
    }
    loadFishAniResource(type, callback) {
        // console.log(`Load Fish ${type}`)
        const setting = this.fishSetting[type];
        const aniMaker = setting.isImageAni ? this.aniImagsUrls : this.aniUrls;
        const aniFishType = setting.animationId ? setting.animationId : type;
        let arr = [];
        if (setting.isImageAni) {
            arr = arr.concat(aniMaker(aniFishType, GameConstant_1.default.FISHANIMATIONKEY.SWIM, setting.imgCount[0]));
            arr = arr.concat(aniMaker(aniFishType, GameConstant_1.default.FISHANIMATIONKEY.HIT, setting.imgCount[1]));
            if (setting.isHasDeadAni) {
                arr = arr.concat(aniMaker(aniFishType, GameConstant_1.default.FISHANIMATIONKEY.DEAD, setting.imgCount[2]));
            }
        }
        const aniResource = setting.isImageAni ? arr : `${GameSettings_1.default.fishSettingPrefix}${aniFishType}.atlas`;
        Laya.loader.load(aniResource, Laya.Handler.create(this, () => {
            Laya.Animation.createFrames(aniMaker(aniFishType, GameConstant_1.default.FISHANIMATIONKEY.SWIM, setting.imgCount[0]), `${aniFishType}-${GameConstant_1.default.FISHANIMATIONKEY.SWIM}`);
            Laya.Animation.createFrames(aniMaker(aniFishType, GameConstant_1.default.FISHANIMATIONKEY.HIT, setting.imgCount[1]), `${aniFishType}-${GameConstant_1.default.FISHANIMATIONKEY.HIT}`);
            if (setting.isHasDeadAni) {
                Laya.Animation.createFrames(aniMaker(aniFishType, GameConstant_1.default.FISHANIMATIONKEY.DEAD, setting.imgCount[2]), `${aniFishType}-${GameConstant_1.default.FISHANIMATIONKEY.DEAD}`);
            }
            this.fishLoadedList.push(type);
            callback();
            this.checkFishLoadingList();
        }), Laya.Handler.create(this, (progress) => {
            if (GameSettings_1.default.debug.showFishLoading) {
                console.log(`Load ${type} resource progress  : ${progress}`);
            }
        }));
    }
    aniUrls(fishType, aniName, length) {
        var urls = [];
        for (var i = 0; i < length; i++) {
            urls.push(`${fishType}/${fishType}-${aniName}_${i < 9 ? '0' : ''}${i + 1}.png`);
        }
        return urls;
    }
    aniImagsUrls(fishType, aniName, length) {
        var urls = [];
        for (var i = 0; i < length; i++) {
            urls.push(`${GameSettings_1.default.fishSettingPrefix}${fishType}/${fishType}-${aniName}_${i < 9 ? '0' : ''}${i + 1}.png`);
        }
        return urls;
    }
    doRandomAddFish(random, pathId) {
        let delay = 0;
        let index = 0;
        let path = this.pathSetting[pathId];
        random.count = Math.min(random.count, path.maxFish);
        let childPath = null;
        if (path.pathList.length > 0) {
            for (let i = 0; i < random.count; i++) {
                if (index < path.pathLength) {
                    childPath = path.pathList[index];
                    index += 1;
                    delay = path.assignList[i] ? path.assignList[i] : 0;
                }
                else {
                    index = 0;
                    delay = path.assignList[i] ? path.assignList[i] : 0;
                    childPath = path.pathList[index];
                }
                if (childPath.pointsList.length > 0) {
                    if (!childPath.isInterpolated) {
                        this.interpolationPath(childPath);
                    }
                    this.addFish(random.type, childPath, delay);
                }
            }
        }
    }
    createNewbeeFish() {
        this.checkFishResource(GameConstant_1.default.NEWBEEINFO.fishType, () => {
            const fish = this.getFish(GameConstant_1.default.NEWBEEINFO.fishType);
            this.GC.addFish(GameConstant_1.default.NEWBEEINFO.fishID, GameConstant_1.default.NEWBEEINFO.fishType, fish, false);
            this.fishHolder.addChild(fish.pos(Laya.stage.width / 2, Laya.stage.height / 2));
            const fc = fish.getComponent(FishControl_1.default);
            fc.setup(GameConstant_1.default.NEWBEEINFO.fishID);
        });
    }
    addFish(fishType, path, delay = 0, isMission = false, isTargetFish = false) {
        if (path) {
            const fish = this.getFish(fishType);
            let fishId = this.GC.getFishId();
            this.fishHolder.addChild(fish.pos(-1000, -1000));
            const fc = fish.getComponent(FishControl_1.default);
            fc.setup(fishId, path, delay, isMission, isTargetFish);
            let drop = null;
            if (GameSettings_1.default.DropItemFishList[fishType]) {
                const prefab = this.fishSettings.dropPrefab;
                drop = Laya.Pool.getItemByCreateFun('FishDropItem', prefab.create, prefab);
                fish.addChild(drop);
                const fdc = drop.getComponent(FishDropItemControl_1.default);
                const dropItem = GameSettings_1.default.DropItemFishList[fishType];
                fdc.setInfo(dropItem, this.fishSetting[fishType].dropItemPos);
            }
            this.GC.addFish(fishId, fishType, fish, isTargetFish, drop);
            // const setting = this.fishSetting[fishType]
            // if(setting.isGatherFish){
            //     const fgc : FishGatherControl = fish.getComponent(FishGatherControl)
            //     fgc.setup(setting.childFish,Laya.Handler.create(this,this.getGatherFish))
            // }
        }
    }
    getFish(fishType) {
        const prefab = this.fishSettings[`${fishType}Prefab`];
        return Pool.getItemByCreateFun(fishType, prefab.create, prefab);
    }
    getGatherFish(fishType, callback) {
        this.checkFishResource(fishType, () => {
            callback(this.getFish(fishType));
        });
    }
}
exports.default = FishManager;
},{"../Control/GameCenter":3,"../GameConstant":10,"../GameSettings":11,"../utils/Tarsis":66,"./FishControl":27,"./FishDropItemControl":28,"./FishSettings":32}],31:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-28 15:59:13
 * @Last Modified by:   Odie Robin
 * @Last Modified time: 2019-05-28 15:59:13
 */
Object.defineProperty(exports, "__esModule", { value: true });
var Pool = Laya.Pool;
var Tween = Laya.Tween;
const GameCenter_1 = require("../Control/GameCenter");
class FishNetControl extends Laya.Script {
    constructor() {
        super();
    }
    onEnable() {
        this.GC = GameCenter_1.default.instance;
    }
    onUpdate() { }
    onDisable() {
        Pool.recover(this.fishNetType, this.owner);
    }
    playEffect(bulletId, gunValue = 0, scale = 1) {
        this.gunValue = gunValue;
        const sp = this.owner;
        sp.scale(scale, scale);
        if (this.isAnimation) {
            const ani = this.owner;
            ani.play(0, false);
        }
        else {
            Tween.from(sp, { scaleX: 0.1, scaleY: 0.1 }, this.animationDuration, Laya.Ease.linearNone);
        }
        Laya.timer.once(this.animationDuration, this, () => {
            if (this.isCheckHit) {
                const fishList = this.GC.checkHit({
                    x: sp.x,
                    y: sp.y,
                    multiHit: this.isMuiltHit,
                    checkRadius: sp.width / 2 * scale * 0.9,
                    report: true,
                    bulletId: bulletId,
                    isBullet: false
                });
                fishList.forEach((element) => {
                    element.playHit();
                });
            }
            this.playDead();
        });
    }
    playDead() {
        this.owner.removeSelf();
    }
}
exports.default = FishNetControl;
},{"../Control/GameCenter":3}],32:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-07-01 13:49:43
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-07-08 16:29:39
 */
Object.defineProperty(exports, "__esModule", { value: true });
class FishSettings extends Laya.Script {
}
exports.default = FishSettings;
},{}],33:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const GameSettings_1 = require("../GameSettings");
const GameConstant_1 = require("../GameConstant");
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-06-20 15:23:21
 * @Last Modified by: ZZL
 * @Last Modified time: 2019-11-06 14:30:30
 */
class FlyControl extends Laya.Script {
    constructor() {
        super(...arguments);
        this.settings = null;
        this.isDoToEnd = false;
        this.settingsTemplate = {
            start: null,
            end: null,
            itemType: 'DIAMOND',
            scale: 1,
            isWaitOnclick: false
        };
        this.self = null;
    }
    onEnable() {
        this.self = this.owner;
        this.isDoToEnd = false;
    }
    startFlyLast(data) {
        this.startFly(data);
    }
    startFly(settings) {
        this.settings = Object.assign(Object.assign({}, this.settingsTemplate), settings);
        if (this.settings.id == GameConstant_1.default.ITEMTYPE.COIN || this.settings.id == GameConstant_1.default.ITEMTYPE.ROBOTCOIN) {
            this.settings.scale = 1.5;
            this.self.scale(this.settings.scale, this.settings.scale);
        }
        if (!this.isAnimation) {
            this.self.texture = GameSettings_1.default.itemIconList[this.settings.itemType];
            this.self.scale(this.settings.scale, this.settings.scale);
        }
        let distanceX = Math.floor(Math.random() * 100);
        let distanceY = Math.floor(Math.random() * 80);
        let x = this.settings.start.x > Laya.stage.width * 0.8 ? Laya.stage.width * 0.8 : this.settings.start.x;
        let y = this.settings.start.y > Laya.stage.height * 0.8 ? Laya.stage.height * 0.8 : this.settings.start.y;
        x = this.settings.start.x < Laya.stage.width * 0.2 ? Laya.stage.width * 0.2 : this.settings.start.x;
        this.self.x = (x - 50 + distanceX);
        this.self.y = (y - 40 + distanceY);
        Laya.Tween.to(this.self, {
            x: this.self.x,
            y: (this.self.y - 200)
        }, GameSettings_1.default.durationList.dropFlyJumpAnimation, null, Laya.Handler.create(this, this.jumpBack), 0, false);
    }
    jumpBack() {
        let waitTime = GameSettings_1.default.durationList.dropFlyWaitMoveToEndAnimation;
        if (this.settings.isWaitOnclick) {
            waitTime += 5000;
            // this.settings.callback()
            // this.settings.callback = null
            this.owner.on(Laya.Event.CLICK, this, () => {
                this.moveEndPos();
            });
        }
        Laya.Tween.to(this.self, { x: this.self.x,
            y: (this.self.y + 200)
        }, GameSettings_1.default.durationList.dropFlyJumpBackAnimation, null, Laya.Handler.create(this, this.moveEndPos), waitTime, false);
    }
    moveEndPos() {
        if (!this.isDoToEnd) {
            this.isDoToEnd = true;
            Laya.Tween.to(this.self, { x: this.settings.end.x, y: this.settings.end.y }, GameSettings_1.default.durationList.dropFlyToEndPosAnimation, null, Laya.Handler.create(this, this.end), 0, false);
        }
    }
    end() {
        if (this.settings.callback) {
            this.settings.callback();
        }
        this.self.removeSelf();
        //Laya.timer.once(GameSettings.durationList.dropFlyToEndPosAnimation,this,this.doRemoveSelf,null,false);
    }
    doRemoveSelf() {
        this.self.removeSelf();
    }
    onDisable() {
        Laya.Pool.recover(this.flyItemType, this.owner);
    }
}
exports.default = FlyControl;
},{"../GameConstant":10,"../GameSettings":11}],34:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-28 15:59:20
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-07-08 16:37:42
 */
Object.defineProperty(exports, "__esModule", { value: true });
const GameSettings_1 = require("../GameSettings");
const GameCenter_1 = require("../Control/GameCenter");
const AudioManager_1 = require("../Control/AudioManager");
const GameConstant_1 = require("../GameConstant");
class GameScene extends Laya.Scene {
    constructor() {
        super(...arguments);
        this.isStartLoadingMission = false;
        this.isStartLoadingShop = false;
    }
    onEnable() {
        this.GC = GameCenter_1.default.instance;
        this.GC.fireStatus.hold = true;
        Laya.Scene.load('view/Loading.scene', Laya.Handler.create(this, () => {
            Laya.View.open('view/MainBg.scene', false, null, Laya.Handler.create(this, (s) => { }));
            Laya.View.open('view/Loading.scene', false, null, Laya.Handler.create(this, (s) => {
                this.GC.status.setLoading(true, {
                    text: '正在载入场景'
                });
                Laya.loader.load(['gun/gun_01.png', 'uibase/Coin.png', 'userInfo/lv.png'], Laya.Handler.create(this, () => {
                    // Laya.Scene.load('view/UserInfo.scene',Laya.Handler.create(this,()=>{
                    this.GC.status.setLoading(false);
                    const max = GameSettings_1.default.sceneViewList.Game.length;
                    let count = 1;
                    GameSettings_1.default.sceneViewList.Game.forEach((element) => {
                        Laya.View.open(element, false, null, Laya.Handler.create(this, (s) => {
                            count += 1;
                            if (count >= max) {
                                this.GC.fireStatus.hold = false;
                                // if(!this.isStartLoadingShop){
                                //     this.isStartLoadingShop = true
                                //     GameSettings.sceneViewList.Shop.forEach((element)=>{
                                //         Laya.View.open(element,false, null,Laya.Handler.create(this,(s)=>{}))
                                //     })
                                // }
                                // if(!this.isStartLoadingMission){
                                //     this.isStartLoadingMission = true
                                //     if(GameSettings.isMissionOpen){
                                //         GameSettings.sceneViewList.Mission.forEach((element)=>{
                                //             Laya.View.open(element,false, null,Laya.Handler.create(this,(s)=>{}))
                                //         })
                                //     }
                                // }
                            }
                        }));
                    });
                    //[AUDIO]=======[AUDIO]
                    AudioManager_1.default.instance.playMusic(GameConstant_1.default.MUSICTYPE.BGM);
                }));
            }));
        }));
    }
}
exports.default = GameScene;
},{"../Control/AudioManager":1,"../Control/GameCenter":3,"../GameConstant":10,"../GameSettings":11}],35:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-06-04 17:45:55
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-06-10 14:37:06
 */
Object.defineProperty(exports, "__esModule", { value: true });
const GameCenter_1 = require("../Control/GameCenter");
const ExtBaseButton_1 = require("../extends/ExtBaseButton");
const VipPrizeItemControl_1 = require("../shop/VipPrizeItemControl");
const GameConstant_1 = require("../GameConstant");
class GetItemControl extends Laya.Script {
    constructor() {
        super(...arguments);
        this.isShowing = false;
        this.itemWidth = 200;
        this.defaultY = 750;
        this.secondY = 900;
        this.duration = 500;
        this.itemPos = [
            [0, 0, 0, 0],
            [-1, 1, 0, 0],
            [-1.5, 0, 1.5, 0],
            [-1.5, -0.5, 0.5, 1.5],
            [-2, -1, 0, 1, 2],
            // [-2.5,-1.5,-0.5,0.5,1.5,2.5],
            [-1.8, -0.6, 0.6, 1.8, -1.2, 1.2],
            [-2.25, -0.75, 0.75, 2.25, -1.5, 0, 1.5]
            // [-2,-1,0,1,2,-1.5,1.5]
        ];
        this.prizeItemList = [];
        this.timeLeft = -1;
        this.isOnTimer = false;
    }
    onEnable() {
        this.GC = GameCenter_1.default.instance;
        this.self = this.owner;
        this.vipPrizeText = this.self['vipPrize'];
        this.closeBtn = this.self['close'].getComponent(ExtBaseButton_1.default);
        this.closeBtn.setLabelText('确定');
        this.timerLabel = this.self['counter'];
        for (let i = 0; i < 7; i++) {
            let item = Laya.Pool.getItemByCreateFun('VipPrizeItem', this.vipPrizeItem.create, this.vipPrizeItem);
            let ic = item.getComponent(VipPrizeItemControl_1.default);
            this.prizeItemList.push(ic);
            this.self.addChild(item.pos(0, this.defaultY));
        }
        this.setAward(false);
    }
    onUpdate() {
        if (this.isShowing != this.GC.status.isOnGetItem) {
            this.setAward(this.GC.status.isOnGetItem);
        }
        if (this.isShowing && this.isOnTimer) {
            this.timeLeft -= Laya.timer.delta;
            if (this.timeLeft < 0) {
                this.closeBtn.triggerClick();
            }
            // this.timerLabel.visible = true
            // this.timerLabel.text = `${Math.floor(this.timeLeft / 1000)}`
            this.closeBtn.setLabelText(`确定(${Math.floor(this.timeLeft / 1000)})`);
        }
    }
    setAward(flag) {
        this.isShowing = flag;
        this.self.visible = flag;
        if (this.isShowing) {
            const info = this.GC.status.getItemInfo;
            this.vipPrizeText.visible = info.type == GameConstant_1.default.GETITEMTYPE.VIPPRIZE;
            const itemPosList = this.itemPos[info.itemList.length - 1];
            this.closeBtn.setCallback(() => {
                info.onFinish();
            });
            this.closeBtn.owner.visible = false;
            this.closeBtn.setLabelText(`确定`);
            this.isOnTimer = false;
            this.timeLeft = info.autoClose * 1000;
            this.timerLabel.visible = false;
            const length = info.itemList.length;
            for (var i = 0; i < info.itemList.length; i++) {
                this.prizeItemList[i].setInfo(info.itemList[i]);
                const sp = this.prizeItemList[i].owner;
                sp.x = this.self.width / 2 + this.itemWidth * itemPosList[i];
                sp.y = length > 5 && i > 3 ? this.secondY : this.defaultY;
                Laya.timer.once(this.duration * i, this, () => {
                    sp.visible = true;
                });
            }
            Laya.timer.once(this.duration * (info.itemList.length + 1), this, () => {
                this.closeBtn.owner.visible = true;
                this.isOnTimer = info.autoClose > 0;
            });
        }
        else {
            this.prizeItemList.forEach((element) => {
                element.owner.visible = false;
            });
        }
        this.self.mouseThrough = !this.isShowing;
        this.self.mouseEnabled = this.isShowing;
    }
}
exports.default = GetItemControl;
},{"../Control/GameCenter":3,"../GameConstant":10,"../extends/ExtBaseButton":61,"../shop/VipPrizeItemControl":64}],36:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-28 15:59:27
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-05-29 14:45:46
 */
Object.defineProperty(exports, "__esModule", { value: true });
const GameCenter_1 = require("../Control/GameCenter");
class LoadingControl extends Laya.Script {
    constructor() {
        super();
        this.isShowing = false;
    }
    onEnable() {
        this.GC = GameCenter_1.default.instance;
        this.self = this.owner;
        this.componentAni = this.self['ani'];
        this.componentCover = this.self['cover'];
        this.componentInfo = this.self['info'];
        this.self.size(Laya.stage.width, Laya.stage.height);
        if (this.componentAni) {
            this.componentAni.pos(Laya.stage.width / 2, Laya.stage.height / 2 - 100);
        }
        if (this.componentInfo) {
            this.componentInfo.pos(0, Laya.stage.height / 2 + 100);
        }
        if (this.componentCover) {
            this.componentCover.size(Laya.stage.width, Laya.stage.height).pos(0, 0);
        }
        this.setLoading(false);
    }
    onUpdate() {
        if (this.GC.status.isOnLoading !== this.isShowing) {
            this.setLoading(this.GC.status.isOnLoading);
        }
        if (this.isShowing && this.componentInfo) {
            this.componentInfo.text = this.GC.status.loadingInfo.text;
        }
    }
    setLoading(flag) {
        this.isShowing = flag;
        this.self.visible = flag;
        this.self.mouseThrough = !this.isShowing;
        this.self.mouseEnabled = this.isShowing;
    }
}
exports.default = LoadingControl;
},{"../Control/GameCenter":3}],37:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-28 15:59:36
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-06-04 19:22:49
 */
Object.defineProperty(exports, "__esModule", { value: true });
const GameSettings_1 = require("../GameSettings");
const GameCenter_1 = require("../Control/GameCenter");
// import Sprite = Laya.Sprite
class LoadingScene extends Laya.Scene {
    constructor() {
        super();
    }
    onEnable() {
        this.GC = GameCenter_1.default.instance;
        Laya.View.open('view/UserLogin.scene', false, null, Laya.Handler.create(this, (b) => {
            // if(GameSettings.isAutoLogin){
            //     this.GC.platform.login({success:(res)=>{
            //         const code = res.code
            //         this.GC.platform.getUserInfo({success:(info)=>{
            //             const nickName = info.userInfo.nickName
            //             const avatar = info.userInfo.avatarUrl
            //             this.GC.serverLogin(code,nickName,avatar)
            //         }})
            //     }})
            // }
        }));
        // Laya.View.open('view/MainBg.scene',false, null,Laya.Handler.create(this,(b)=>{
        //     (b as Laya.Sprite).zOrder = 1
        //     this.mainBg = b.getComponent(MainBgControl)
        //     this.mainBg.stopMove()
        // }))
        // Laya.View.open('view/LogoArea.scene',false, null,Laya.Handler.create(this,(b)=>{}))
        GameSettings_1.default.sceneViewList.Loading.forEach((element) => {
            Laya.View.open(element, false, null, Laya.Handler.create(this, (s) => { }));
        });
    }
}
exports.default = LoadingScene;
},{"../Control/GameCenter":3,"../GameSettings":11}],38:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-28 15:59:42
 * @Last Modified by:   Odie Robin
 * @Last Modified time: 2019-05-28 15:59:42
 */
Object.defineProperty(exports, "__esModule", { value: true });
const GameSettings_1 = require("../GameSettings");
class LogoZone extends Laya.View {
    constructor() {
        super();
    }
    onEnable() {
        this.logo = this['logoImage'];
        if (this.logo) {
            Laya.loader.load(GameSettings_1.default.logoAddress, Laya.Handler.create(this, () => {
                this.logo.graphics.loadImage(GameSettings_1.default.logoAddress);
            }));
        }
    }
}
exports.default = LogoZone;
},{"../GameSettings":11}],39:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-28 15:59:48
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-07-17 15:01:11
 */
Object.defineProperty(exports, "__esModule", { value: true });
var Sprite = Laya.Sprite;
const GameSettings_1 = require("../GameSettings");
class MainBgControl extends Laya.Script {
    constructor() {
        super(...arguments);
        this.moveFlag = true;
        this.movingLength = 0;
        this.unitLength = 1920;
        this.nowIndex = 0;
        this.isMoving = false;
        this.bgList = [];
    }
    onEnable() {
        this.unitLength = this.bgHeight;
        this.nowIndex = this.direction == 1 ? 3 : 0;
        this.moveDuration = this.unitLength / this.speed * 1000;
        this.bgHolder = new Sprite();
        this.owner.addChild(this.bgHolder.pos(0, 0));
        this.versionLabel = this.owner['verLabel'];
        this.versionLabel.text = `${GameSettings_1.default.nowVersionStr} [${GameSettings_1.default.nowSubVersion}]`;
        const par = this.owner;
        for (let i = 0; i < 4; i++) {
            const image = new Laya.Image(this.mainBgImage);
            image.size(this.bgWidth, this.bgHeight)
                .pivot(0, 0)
                .pos(0, -this.bgHeight * 2 + Laya.stage.height / 2 + i * this.bgHeight);
            this.bgHolder.addChild(image);
            this.bgList.push(image);
        }
        this.moveTarget = this.direction == 1
            ? new Laya.Point(this.bgList[0].x, this.bgList[0].y)
            : new Laya.Point(this.bgList[3].x, this.bgList[3].y);
    }
    onUpdate() {
        if (this.moveFlag && this.bgList.length > 0 && !this.isMoving) {
            this.startMove();
        }
        if (!this.moveFlag && this.isMoving) {
            this.stopMove();
        }
        // if(this.isMoving && this.bgList.length > 0){
        //     const deltaLength = this.speed * Laya.timer.delta / 1000
        //     this.movingLength += deltaLength
        //     this.bgList.forEach((element) => {
        //         element.pos(element.x,element.y + deltaLength * this.direction)
        //     })
        //     // this.bgHolder.pos(this.bgHolder.x,this.bgHolder.y + deltaLength * this.direction)
        //     if(this.movingLength >= this.unitLength){
        //         console.log(this.bgList[this.nowIndex].x,this.bgList[this.nowIndex].y)
        //         this.bgList[this.nowIndex].pos(this.bgList[this.nowIndex].x,this.moveTarget.y)
        //         console.log(this.bgList[this.nowIndex].x,this.bgList[this.nowIndex].y)
        //         this.movingLength -= this.unitLength
        //         this.nowIndex = this.getNext()
        //     }
        // }
    }
    startMove() {
        Laya.timer.once(0, this, () => {
            this.isMoving = true;
            this.bgList.forEach((bg) => {
                Laya.Tween.to(bg, { y: bg.y + this.direction * this.unitLength }, this.moveDuration, Laya.Ease.linearNone);
            });
            Laya.timer.once(this.moveDuration, this, () => {
                this.bgList[this.nowIndex].pos(this.bgList[this.nowIndex].x, this.moveTarget.y);
                this.nowIndex = this.getNext();
                this.isMoving = false;
            });
        });
    }
    stopMove() {
        this.moveFlag = false;
        Laya.timer.clearAll(this);
    }
    getNext() {
        return this.nowIndex - this.direction >= 0
            ? this.nowIndex - this.direction
            : 3;
    }
}
exports.default = MainBgControl;
},{"../GameSettings":11}],40:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const GameSettings_1 = require("../GameSettings");
const ExtBaseButton_1 = require("../extends/ExtBaseButton");
const GameCenter_1 = require("../Control/GameCenter");
const GameConstant_1 = require("../GameConstant");
/*
 * @Author: ZZL
 * @Date: 2019-06-28 14:15:35
 * @Last Modified by: ZZL
 * @Last Modified time: 2019-11-09 16:31:54
 */
class MissionControl extends Laya.View {
    constructor() {
        super(...arguments);
        this.isInit = false;
        this.MissionList = null;
        this.MissionData = null;
        this.CurrentMission = null;
        this.missionState = 0; // 0  1  2
        this.timeleft = 0;
        this.timeleft1 = 0;
        this.onMissionTimeUp = null;
        this.onMissionStart = null;
        this.isStartMission = false;
        this.isInitMissionFish = false;
        this.isFinishMissionFish = false;
    }
    onEnable() {
        this.GC = GameCenter_1.default.instance;
        this.GC.registComponent(GameConstant_1.default.GAMECOMPONENT.MISSION, this, (handler) => {
            this.callback = handler;
        });
        this.Setep1Node = this['MissionSetep1'];
        this.Setep2Node = this['MissionSetep2'];
        this.Setep3Node = this['MissionSetep3'];
        if (this.Setep1Node && this.Setep2Node && this.Setep3Node) {
            this['closeBtn'].getComponent(ExtBaseButton_1.default).setCallback(() => {
                // this.setShow(false)
                this.callback.runWith(GameConstant_1.default.USERACTIONTYPE.CLOSEMISSION);
            });
            this['closeBtn2'].getComponent(ExtBaseButton_1.default).setCallback(() => {
                this.callback.runWith(GameConstant_1.default.USERACTIONTYPE.CLOSEMISSION);
            });
            this['closeBtn3'].getComponent(ExtBaseButton_1.default).setCallback(() => {
                this.callback.runWith(GameConstant_1.default.USERACTIONTYPE.CLOSEMISSION);
            });
        }
        this['customerText'].text = `${GameConstant_1.default.PROMOTIONTEXT.CUSTOMQQ.replace('$qq$', GameSettings_1.default.customQQ)}\n${GameConstant_1.default.PROMOTIONTEXT.PUBLICACCOUNT.replace('$pa$', GameSettings_1.default.wechatPublicAccount)}`;
        this.initMis();
        this.isInit = true;
        this.setShow(false);
        Laya.timer.frameLoop(1, this, this.update);
    }
    update() {
        if (this.isShowing && this.missionState != this.GC.status.missionViewState) {
            this.missionState = this.GC.status.missionViewState;
            this.isFinishMissionFish = false;
            this.setTab();
        }
        //初始化进入任务参数
        if (this.isInitMissionFish) {
            this.isInitMissionFish = false;
            const info = this.GC.status.missInfo;
            this.timeleft = info.duration;
            this.onMissionTimeUp = info.callback;
            this.timeleft1 = info.countDown;
            this.onMissionStart = info.startCallback;
        }
        if (this.timeleft1 > 0) {
            this.timeleft1 -= Laya.timer.delta;
            this['startText1'].visible = false;
            this['countDownNumber'].visible = true;
            this['countDownNumber'].value = Math.floor(this.timeleft1 / 1000);
            if (this.timeleft1 <= 0) {
                this['countDownNumber'].visible = false;
                this['startText1'].visible = true;
                this['startBtn2'].getComponent(ExtBaseButton_1.default).toggleFrozen(false);
            }
        }
        if (this.isFinishMissionFish && this.timeleft > 0) {
            this.timeleft -= Laya.timer.delta;
            if (this.timeleft < 5000 && this.GC.status.isOnMission && !this.GC.status.isOnCountDown) {
                this.GC.status.setCountDown({ time: 5000 });
            }
            if (this.timeleft < 0) {
                if (this.onMissionTimeUp && this.GC.status.isOnMission) {
                    this.onMissionTimeUp();
                    this.isFinishMissionFish = false;
                }
            }
        }
    }
    initMis() {
        this.Setep1Node.visible = false;
        this.Setep2Node.visible = false;
        this.Setep3Node.visible = false;
    }
    // public checkState(){
    //     const data = this.MissionData
    //     if((data.mainState == 1 && data.miState > 0) || (data.mainState == 2 && data.miState == 0)){
    //         this.GC.status.missionViewState = 0
    //     }else if(data.mainState == 3){
    //         this.GC.status.missionViewState = 2
    //     }else if(data.mainState == 5){
    //         this.GC.status.missionViewState = 3
    //     }
    // }
    getMission(code) {
        let mission = null;
        this.MissionList["list"].forEach(element => {
            if (element.code == code) {
                mission = element;
            }
        });
        return mission;
    }
    setShow(isShowing) {
        this.isShowing = isShowing;
        this.visible = isShowing;
        if (isShowing) {
            this.setTab();
        }
        else {
            this.GC.status.isOnCoving = false;
        }
    }
    getStepMissionCode(step = 0) {
        let code = null;
        let codeArray = this.MissionData.flow.split('->');
        code = codeArray[step];
        return code;
    }
    setTab() {
        const data = this.MissionData;
        this.initMis();
        let currentView = null;
        if (this.GC.status.missionViewState == 0) {
            this['prize'].value = GameSettings_1.default.missionPrize;
            this['startBtn'].getComponent(ExtBaseButton_1.default).setLabelText('');
            this['startBtn2'].getComponent(ExtBaseButton_1.default).setLabelText('');
            this['btn3'].getComponent(ExtBaseButton_1.default).setLabelText('');
            if (data.miState == 1) {
                this.CurrentMission = this.getMission(data.miCode);
                this['fishIcon'].skin = GameSettings_1.default.MISSIONFISHTIPS[this.CurrentMission.miType].fishIcon;
                this['fishTipsText'].text = GameSettings_1.default.MISSIONFISHTIPS[this.CurrentMission.miType].tipsText;
                this['progress'].value = data.progress + '/' + this.CurrentMission.max;
                this['startBtn'].visible = false;
                this['Finish'].visible = false;
            }
            else if (data.miState == 2 || (data.mainState == 2 && data.miState == 0)) {
                this['startBtn'].visible = true;
                this['Finish'].visible = true;
                const missionInfo = this.getMission(this.getStepMissionCode());
                this['fishIcon'].skin = GameSettings_1.default.MISSIONFISHTIPS[missionInfo.miType].fishIcon;
                this['fishTipsText'].text = GameSettings_1.default.MISSIONFISHTIPS[missionInfo.miType].tipsText;
                this['progress'].visible = false;
                this['startBtn'].getComponent(ExtBaseButton_1.default).setCallback(() => {
                    let spMissionData = this.GC.mission.getMission(this.GC.mission.MissionData.miCode);
                    let type = spMissionData.miType.substring(2, spMissionData.miType.length); // 特殊任务 S_1
                    this.GC.fishManager.GetMissionInfo(type);
                    this.GC.status.missionViewState = 1;
                    this.isInitMissionFish = true;
                    this.GC.robot.isActivate = false;
                    this.GC.userInfoZone.cancelFreeBattery();
                });
            }
            this.Setep1Node.visible = true;
        }
        else if (this.GC.status.missionViewState == 1) {
            this['explainText'].text = '1.限时15秒 2.击杀' + this.GC.nowMissionHitFishCount + '条目标鱼 3.只能发射' + this.GC.fishManager.missionInfo.bulletCount + "发子弹";
            this['explainText1'].text = '失败后可重复挑战';
            this['prize2'].value = GameSettings_1.default.missionPrize;
            this['startBtn2'].getComponent(ExtBaseButton_1.default).toggleFrozen(true);
            const missionInfo = this.getMission(this.getStepMissionCode(1));
            let iconPath = 'mission/task_01.png';
            if (this.GC.fishManager.missionInfo) {
                let targetFishName = "F011";
                this.GC.fishManager.missionInfo.Fish.forEach(element => {
                    if (element.isTarget) {
                        targetFishName = element.fishName;
                    }
                });
                iconPath = GameSettings_1.default.MISSIONSPICONPATH[targetFishName];
            }
            this['fishIcon2'].skin = iconPath;
            this['startBtn2'].getComponent(ExtBaseButton_1.default).setCallback(() => {
                this.callback.runWith(GameConstant_1.default.USERACTIONTYPE.MISSIONSTART);
                this.isFinishMissionFish = true;
                this.GC.setMission();
                this.setShow(false);
                this.onMissionStart();
            });
            this['closeBtn2'].visible = false;
            this.Setep2Node.visible = true;
        }
        else if (this.GC.status.missionViewState == 2) {
            this['btn3'].visible = false;
            this['prize3'].value = GameSettings_1.default.missionPrize;
            this.Setep3Node.visible = true;
        }
        else if (this.GC.status.missionViewState == 3) {
            const btn = this['btn3'];
            btn.getComponent(ExtBaseButton_1.default).setLabelText('');
            btn.visible = true;
            btn.getComponent(ExtBaseButton_1.default).setCallback(() => {
                this.setShow(false);
                this.callback.runWith(GameConstant_1.default.USERACTIONTYPE.MISSIONRECBIGPRIZE);
            });
            this['getText'].visible = false;
            this.Setep3Node.visible = true;
        }
    }
}
exports.default = MissionControl;
},{"../Control/GameCenter":3,"../GameConstant":10,"../GameSettings":11,"../extends/ExtBaseButton":61}],41:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-28 15:59:52
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-07-04 19:43:58
 */
Object.defineProperty(exports, "__esModule", { value: true });
var Pool = Laya.Pool;
const GameCenter_1 = require("../Control/GameCenter");
class MissionFishControl extends Laya.Script {
    constructor() {
        super();
        /** @prop {name:speed,tips:"当前对象的速度",type:Int}*/
        this.speed = 200;
        this.isInit = false;
        this.moveLen = 0;
        this.isTargetFish = false; //目标鱼
        this.pathPosIndex = 0;
        this.faceRight = false;
        this.fishScale = 2;
    }
    onEnable() {
        this.GC = GameCenter_1.default.instance;
        this.self = this.owner;
    }
    onUpdate() {
        // if(this.isInit){
        //     this.MoveToNextPoint()
        // }
    }
    onDisable() {
        Pool.recover(this.fishType, this.owner);
    }
    setup(fishType, scale) {
        this.isInit = false;
        this.fishScale = scale;
        this.self.scale(-this.fishScale, -this.fishScale);
    }
    init(id, path, isTargetFish, waitTime = 0) {
        this.fishId = id;
        this.isTargetFish = isTargetFish;
        this.path = path;
        this.moveLen = (path.length - 1);
        this.self.pos(this.path[0].x, this.path[0].y);
        this.isInit = true;
        this.pathPosIndex = 0;
        if (waitTime != 0) {
            this.targetMove(waitTime);
        }
        else {
            this.MoveToNextPoint();
        }
    }
    targetMove(waitTime) {
        Laya.timer.once(waitTime, this, this.MoveToNextPoint);
    }
    speedUp() {
        this.onDead();
    }
    checkFace() {
        if (this.faceRight != this.moveTarget.x > this.self.x) {
            this.faceRight = this.moveTarget.x > this.self.x;
            this.self.scale(-this.fishScale, this.faceRight ? this.fishScale : -this.fishScale);
        }
    }
    MoveToNextPoint() {
        if (this.isInit) {
            if (this.moveLen > this.pathPosIndex) {
                this.pathPosIndex++;
            }
            else {
                this.pathPosIndex = 0;
            }
            let callback = null;
            if (this.path[this.pathPosIndex].isDead) {
                callback = Laya.Handler.create(this, this.onDead);
            }
            else {
                callback = Laya.Handler.create(this, this.MoveToNextPoint);
            }
            if (this.path) {
                Laya.Tween.to(this.self, {
                    x: this.path[this.pathPosIndex].x,
                    y: this.path[this.pathPosIndex].y
                }, this.path[this.pathPosIndex].time, null, callback);
            }
            this.moveTarget = new Laya.Point(this.path[this.pathPosIndex].x, this.path[this.pathPosIndex].y);
            this.self.rotation = this.getAngle(new Laya.Point(this.self.x, this.self.y), this.moveTarget);
            this.checkFace();
        }
    }
    getAngle(lhs, rhs) {
        var x = rhs.x - lhs.x;
        var y = rhs.y - lhs.y;
        var hypotenuse = Math.sqrt(Math.pow(x, 2) + Math.pow(y, 2));
        var cos = x / hypotenuse;
        var radian = Math.acos(cos);
        var angle = 180 / (Math.PI / radian);
        if (y < 0) {
            angle = -angle;
        }
        else if ((y == 0) && (x < 0)) {
            angle = 180;
        }
        return angle;
    }
    onDead(dely = 0) {
        this.isInit = false;
        this.GC.removeFish(this.fishId);
        this.owner.removeSelf();
    }
}
exports.default = MissionFishControl;
},{"../Control/GameCenter":3}],42:[function(require,module,exports){
"use strict";
/*
 * @Author: ZZL
 * @Date: 2019-07-22 15:52:56
 * @Last Modified by: ZZL
 * @Last Modified time: 2019-07-22 16:36:30
 */
Object.defineProperty(exports, "__esModule", { value: true });
const GameCenter_1 = require("../Control/GameCenter");
const GameConstant_1 = require("../GameConstant");
class Newbee extends Laya.View {
    constructor() {
        super(...arguments);
        this.stepIndex = 0;
        this.stepIndexMax = 5;
        this.versionCallback = null;
        this.isCanNext = true;
        this.isWait = false;
        this.redCount = 0;
        this.coinCount = 0;
    }
    onEnable() {
        this.GC = GameCenter_1.default.instance;
        this.GC.registComponent(GameConstant_1.default.GAMECOMPONENT.NEWBEE, this, (handler) => {
            this.callback = handler;
        });
        this.size(Laya.stage.width, Laya.stage.height);
        this.redCount = this.GC.nowUser.redPacketCnt;
        this.coinCount = this.GC.nowUser.coin;
        this.GC.nowUser.redPacketCnt = 0;
        this.GC.nowUser.coin = 0;
        this.on(Laya.Event.CLICK, this, this.Step);
        this.startNewbeeStep();
    }
    startNewbeeStep() {
        this.next = this['next'];
        this.next.pos(Laya.stage.width / 2, Laya.stage.height * 0.6);
        this.Step();
    }
    hide() {
        this._children.forEach(element => {
            element.visible = false;
        });
    }
    Step() {
        if (this.isWait) {
            switch (this.stepIndex) {
                case 5:
                    //发射子弹  等待可以点击
                    this.GC.fireNewbeeBullet();
                    this.isWait = false;
                    this.hide();
                    return;
            }
        }
        if (!this.isCanNext) {
            return;
        }
        this.hide();
        switch (this.stepIndex) {
            case 0:
                const nb1 = this['newbee1'];
                nb1.visible = true;
                const img1 = this['sp1'];
                nb1.pivot(img1.width / 2, img1.height / 2);
                console.log("Laya.stage.height", Laya.stage.height);
                nb1.pos(Laya.stage.width / 2, Laya.stage.height - img1.height - 210);
                this.next.visible = true;
                break;
            case 1:
                const nb2 = this['newbee2'];
                nb2.visible = true;
                const img2 = this['sp2'];
                nb2.pivot(img2.width / 2, img2.height / 2);
                nb2.pos(Laya.stage.width / 2, Laya.stage.height - 380);
                this.next.visible = true;
                break;
            case 2:
                const nb3 = this['newbee3'];
                nb3.visible = true;
                const img3 = this['sp3'];
                nb3.pivot(img3.width / 2, img3.height / 2);
                nb3.pos(img3.width / 2, Laya.stage.height - 240);
                this.next.visible = true;
                break;
            case 3:
                const nb7 = this['newbee7'];
                nb7.visible = true;
                const img7 = this['sp7'];
                nb7.pivot(img7.width / 2, img7.height / 2);
                nb7.pos(Laya.stage.width * 0.85 - img7.width, 460);
                const nb8 = this['newbee8'];
                nb8.visible = true;
                const img8 = this['sp8'];
                nb8.pivot(img8.width / 2, img8.height / 2);
                nb8.pos(Laya.stage.width * 0.85 - img8.width, 700);
                this.next.visible = true;
                break;
            case 4:
                const nb4 = this['newbee4'];
                nb4.visible = true;
                const img4 = this['sp4'];
                nb4.pivot(img4.width / 2, img4.height / 2);
                nb4.pos(Laya.stage.width / 2, Laya.stage.height / 2 + 300);
                this.GC.fishManager.createNewbeeFish();
                this.isCanNext = false;
                this.isWait = true;
                break;
            case 5:
                const nb5 = this['newbee5'];
                nb5.visible = true;
                const img5 = this['sp5'];
                nb5.pivot(img5.width / 2, img5.height / 2);
                nb5.pos(Laya.stage.width / 2, Laya.stage.height - 280);
                this.next.visible = true;
                break;
            case 6:
                const nb6 = this['newbee6'];
                nb6.visible = true;
                const img6 = this['sp6'];
                nb6.pivot(img6.width / 2, img6.height / 2);
                nb6.pos(Laya.stage.width * 0.5, Laya.stage.height - 280);
                this.next.visible = true;
                break;
            case 7:
                this.callback.runWith(GameConstant_1.default.USERACTIONTYPE.USERINFOREDPACK);
                this.waitFunction();
                break;
            default:
                this.callback.runWith(GameConstant_1.default.USERACTIONTYPE.NEWBEE);
                this.removeSelf();
                this.GC.status.isOnNewbee = false;
                return;
        }
        this.stepIndex++;
    }
    waitFunction() {
        Laya.timer.once(2000, this, this.setWait);
    }
    setWait() {
        this.isWait = false;
        this.isCanNext = true;
        this.Step();
    }
}
exports.default = Newbee;
},{"../Control/GameCenter":3,"../GameConstant":10}],43:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-28 15:59:52
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-07-08 13:29:37
 */
Object.defineProperty(exports, "__esModule", { value: true });
var Point = Laya.Point;
var Pool = Laya.Pool;
var Vector3 = Laya.Vector3;
const GameCenter_1 = require("../Control/GameCenter");
const GameSettings_1 = require("../GameSettings");
class PathMove extends Laya.Script {
    constructor() {
        super();
        /** @prop {name:speed,tips:"当前对象的速度",type:Int}*/
        this.speed = 200;
        this.isInit = false;
        this.moveLen = 0;
        this.isShowTargetBall = false;
        this.faceRight = false;
        this.isGatherFish = false;
    }
    onEnable() {
        this.GC = GameCenter_1.default.instance;
        this.self = this.owner;
    }
    onUpdate() {
        if (this.isInit) {
            this.MoveToNextPoint();
        }
    }
    onDisable() {
        Pool.recover(this.fishType, this.owner);
    }
    setup(type, speed, scale) {
        this.isInit = false;
        // this.fishId = id
        this.fishType = type;
        this.speed = speed;
        this.oriSpeed = speed;
        this.fishScale = scale;
        this.self.scale(-this.fishScale, -this.fishScale);
    }
    init(id, path, delay = 0, isGatherFish = false) {
        this.fishId = id;
        this.path = path;
        this.delay = delay;
        this.moveLen = 0;
        this.isGatherFish = isGatherFish;
        Laya.timer.once(this.delay * 1000, this, () => {
            this.isInit = true;
        });
    }
    speedUp() {
        this.speed = GameSettings_1.default.fishSpeedUpSpeed;
    }
    checkFace() {
        if (this.faceRight != this.moveTarget.x > this.self.x) {
            this.faceRight = this.moveTarget.x > this.self.x;
            this.self.scale(-this.fishScale, this.faceRight ? this.fishScale : -this.fishScale);
        }
    }
    MoveToNextPoint() {
        let moveDelta = this.speed * Laya.timer.delta / 1000;
        this.moveLen += moveDelta;
        const pos = this.GetPointByLen(this.moveLen);
        this.moveTarget = this.GetPointByLen(this.moveLen + moveDelta);
        this.self.pos(pos.x, pos.y);
        this.self.rotation = this.getAngle(pos, this.moveTarget);
        if (!this.isGatherFish) {
            this.checkFace();
        }
    }
    getAngle(lhs, rhs) {
        var x = rhs.x - lhs.x;
        var y = rhs.y - lhs.y;
        var hypotenuse = Math.sqrt(Math.pow(x, 2) + Math.pow(y, 2));
        var cos = x / hypotenuse;
        var radian = Math.acos(cos);
        var angle = 180 / (Math.PI / radian);
        if (y < 0) {
            angle = -angle;
        }
        else if ((y == 0) && (x < 0)) {
            angle = 180;
        }
        return angle;
    }
    GetPointByLen(len) {
        if (len > this.path.pathLen) {
            // len= len % this.path.pathLen;
            this.onDead();
        }
        let startIndex = 0;
        let endIndex = this.path.smoothPoints.length - 1;
        let middleIndex = Math.ceil((startIndex + endIndex) / 2);
        while (endIndex - startIndex > 1) {
            if (len >= this.path.pointLenInPath[middleIndex]) {
                startIndex = middleIndex;
                middleIndex = Math.ceil((startIndex + endIndex) / 2);
            }
            else {
                endIndex = middleIndex;
                middleIndex = Math.ceil((startIndex + endIndex) / 2);
            }
        }
        // console.log("Start Index : ",startIndex)
        let delLen = len - this.path.pointLenInPath[startIndex];
        let delPercent = delLen / (this.path.pointLenInPath[startIndex + 1] - this.path.pointLenInPath[startIndex]);
        let pos = new Vector3();
        let startPos = new Vector3(this.path.smoothPoints[startIndex].x, this.path.smoothPoints[startIndex].y, 0);
        let endPos = new Vector3(this.path.smoothPoints[startIndex + 1].x, this.path.smoothPoints[startIndex + 1].y, 0);
        Vector3.lerp(startPos, endPos, delPercent, pos);
        // this.moveTarget = endPos
        return new Point(pos.x, pos.y);
    }
    onDead(dely = 0) {
        this.isInit = false;
        this.speed = this.oriSpeed;
        Laya.timer.once(dely, this, () => {
            this.GC.removeFish(this.fishId);
            this.owner.removeSelf();
        });
    }
}
exports.default = PathMove;
},{"../Control/GameCenter":3,"../GameSettings":11}],44:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const GameSettings_1 = require("../GameSettings");
const ExtBaseButton_1 = require("../extends/ExtBaseButton");
const VipPrizeItemControl_1 = require("../shop/VipPrizeItemControl");
const GameCenter_1 = require("../Control/GameCenter");
const GameConstant_1 = require("../GameConstant");
/*
 * @Author: ZZL
 * @Date: 2019-06-28 14:15:35
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-12-12 18:57:22
 */
class PopupControl extends Laya.Script {
    constructor() {
        super(...arguments);
        this.isInit = false;
        this.type = null;
        this.isShowing = false;
        this.tempData = null;
        this.clickCallback = null;
    }
    onEnable() {
        this.GC = GameCenter_1.default.instance;
        this.GC.registComponent(GameConstant_1.default.GAMECOMPONENT.POPUP, this, (handler) => {
            this.callback = handler;
        });
        this.self = this.owner;
        this.setShow(false);
        this.self.on(Laya.Event.CLICK, this, () => {
            if (this.tempData.onClose && this.tempData.isTouchClose) {
                this.tempData.onClose();
            }
        });
        this.self['button'].visible = false;
        this.text = this.self['text'];
        this.clip = this.self['failClip'];
        this.bg = this.self['popupBg'];
        this.levelUp = this.self['lvUp'];
        this.versionLabel = this.self['desc'];
        this.versionCustLabel = this.self['addon'];
        this.versionImg1 = this.self['versionImg1'];
        this.versionImg2 = this.self['versionImg2'];
        this.versionImg3 = this.self['versionImg3'];
        this.edition = this.self['edition'];
        this.sureBtn = this.self['gzhBtnsure'];
        this.gzhSureBtn = this.sureBtn.getComponent(ExtBaseButton_1.default);
        this.gzhSureBtn.setLabelText('领取');
        this.gzhBg = this.self['gzhBg'];
        let item = Laya.Pool.getItemByCreateFun('VipPrizeItem', this.vipPrizeItem.create, this.vipPrizeItem);
        this.prizeItem = item.getComponent(VipPrizeItemControl_1.default);
        this.gzhBg.addChild(item.pos(this.gzhBg.width / 2, this.gzhBg.height / 2));
        this.versionsureBtn = this.self['sure'];
        this.versionSure = this.versionsureBtn.getComponent(ExtBaseButton_1.default);
        this.versionSure.setLabelText('确定');
        this.versionSure.setCallback(() => {
            this.GC.status.isOnPopup = false;
        });
        let gzgzhBtnClose = this.self['gzgzhClose'];
        this.gzgzhClose = gzgzhBtnClose.getComponent(ExtBaseButton_1.default);
        this.gzgzhClose.setCallback(() => {
            this.GC.status.isOnPopup = false;
        });
        const aquaManPrizeButton = this.self['aquaManPrizeRecBtn'];
        const aquaManPrizeButtonControl = aquaManPrizeButton.getComponent(ExtBaseButton_1.default);
        if (aquaManPrizeButtonControl) {
            aquaManPrizeButtonControl.setLabelText(`领取`);
            aquaManPrizeButtonControl.setCallback(() => {
                this.clickCallback();
            });
        }
        this.self['btnCloseShare'].getComponent(ExtBaseButton_1.default).setCallback(() => {
            this.GC.status.isOnPopup = false;
        });
        this.self['btnStartShare'].getComponent(ExtBaseButton_1.default).setCallback(() => {
            if (this.callback) {
                this.callback.runWith(GameConstant_1.default.USERACTIONTYPE.SHARENEW);
            }
        });
        this.self['RechargeShare'].addChild(this.getIntroItem().pos(99, 350));
    }
    onUpdate() {
        if (this.isShowing != this.GC.status.isOnPopup) {
            this.setShow(this.GC.status.isOnPopup);
        }
    }
    setShow(isShowing) {
        this.isShowing = isShowing;
        this.self.visible = isShowing;
        if (isShowing) {
            this.tempData = this.GC.status.popupInfo;
            this.type = this.tempData.type;
            if (this.tempData.onClose) {
                this.clickCallback = this.tempData.onClose;
            }
            this.setTab();
            this.self.zOrder = this.tempData.type == GameConstant_1.default.POPUPTYPE.INVITEINTRO ? 65 : 56;
        }
    }
    setTab() {
        console.log("setTab_", this.tempData);
        this.self._children.forEach(element => {
            element.visible = false;
        });
        let data = this.GC.status.popupInfo.JIUJIBI_Info;
        switch (this.type) {
            case GameConstant_1.default.POPUPTYPE.MISSIONFIAL:
                this.bg.skin = GameSettings_1.default.POPUPBG.FAIL;
                this.text.text = GameSettings_1.default.POPUPTIPS.MISSIONFAIL;
                this.clip.value = GameSettings_1.default.missionPrize;
                this.bg.visible = true;
                this.text.visible = true;
                this.clip.visible = true;
                break;
            case GameConstant_1.default.POPUPTYPE.MISSIONSUCCESS:
                this.bg.skin = GameSettings_1.default.POPUPBG.WIN;
                this.text.text = GameSettings_1.default.POPUPTIPS.MISSIONWIN;
                this.bg.visible = true;
                this.text.visible = true;
                break;
            case GameConstant_1.default.POPUPTYPE.LEVELUP:
                this.levelUp.visible = true;
                this.self["unLockGunValueText"].value = this.tempData.levelUpInfo.unclock_batteryLv;
                this.levelUpAnimation(this.levelUp);
                break;
            case GameConstant_1.default.POPUPTYPE.VERSIONINFO:
                this.edition.visible = true;
                this.versionImg1.visible = true;
                this.versionImg2.visible = true;
                this.versionImg3.visible = true;
                this.versionLabel.text = this.tempData.versionInfo.info.join('\n\n');
                this.versionLabel.visible = true;
                this.versionCustLabel.text = `${GameConstant_1.default.PROMOTIONTEXT.CUSTOMQQ.replace('$qq$', GameSettings_1.default.customQQ)}`;
                this.versionCustLabel.visible = true;
                this.sureBtn.visible = true;
                break;
            case GameConstant_1.default.POPUPTYPE.JIUJIBI:
                if (data.is_show == 1) {
                    this.self['pack']._children.forEach(element => {
                        element.visible = true;
                    });
                    this.self['pack'].visible = true;
                    let info = {
                        count: data.prize
                    };
                    this.prizeItem.setInfo(info);
                    let prizeSp = this.prizeItem.owner;
                    prizeSp.scale(2, 2);
                    this.gzhSureBtn.setCallback(() => {
                        if (this.tempData.onClose && !this.tempData.isTouchClose) {
                            this.tempData.onClose();
                        }
                    });
                }
                else if (data.is_show == 3) {
                    this.self['Concern']._children.forEach(element => {
                        element.visible = true;
                    });
                    this.self['Concern'].visible = true;
                    this.self['gzgzhAddon'].text = `${GameConstant_1.default.PROMOTIONTEXT.CUSTOMQQ.replace('$qq$', GameSettings_1.default.customQQ)}`;
                }
                else if (data.is_show == 2) {
                }
                else {
                    //this.GC.status.openShop(GameConstant.SHOPTYPE.DIAMOND)
                }
                break;
            case GameConstant_1.default.POPUPTYPE.AQUAMANPRIZE:
                this.self['aquaManPrizeHolder'].visible = true;
                this.self['aquaManPrizeLabel'].text = `恭喜获得海王榜第` + this.tempData.seq + '名';
                this.self['aquaManPrizeCount'].value = this.tempData.redPack;
                break;
            case GameConstant_1.default.POPUPTYPE.INVITEINTRO:
                this.self['RechargeShare'].visible = true;
                break;
            default:
                break;
        }
    }
    levelUpAnimation(obj) {
        obj.alpha = 1;
        Laya.Tween.to(obj, { alpha: 0 }, 3000, null, Laya.Handler.create(this, this.hide));
    }
    hide() {
        this.GC.status.isOnPopup = false;
    }
    getIntroItem() {
        return Laya.Pool.getItemByCreateFun('ShareRedPackRuleDetail', this.introItem.create, this.introItem);
    }
}
exports.default = PopupControl;
},{"../Control/GameCenter":3,"../GameConstant":10,"../GameSettings":11,"../extends/ExtBaseButton":61,"../shop/VipPrizeItemControl":64}],45:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-30 14:46:43
 * @Last Modified by: ZZL
 * @Last Modified time: 2019-12-25 18:38:17
 */
Object.defineProperty(exports, "__esModule", { value: true });
const GameConstant_1 = require("../GameConstant");
const ExtBaseButton_1 = require("../extends/ExtBaseButton");
const GameCenter_1 = require("../Control/GameCenter");
class RechargeActivity extends Laya.Script {
    constructor() {
        super(...arguments);
        this.nowType = 0;
        this.isShowing = false;
        this.isRuleShow = false;
    }
    onEnable() {
        this.GC = GameCenter_1.default.instance;
        this.self = this.owner;
        this.tabFirst = this.self['coinBtn'].getComponent(ExtBaseButton_1.default);
        this.tabFirst.setLabelText('首充');
        this.tabFirst.setLabelOffset(0, 20);
        this.tabFirst.setCallback(() => {
            this.GC.status.setShop(GameConstant_1.default.RECHARGEACTIVITYTYPE.FIRST);
            this.callbackAction.runWith([GameConstant_1.default.USERACTIONTYPE.RECHARGEACTIVITY, GameConstant_1.default.RECHARGEACTIVITYTYPE.FIRST]);
        });
        this.tabFree = this.self['redPackBtn'].getComponent(ExtBaseButton_1.default);
        this.tabFree.setLabelText('免单');
        this.tabFree.setLabelOffset(0, 20);
        this.tabFree.setCallback(() => {
            this.GC.status.setShop(GameConstant_1.default.RECHARGEACTIVITYTYPE.FREE);
            this.callbackAction.runWith([GameConstant_1.default.USERACTIONTYPE.RECHARGEACTIVITY, GameConstant_1.default.RECHARGEACTIVITYTYPE.FREE]);
        });
        this.tabs = [this.tabFirst, this.tabFree];
        this.closeBtn = this.self['close'].getComponent(ExtBaseButton_1.default);
        this.closeBtn.setCallback(() => {
            // this.GC.status.closeShop()
            this.callbackAction.runWith(GameConstant_1.default.USERACTIONTYPE.CLOSESHOP);
        });
        this.tabFirstPag = this.self['First'];
        this.tabFreePag = this.self['Freesheet'];
        this.tabsPagList = [this.tabFirstPag, this.tabFreePag];
        this.ruleBtn = this.self['btnRule'];
        this.ruleBtn.visible = false;
        this.ruleBtn.on(Laya.Event.CLICK, this, () => {
            this.showRule(!this.isRuleShow);
        });
        this.ruleImage = this.self['ruleImage'];
        this.ruleBtn.on(Laya.Event.CLICK, this, () => {
            this.showRule(false);
        });
        this.self['progress']._children.forEach(element => {
            if (element.name != "progressBg") {
                this.FreeProgress.push(element);
            }
        });
        this.GC.registComponent(GameConstant_1.default.GAMECOMPONENT.RECHARGEACTIVITY, this, (callback) => {
            this.callbackAction = callback;
        });
    }
    showRule(flag = true) {
        this.ruleImage.visible = flag;
    }
    setTab() {
        this.tabs.forEach((element) => {
            element.toggleChcek(false);
        });
        this.tabs[this.nowType].toggleChcek(true);
        this.tabsPagList.forEach((element) => {
            element.visible = false;
        });
        switch (this.nowType) {
            case GameConstant_1.default.RECHARGEACTIVITYTYPE.FIRST:
                this.tabFirstPag.visible = true;
                break;
            case GameConstant_1.default.RECHARGEACTIVITYTYPE.FREE:
                this.tabFreePag.visible = true;
                break;
        }
    }
    setShop(flag) {
        this.isShowing = flag;
        this.self.visible = flag;
        this.setTab();
    }
    onUpdate() {
        if (this.isShowing != this.GC.status.isOnShop) {
            this.nowType = this.GC.status.nowRechargeType;
            this.setShop(this.GC.status.isOnShop);
        }
        if (this.isShowing && this.nowType != this.GC.status.nowRechargeType) {
            this.nowType = this.GC.status.nowRechargeType;
            this.setTab();
        }
    }
}
exports.default = RechargeActivity;
},{"../Control/GameCenter":3,"../GameConstant":10,"../extends/ExtBaseButton":61}],46:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const GameCenter_1 = require("../Control/GameCenter");
const ExtBaseButton_1 = require("../extends/ExtBaseButton");
const RedPackShopItemControl_1 = require("../shop/RedPackShopItemControl");
const GameConstant_1 = require("../GameConstant");
const GameSettings_1 = require("../GameSettings");
class RedPackShopControl extends Laya.Script {
    constructor() {
        super(...arguments);
        /**
         * 当前商城类型
         * 设置Tab
         * 参考值：GameConstant.REDPACKSHOPTYPE
         */
        this.nowShopType = 0;
        this.isShowing = false;
        this.itemList = [];
        this.itemPosList = [
            { x: 70, y: 690 },
            { x: 530, y: 690 },
            { x: 70, y: 1115 },
            { x: 530, y: 1115 }
        ];
    }
    onEnable() {
        this.GC = GameCenter_1.default.instance;
        this.self = this.owner;
        this.goodsList = [GameSettings_1.default.redPackRmbGoods, GameSettings_1.default.redPackCoinGoods, GameSettings_1.default.redPackVipGoods];
        this.goodsTypeList = [GameConstant_1.default.SHOPGOODSTYPE.REDPACK, GameConstant_1.default.SHOPGOODSTYPE.REDPACKCOIN, GameConstant_1.default.SHOPGOODSTYPE.REDPACKVIP];
        this.tabRedPack = this.self['redPackBtn'].getComponent(ExtBaseButton_1.default);
        this.tabRedPack.setCallback(() => {
            this.callbackAction.runWith([GameConstant_1.default.USERACTIONTYPE.CHANGEREDPACKSHOPTYPE, GameConstant_1.default.REDPACKSHOPTYPE.REDPACK]);
        });
        this.tabRedPack.setLabelText('红包');
        this.tabRedPack.setLabelOffset(0, 10);
        this.tabVip = this.self['vipBtn'].getComponent(ExtBaseButton_1.default);
        this.tabVip.setCallback(() => {
            this.callbackAction.runWith([GameConstant_1.default.USERACTIONTYPE.CHANGEREDPACKSHOPTYPE, GameConstant_1.default.REDPACKSHOPTYPE.VIP]);
        });
        this.tabVip.setLabelText('VIP经验');
        this.tabVip.setLabelOffset(0, 10);
        this.tabCoin = this.self['coinBtn'].getComponent(ExtBaseButton_1.default);
        this.tabCoin.setCallback(() => {
            this.callbackAction.runWith([GameConstant_1.default.USERACTIONTYPE.CHANGEREDPACKSHOPTYPE, GameConstant_1.default.REDPACKSHOPTYPE.COIN]);
        });
        this.tabCoin.setLabelText('金币');
        this.tabCoin.setLabelOffset(0, 10);
        this.tabs = [this.tabRedPack, this.tabCoin, this.tabVip];
        this.userId = this.self['idLabel'];
        this.userId.text = this.GC.nowUser.uid;
        this.userRedPackCount = this.self['redPackValue'];
        this.userVip = this.self['vipLevel'];
        this.userRedPackRecCount = this.self['recCountLeft'];
        this.userRedPackRecNoLimit = this.self['recCountLeftNoLimit'];
        this.redPackBonusSign = this.self['bonusRedPack'];
        this.coinBonusSign = this.self['bonusCoin'];
        this.vipBonusSign = this.self['bonusVip'];
        this.redPackBonusSign.visible = GameSettings_1.default.goodsHasBonus.redPackRmbGoods;
        this.coinBonusSign.visible = GameSettings_1.default.goodsHasBonus.redPackCoinGoods;
        //this.vipBonusSign.visible = GameSettings.goodsHasBonus.redPackVipGoods
        this.bottomInfo = this.self['bottomText'];
        this.bottomInfo1 = this.self['bottomText1'];
        this.bottomInfo.text = GameConstant_1.default.PROMOTIONTEXT.PUBLICACCOUNT.replace('$pa$', GameSettings_1.default.wechatPublicAccount);
        this.bottomInfo1.text = GameConstant_1.default.PROMOTIONTEXT.CUSTOMQQ.replace('$qq$', GameSettings_1.default.customQQ);
        // this.bottomInfo.editable = false
        this.closeBtn = this.self['close'].getComponent(ExtBaseButton_1.default);
        this.closeBtn.setCallback(() => {
            this.callbackAction.runWith(GameConstant_1.default.USERACTIONTYPE.CLOSEREDPACKSHOP);
        });
        this.redPackTip = this.self['RedPackShopTip'];
        this.redPackTip.visible = false;
        this.self['RedPackShopTipTouch'].on(Laya.Event.CLICK, this, () => {
            this.redPackTip.visible = false;
        });
        for (let i = 0; i < 4; i++) {
            let item = Laya.Pool.getItemByCreateFun('ShopItem', this.shopItem.create, this.shopItem);
            let ic = item.getComponent(RedPackShopItemControl_1.default);
            this.self.addChild(item.pos(this.itemPosList[i].x, this.itemPosList[i].y));
            ic.setCallbck((info) => {
                if (this.callbackAction) {
                    this.callbackAction.runWith([GameConstant_1.default.USERACTIONTYPE.REDPACKPURCH, info]);
                }
            });
            this.itemList.push(ic);
        }
        this.setShop(false);
        this.GC.registComponent(GameConstant_1.default.GAMECOMPONENT.REDPACKSHOP, this, (callback) => {
            this.callbackAction = callback;
        });
    }
    onUpdate() {
        if (this.isShowing != this.GC.status.isOnRedPackShop) {
            this.nowShopType = this.GC.status.nowRedPackShopType;
            this.setShop(this.GC.status.isOnRedPackShop);
        }
        if (this.isShowing && this.nowShopType != this.GC.status.nowRedPackShopType) {
            this.nowShopType = this.GC.status.nowRedPackShopType;
            this.setTab();
        }
        if (this.isShowing && (this.userVipValue != this.GC.nowUser.vip
            || this.userRedPackCountValue != this.GC.nowUser.redPacketCnt
            || this.userRecCount != this.GC.nowUser.redPacketRecOtherMoneyCnt)) {
            this.setUserInfo();
        }
    }
    setUserInfo() {
        this.userRedPackCountValue = this.GC.nowUser.redPacketCnt;
        this.userRedPackCount.text = `${this.userRedPackCountValue}`;
        this.userVipValue = this.GC.nowUser.vip;
        this.userRecCount = this.GC.nowUser.redPacketRecOtherMoneyCnt;
        this.userVip.skin = `uibase/textVip_${this.userVipValue}.png`;
        this.userRedPackRecCount.visible = this.userRecCount < 99;
        this.userRedPackRecNoLimit.visible = this.userRecCount >= 99;
        this.userRedPackRecCount.value = `${this.userRecCount}`;
    }
    setShop(flag) {
        this.isShowing = flag;
        this.self.visible = flag;
        if (this.isShowing) {
            this.setTab();
            this.setUserInfo();
        }
    }
    setTab() {
        this.tabs.forEach((element) => {
            element.toggleChcek(false);
        });
        this.tabs[this.nowShopType].toggleChcek(true);
        if (this.redPackTip) {
            this.redPackTip.visible = false;
            if (this.nowShopType == GameConstant_1.default.REDPACKSHOPTYPE.REDPACK) {
                this.redPackTip.visible = true;
            }
        }
        const infoList = this.goodsList[this.nowShopType];
        const goodsType = this.goodsTypeList[this.nowShopType];
        for (let i = 0; i < 4; i++) {
            this.itemList[i].setInfo(Object.assign({ goodsType: goodsType }, infoList[i]));
        }
        // this.tabContent.forEach((element) =>{
        //     element.visible = false
        // })
        // this.tabContent[this.nowShopType].visible = true
    }
}
exports.default = RedPackShopControl;
},{"../Control/GameCenter":3,"../GameConstant":10,"../GameSettings":11,"../extends/ExtBaseButton":61,"../shop/RedPackShopItemControl":62}],47:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-28 15:59:58
 * @Last Modified by: ZZL
 * @Last Modified time: 2019-12-17 16:05:42
 */
Object.defineProperty(exports, "__esModule", { value: true });
const GameCenter_1 = require("../Control/GameCenter");
const GameConstant_1 = require("../GameConstant");
const GameSettings_1 = require("../GameSettings");
class RobotControl extends Laya.View {
    constructor() {
        super();
        this.isInit = false;
        this.isOut = true;
        this.isMoveIn = false;
        this.isActivate = true;
        this.currentActivate = true;
        this.robotFishDaedRate = null;
        this.robotBatteryLvList = null;
        this.robotName = [
            "薄荷微凉", "白云森林", "素手挽清风", "故乡梨花", "撑起纸伞", "杏花老街", "撩起裙角", "远山芙蓉",
            "树拓静秋", "温柔腔", "碎花信纸", "凌晨车站", "白衣胜雪", "梨花未盛开", "果味纯氧", "轻颦浅笑", "粉色领结", "南音少女", "热恋少女", "荔枝妹妹", "白山茶",
            "橙子味的风", "拂来春风", "夏树繁花", "晨曦微暖", "月竹挽风", "白云悠悠", "冥雪幽兰", "清风少女", "简洁的白裙", "森裙", "吊带少女", "风吹柳", "校服的裙摆",
            "粉色卷耳兔", "绿柚", "微凉薄荷糖", "白衣扶弦", "草莓樱桃风", "海棠花开", "梨花", "春风袅袅", "颈上鲜草莓", "暖如煦阳", "山深闻鹧鸪", "秋月春风", "醉晨色",
            "清凉", "秋水潺潺", "风吹少女心", "微风荡漾", "飘落散花", "晨风暖", "半袖桃花", "微风情", "一夜听春雨", "海风少女", "江畔旧时月", "晨曦吻了脸", "杏花沾",
            "淡若清风", "微风轻柔", "月依秋水", "冷月星空", "梓萱", "一帘剑影", "陌上花开", "阡", "碧海蓝天", "芊絮", "慕莎", "轻妆淡抹", "繁星春水", "凌月", "汐黛",
            "颜汐梧", "怡雪素颜", "沁雪蓝馨", "月影", "曦雪", "月纱", "朝花夕拾", "月清落花", "芯蕊", "末学", "弥云裳", "寒鸢", "月疏影", "云淡风清", "奶昔",
            "浅蓝◇娇茜", "岁月静好", "花开花落", "蝶梦", "馨芸", "娅楠", "霜翼", "雨嘉", "你很特别。", "纯粹一点。", "乍见之欢。", "在那以后。", "三十九度风", "超喜欢你",
            "好感都给你。", "看到你好害羞", "讲后来", "此夜此月", "暖风撩人。", "兔子丢了", "白头吟。", "脸红得思春期", "少女心事", "软得离谱", "热爱世界", "沙沙粒小", "七七",
            "你的背包", "意中人", "万劫不复", "梓梦", "愛殇璃", "万劫不复", "源来凯始玺欢你", "小傻瓜", "凤舞天涯", "小兔几", "天煞孤星", "遗失的美好", "十二",
            "浅浅淡淡", "最好是你", "最单纯的乌龟", "伊面", "洋洋洒洒", "您的好友蓝忘机已上羡", "魔", "紫轩蝶泪", "蛮可爱", "最笨的告白", "喪", "后来的我们", "童话",
            "似梦非梦", "谈情不如逗狗", "高冷爸爸", "南城旧梦", "别理我", "诺曦", "悲欢浪女", "一枫情书", "尹雨沫", "呆橘", "困倦", "玉环", "青柠芒果", "来日方长",
            "痞味浪人", "旧城空念", "世界和平", "二货你真萌", "老子叫无熙", "唐婉", "骄傲", "冰火雁神", "老娘不死你永远是小三", "慈悲佛祖", "满地尘埃落定", "圈圈圆圆圈圈",
            "寻找我们的幸福", "孤蝉", "尴尬癌患者", "身边", "所谓喜欢", "南笙", "失而复得", "转身以后", "勿忘心安", "神回复", "江湖彼岸", "段念尘", "饭团", "你的笑",
            "烟花易冷人易散", "蓦然回首", "北恋", "白日梦", "美羊羊", "罗罗贝儿", "小红帽", "灯下孤影", "爱冒险", "水中月", "过气美图社", "陈独秀", "陈甜", "柒七",
            "遗忘曾经", "娇纵", "不顾", "衣神在巴黎", "篱下浅笙歌", "情话墙", "酷炫老祖宗", "打小就很酷", "南风起", "我的奇迹", "浅忆", "油焖大侠", "半夏半凉", "玩物",
            "吖咩", "猫七", "可可"
        ];
        this.robotSetting = {
            lv: 1,
            name: "999",
            coin: 9999999,
            batteryId: "1",
            changeGunAngleInterval: 30,
            batteryData: null,
            coinRuleData: null,
            exchangeBatteryAngleRate: 0,
            exchangeRobotTime: 20,
            lvDiff: 3,
            shootTimeData: null
        };
        this.robotInfo = {
            lv: 2,
            name: "test",
            coin: 9999,
            battertLv: 1000,
            changeGunAngleInterval: 30,
            batteryId: "1",
            exchangeBatteryAngleRate: 0.3,
            exchangeRobotTime: 20,
            shootTimeData: 150,
            gunRateValue: 0
        };
        this.robotSetLabel = {
            lv: null,
            coin: null,
            robotInfo: null,
            gunShip: null,
            batteryLv: null
        };
    }
    onEnable() {
        this.GC = GameCenter_1.default.instance;
        if (!this.isInit) {
            this.init();
        }
        this._children.forEach(element => {
            switch (element.name) {
                case "robotInfo":
                    this.robotSetLabel.robotInfo = element;
                    this.robotSetLabel.robotInfo._children.forEach(element => {
                        switch (element.name) {
                            case "coin":
                                this.robotSetLabel.coin = element;
                                break;
                            case "userLv_name":
                                this.robotSetLabel.lv = element;
                                break;
                        }
                    });
                    break;
                case "gunShip":
                    this.robotSetLabel.gunShip = element;
                    this.robotSetLabel.gunShip._children.forEach(element => {
                        switch (element.name) {
                            case "gunBatteryLv":
                                this.robotSetLabel.batteryLv = element;
                                break;
                        }
                    });
                    break;
            }
        });
        Laya.timer.frameLoop(5, this, this._update);
    }
    setRobotInfo() {
        if (!this.isActivate) {
            return;
        }
        let lv = Math.floor((this.GC.nowUser.lv - this.robotSetting.lvDiff) + Math.random() * 2 * this.robotSetting.lvDiff);
        console.log("lv:", lv);
        if (lv < 2) {
            lv = 2;
        }
        else if (lv > 50) {
            lv = 50;
        }
        let coin = 0;
        let batteryId = "1";
        let name = this.robotName[Math.floor(Math.random() * this.robotName.length)];
        let shootTime = Math.floor(Math.random() * ((parseInt(this.robotSetting.shootTimeData[1]) - parseInt(this.robotSetting.shootTimeData[0])))) + parseInt(this.robotSetting.shootTimeData[0]);
        let batteryLv = this.robotBatteryLvList[lv - 1].batteryLv;
        for (let k = 0; k < this.robotSetting.coinRuleData.length; k++) {
            let coinData = this.robotSetting.coinRuleData[k].split(',');
            let lvData = coinData[0].split('-');
            if (lv >= parseInt(lvData[0]) && lv <= parseInt(lvData[1])) {
                let coinNumberData = coinData[1].split('-');
                let num = Math.floor(Math.random() * (parseInt(coinNumberData[1]) - parseInt(coinNumberData[0])) + parseInt(coinNumberData[0]));
                //console.log("num:",num)
                coin = Math.floor(num / 10) * 10 * batteryLv;
                break;
            }
        }
        for (let j = 0; j < this.robotSetting.batteryData.length; j++) {
            let batteryData = this.robotSetting.batteryData[j].split(',');
            let batteryIdData = batteryData[0].split('-');
            if (lv >= parseInt(batteryIdData[0]) && lv <= parseInt(batteryIdData[1])) {
                let batteryIdList = batteryData[1].split('-');
                batteryId = (batteryIdList[Math.floor(Math.random() * batteryIdList.length)]).toString();
                break;
            }
        }
        this.robotInfo = {
            lv: lv,
            name: name,
            coin: coin,
            battertLv: this.robotBatteryLvList[lv - 1].batteryLv,
            changeGunAngleInterval: this.robotSetting.changeGunAngleInterval,
            batteryId: batteryId,
            exchangeBatteryAngleRate: this.robotSetting.exchangeBatteryAngleRate,
            exchangeRobotTime: this.robotSetting.exchangeRobotTime,
            shootTimeData: shootTime,
            gunRateValue: 0
        };
        this.robotSetLabel.batteryLv.value = this.robotInfo.battertLv;
        console.log("this.robotInfo:", this.robotInfo);
        let waitTime = (Math.floor(Math.random() * 5 + 5)) * 1000;
        Laya.timer.once(waitTime, this, this.moveIn);
    }
    onDisable() {
        //Laya.timer.clearAll(this._update);
    }
    init() {
        this.GC.registComponent(GameConstant_1.default.GAMECOMPONENT.ROBOTINFO, this, () => {
            Laya.View.open('view/RobotShip.scene', false, null, Laya.Handler.create(this, (s) => {
                this.ship = s;
                const pos = this["batteryPosition"];
                pos.addChild(this.ship);
                this.ship.pos(0, 0);
                this.ship.rotation = 180;
                //------bate--------
                //this.moveIn()
            }));
        });
    }
    _update() {
        if (!this.isOut) {
            if (this.robotSetLabel.coin.value != this.robotInfo.coin) {
                this.robotSetLabel.coin.value = this.robotInfo.coin;
            }
            if (this.robotInfo.coin <= 20 * this.robotInfo.battertLv) {
                this.isActivate = false;
                Laya.timer.once(1000 * 20, this, () => {
                    this.isActivate = true;
                    this.setRobotInfo();
                }, null, true);
            }
        }
        //控制是否激活机器人功能
        if (this.ship && this.isActivate != this.currentActivate) {
            this.currentActivate = this.isActivate;
            if (!this.currentActivate) {
                if (!this.isOut) {
                    this.moveOut();
                }
                if (this.isMoveIn) {
                    Laya.timer.once(1000, this, this.moveOut);
                }
            }
            else {
                this.setRobotInfo();
            }
        }
        //控制是否显示机器人信息
        if (this.robotSetLabel.robotInfo.visible != !this.isOut) {
            this.robotSetLabel.lv.text = "Lv:" + this.robotInfo.lv + "  " + this.robotInfo.name;
            this.robotSetLabel.robotInfo.visible = !this.isOut;
            if (this.ship) {
                this.ship.isActivation = !this.isOut;
            }
        }
    }
    checkHit(arr) {
        arr.forEach(element => {
            this.robotFishDaedRate.forEach(element1 => {
                if (element1.fishType == element.fishType) { //element.fishType
                    if (Math.random() < element1.rate) {
                        const itemList = [];
                        element.playDead();
                        let fish = this.GC.getFish(element.fishId);
                        const point = new Laya.Point(fish.x, fish.y);
                        itemList.push({ id: GameConstant_1.default.ITEMTYPE.ROBOTCOIN, desc: GameSettings_1.default.coinDropSetting[element1.fishType] });
                        this.GC.drop.flyItems(itemList, point);
                        this.robotFishDaedRate.score * this.robotInfo.battertLv;
                        let score = 0;
                        let scoreList = element1.score.split('-');
                        let getCoin = 0;
                        if (scoreList.length > 1) {
                            let num1 = parseInt(scoreList[1]);
                            let num0 = parseInt(scoreList[0]);
                            getCoin = (Math.floor(Math.random() * (num1 - num0)) + num0) * this.robotInfo.battertLv;
                        }
                        else {
                            getCoin = scoreList[0] * this.robotInfo.battertLv;
                        }
                        this.robotInfo.coin += getCoin;
                        this.GC.drop.onFishDead(element.fishType, getCoin, point);
                    }
                }
            });
        });
    }
    CountDown(num) {
        //this.setRobotInfoPag()
        if (this.isMoveIn) {
            this.isMoveIn = false;
            this.isOut = false;
            this.isExchangeGun();
        }
        else {
            Laya.timer.clear(this, this.checkExchange);
            if (this.GC.robotShip) {
                this.GC.robotShip.rotation = 180;
            }
        }
        Laya.timer.once(1000 * num, this, () => {
            if (this.isOut) {
                this.setRobotInfo();
            }
            else {
                this.moveOut();
            }
        }, null, true);
    }
    isExchangeGun() {
        Laya.timer.loop(1000 * this.robotInfo.changeGunAngleInterval, this, this.checkExchange); //this.robotInfo.changeGunAngleInterval
    }
    checkExchange() {
        this.GC.robotShip.rotation = 225;
        let r = Math.random();
        if (r < this.robotInfo.exchangeBatteryAngleRate) {
            if (!this.isOut) {
                this.exchangeGun();
            }
        }
    }
    exchangeGun() {
        let r = 180;
        switch (Math.floor(Math.random() * 4)) {
            case 0:
                r = 180 + 45;
                break;
            case 1:
                r = 180;
                break;
            case 2:
                r = 180 - 45;
                break;
        }
        if (this.robotInfo.gunRateValue != r) {
            this.robotInfo.gunRateValue = r;
            this.GC.robotShip.rotation = this.robotInfo.gunRateValue;
        }
        this.isExchangeGun();
    }
    moveIn() {
        if (this.GC.robotShip) {
            this.GC.robotShip.setBattery("1");
        }
        this.isMoveIn = true;
        if (this.GC.robotShip) {
            this.GC.robotShip.rotation = 180;
        }
        Laya.Tween.to(this.robotSetLabel.gunShip, { y: this.robotSetLabel.gunShip.y + 400 }, 1000, null, Laya.Handler.create(this, this.CountDown, [this.robotInfo.shootTimeData])); //this.robotInfo.shootTimeData
    }
    moveOut() {
        this.isOut = true;
        Laya.Tween.to(this.robotSetLabel.gunShip, { y: this.robotSetLabel.gunShip.y - 400 }, 1000, null, Laya.Handler.create(this, this.CountDown, [this.robotInfo.exchangeRobotTime]));
    }
    getDropTarget(type) {
        let point = null;
        switch (type) {
            case GameConstant_1.default.ITEMTYPE.ROBOTCOIN:
                point = new Laya.Point(this.robotSetLabel.lv.x, this.robotSetLabel.lv.y);
                break;
        }
        if (point) {
            point = this.localToGlobal(point);
        }
        return point;
    }
}
exports.default = RobotControl;
},{"../Control/GameCenter":3,"../GameConstant":10,"../GameSettings":11}],48:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-12-12 17:18:05
 * @Last Modified by: ZZL
 * @Last Modified time: 2019-12-17 15:09:04
 */
Object.defineProperty(exports, "__esModule", { value: true });
const Tarsis_1 = require("../utils/Tarsis");
const ExtBaseButton_1 = require("../extends/ExtBaseButton");
class ShareIntroControl extends Tarsis_1.ViewControl {
    onEnable() {
        super.onEnable();
        this.filtAllChildren(this.onFilteElement);
    }
    onFilteElement(element, view) {
        switch (element.name) {
            case 'btnRule':
                view.btnDetail = element.getComponent(ExtBaseButton_1.default);
                view.btnDetail.setCallback(() => {
                    view.infoImg.visible = true;
                });
                break;
            case 'Formula':
                view.infoImg = element;
                view.infoImg.on(Laya.Event.CLICK, this, () => {
                    view.infoImg.visible = false;
                });
                view.infoImg.visible = false;
                break;
            case 'ruleBg':
                view.bg = element;
                view.bg.on(Laya.Event.CLICK, this, () => {
                    view.infoImg.visible = false;
                });
                break;
        }
    }
    closeDetail() {
        if (this.infoImg) {
            this.infoImg.visible = false;
        }
    }
}
exports.default = ShareIntroControl;
},{"../extends/ExtBaseButton":61,"../utils/Tarsis":66}],49:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-12-12 11:30:42
 * @Last Modified by: ZZL
 * @Last Modified time: 2019-12-17 16:29:51
 */
Object.defineProperty(exports, "__esModule", { value: true });
const Tarsis_1 = require("../utils/Tarsis");
const ExtBaseButton_1 = require("../extends/ExtBaseButton");
const GameCenter_1 = require("../Control/GameCenter");
const GameConstant_1 = require("../GameConstant");
const ShareRedPackPrizeItemControl_1 = require("./ShareRedPackPrizeItemControl");
const ShareIntroControl_1 = require("./ShareIntroControl");
class ShareRedPackPrizeControl extends Tarsis_1.ViewControl {
    constructor() {
        super(...arguments);
        this.isOnShow = false;
        this.prizeItemHolderDragLength = 0;
        this.prizeItemHolderDragStartPosY = 0;
        this.prizeItemInsertY = 0;
        this.prizeitemSingleHeight = 106;
    }
    onEnable() {
        super.onEnable();
        this.filtAllChildren(this.onFilteElement);
        this.GC = GameCenter_1.default.instance;
        this.GC.registComponent(GameConstant_1.default.GAMECOMPONENT.SHARENEW, this, (handler) => {
            this.handler = handler;
        });
        this.prizeItemRealList = [];
        this.setList([]);
    }
    onUpdate() {
        if (this.isOnShow != this.GC.status.isOnShare) {
            this.isOnShow = this.GC.status.isOnShare;
            this.setShow(this.isOnShow);
            if (this.isOnShow && this.ruleDetail) {
                this.ruleDetail.closeDetail();
            }
        }
    }
    get prizeItemDragArae() {
        if (this.prizeItemHolder) {
            if (this.prizeItemHolder.height > 1100) {
                return new Laya.Rectangle(this.prizeItemHolder.x, -this.prizeItemHolder.height + 1100, 0, this.prizeItemHolder.height - 1100);
            }
            else {
                return new Laya.Rectangle(0, 0, 0, 0);
            }
        }
        else {
            return null;
        }
    }
    onFilteElement(element, view) {
        switch (element.name) {
            case 'prizeListHolder':
                view.prizeItemHolder = element;
                view.prizeItemHolder.height = 1300;
                view.prizeItemHolder.on(Laya.Event.MOUSE_DOWN, view, () => {
                    if (view.prizeItemHolder.height > 1100) {
                        this.prizeItemHolderDragStartPosY = this.prizeItemHolder.y;
                        this.prizeItemHolderDragLength = 0;
                        this.prizeItemHolder.startDrag(view.prizeItemDragArae);
                        Laya.timer.frameLoop(1, view, view.onItemHolderDrage);
                    }
                });
                view.prizeItemHolder.on(Laya.Event.MOUSE_DOWN, view, () => {
                    if (view.prizeItemHolder.height > 1100) {
                        Laya.timer.clear(view, view.onItemHolderDrage);
                    }
                });
                break;
            case 'prizeItemZone':
                view.prizeItemZone = element;
                view.prizeItemZone.scrollRect = new Laya.Rectangle(0, 0, view.prizeItemZone.width, view.prizeItemZone.height);
                view.onFilterChildrenElement(element, view);
                break;
            case 'btnRule':
                view.btnRule = element.getComponent(ExtBaseButton_1.default);
                view.btnRule.setCallback(() => {
                    if (view.ruleWindow) {
                        view.ruleWindow.visible = true;
                    }
                });
                break;
            case 'btnShare':
                view.btnShare = element.getComponent(ExtBaseButton_1.default);
                view.btnShare.setCallback(() => {
                    if (view.handler) {
                        view.handler.runWith(GameConstant_1.default.USERACTIONTYPE.SHARENEW);
                    }
                });
                break;
            case 'btnRec':
                view.btnRec = element.getComponent(ExtBaseButton_1.default);
                view.btnRec.setCallback(() => {
                    if (view.handler) {
                        view.handler.runWith(GameConstant_1.default.USERACTIONTYPE.SHANRNEWREC);
                    }
                });
                break;
            case 'ShareRule':
                view.ruleWindow = element;
                view.ruleWindow.visible = false;
                view.onFilterChildrenElement(element, view);
                const intro = view.getIntroItem();
                view.ruleDetail = intro.getComponent(ShareIntroControl_1.default);
                view.ruleWindow.addChild(intro.pos(90, 344));
                if (Laya.LocalStorage.getItem(GameConstant_1.default.LOCALSTORAGEKEY.FIRSTOPENSHARE) == '') {
                    Laya.LocalStorage.setItem(GameConstant_1.default.LOCALSTORAGEKEY.FIRSTOPENSHARE, "1");
                    view.ruleWindow.visible = true;
                }
                break;
            case 'shareRuleBg':
                view.ruleBg = element;
                view.ruleBg.on(Laya.Event.CLICK, this, () => {
                    if (view.ruleDetail) {
                        view.ruleDetail.closeDetail();
                    }
                });
                break;
            case 'btnCloseRule':
                view.btnCloseRule = element.getComponent(ExtBaseButton_1.default);
                view.btnCloseRule.setCallback(() => {
                    if (view.ruleWindow) {
                        view.ruleWindow.visible = false;
                    }
                });
                break;
            case 'redPackTotal':
                view.toalaRedPackLabel = element;
                break;
            case 'btnCloseShare':
                view.btnCloseShare = element.getComponent(ExtBaseButton_1.default);
                view.btnCloseShare.setCallback(() => {
                    // view.setShow(false)
                    view.GC.status.closeShare();
                });
                break;
            case 'NoRedPackGet':
                view.noPrizeLabel = element;
                view.noPrizeLabel.visible = false;
                break;
        }
    }
    showRule(flag = true) {
        // this.ruleBg.visible = flag
        this.ruleWindow.visible = flag;
    }
    onFilterChildrenElement(element, view) {
        for (let index = 0; index < element.numChildren; index++) {
            const el = element.getChildAt(index);
            view.onFilteElement(el, view);
        }
    }
    onItemHolderDrage() {
        this.prizeItemHolderDragLength += Math.abs(this.prizeItemHolder.y - this.prizeItemHolderDragStartPosY);
        this.prizeItemHolderDragStartPosY = this.prizeItemHolder.y;
    }
    getPrizeItem() {
        return Laya.Pool.getItemByCreateFun('ShareRedPackPrizeItem', this.prizeItem.create, this.prizeItem);
    }
    getIntroItem() {
        return Laya.Pool.getItemByCreateFun('ShareRedPackRuleDetail', this.introItem.create, this.introItem);
    }
    setList(list) {
        // uid	string	用户id	
        // nick	string	昵称	
        // proxyLv	int	代理等级	0
        // redPack	int	红包(奖励)	0
        this.prizeItemRealList.forEach(element => {
            element.setShow(false);
            Laya.Pool.recover('ShareRedPackPrizeItem', element.self);
        });
        let total = 0;
        this.prizeItemHolder.y = 0;
        this.prizeItemHolder.height = 0;
        this.prizeItemInsertY = 0;
        for (let index = 0; index < list.length; index++) {
            const element = list[index];
            const sp = this.getPrizeItem();
            const control = sp.getComponent(ShareRedPackPrizeItemControl_1.default);
            this.prizeItemHolder.addChild(sp.pos(0, this.prizeItemInsertY));
            this.prizeItemInsertY += this.prizeitemSingleHeight;
            this.prizeItemHolder.height = this.prizeItemInsertY + 10;
            control.setShow(true);
            control.setInfo(element);
            this.prizeItemRealList.push(control);
            total += element.redPack;
        }
        this.toalaRedPackLabel.value = (`${total}`);
        this.noPrizeLabel.visible = list.length == 0;
    }
}
exports.default = ShareRedPackPrizeControl;
},{"../Control/GameCenter":3,"../GameConstant":10,"../extends/ExtBaseButton":61,"../utils/Tarsis":66,"./ShareIntroControl":48,"./ShareRedPackPrizeItemControl":50}],50:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-12-12 10:36:38
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-12-12 11:31:31
 */
Object.defineProperty(exports, "__esModule", { value: true });
const Tarsis_1 = require("../utils/Tarsis");
class ShareRedPackPrizeItemControl extends Tarsis_1.ViewControl {
    onEnable() {
        super.onEnable();
        this.filtAllChildren(this.onFilteElement);
    }
    onFilteElement(element, view) {
        switch (element.name) {
            case 'LvLabel':
                view.lvLabel = element;
                break;
            case 'NameLabel':
                view.nameLabel = element;
                break;
            case 'RewardLabel':
                view.rewardLabel = element;
                break;
        }
    }
    setInfo(info) {
        // uid	string	用户id	
        // nick	string	昵称	
        // proxyLv	int	代理等级	0
        // redPack	int	红包(奖励)	0
        this.nameLabel.changeText(info.nick.length > 8 ? `${info.nick.substr(0, 6)}...` : `${info.nick}`);
        this.rewardLabel.changeText(`${info.redPack}`);
        this.lvLabel.changeText(`Lv${info.proxyLv}`);
    }
}
exports.default = ShareRedPackPrizeItemControl;
},{"../utils/Tarsis":66}],51:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-28 15:59:58
 * @Last Modified by: ZZL
 * @Last Modified time: 2019-11-01 16:26:59
 */
Object.defineProperty(exports, "__esModule", { value: true });
const BatteryInfo_1 = require("../extends/BatteryInfo");
const GameCenter_1 = require("../Control/GameCenter");
const GameConstant_1 = require("../GameConstant");
const Tarsis_1 = require("../utils/Tarsis");
var Vector2 = Laya.Vector2;
class ShipControl extends Laya.View {
    constructor() {
        super();
        this.batteryList = [];
        this.isInit = false;
        this.nowBattery = null;
        this.nowBatteryID = '-1';
    }
    onEnable() {
        this.GC = GameCenter_1.default.instance;
        if (!this.isInit) {
            this.init(GameConstant_1.default.GAMECOMPONENT.USERSHIP, () => {
                Laya.timer.frameLoop(5, this, this._update);
            });
        }
    }
    onDisable() {
        Laya.timer.clearAll(this._update);
    }
    init(type, regCallback) {
        this._children.forEach(element => {
            const sprite = element;
            const info = sprite.getComponent(BatteryInfo_1.default);
            if (info) {
                this.batteryList[info.batteryId] = sprite;
                if (sprite.visible) {
                    this.nowBattery = sprite;
                }
            }
        });
        this.isInit = true;
        this.GC.registComponent(type, this, regCallback);
    }
    _update() {
        if (this.GC && this.GC.status.isUserServerLoginDone) {
            if (this.GC.nowUser.curBatteryid != this.nowBatteryID) {
                this.nowBatteryID = this.GC.nowUser.curBatteryid;
                this.setBattery(this.nowBatteryID);
                this.GC.userInfoZone.setBattery();
            }
        }
    }
    setBattery(batteryId) {
        if (this.nowBattery.batteryInfo.batteryId != batteryId && this.batteryList[batteryId]) {
            this.hideAllBattery();
            this.batteryList[batteryId].visible = true;
            this.nowBattery = this.batteryList[batteryId];
        }
    }
    hideAllBattery() {
        Object.keys(this.batteryList).forEach(key => {
            this.batteryList[key].visible = false;
        });
    }
    fireOnce(bulletId) {
        this.nowBattery.fireOnce(bulletId);
    }
    rotate(x, y) {
        this.nowBattery.rotation = this.getGunAngle(x, y);
    }
    getGunAngle(x, y) {
        let pos = this.localToGlobal(new Laya.Point(this.pivotX, this.pivotY));
        let from = new Vector2(0, -1);
        let to = new Laya.Vector2(x - pos.x, y - pos.y);
        let angle = Tarsis_1.default.Vector2Angle(from, to);
        angle = Math.max(Math.min(angle, 90), 0);
        return x < pos.x ? -angle : angle;
    }
}
exports.default = ShipControl;
},{"../Control/GameCenter":3,"../GameConstant":10,"../extends/BatteryInfo":60,"../utils/Tarsis":66}],52:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-30 14:46:43
 * @Last Modified by: ZZL
 * @Last Modified time: 2019-12-25 18:38:17
 */
Object.defineProperty(exports, "__esModule", { value: true });
const GameConstant_1 = require("../GameConstant");
const ExtBaseButton_1 = require("../extends/ExtBaseButton");
const GameCenter_1 = require("../Control/GameCenter");
const ShopItemControl_1 = require("../shop/ShopItemControl");
const GameSettings_1 = require("../GameSettings");
const VipPrizeItemControl_1 = require("../shop/VipPrizeItemControl");
class ShopControl extends Laya.Script {
    constructor() {
        super(...arguments);
        /**
         * 当前商城类型
         * 设置Tab
         * 参考值：GameConstant.SHOPTYPE
         */
        this.nowShopType = 0;
        this.isShowing = false;
        this.shopItemList = [];
        this.itemPosList = [
            { x: 0, y: 10 },
            { x: 480, y: 10 },
            { x: 0, y: 390 },
            { x: 480, y: 390 },
            { x: 0, y: 770 },
            { x: 480, y: 770 },
        ];
        this.vipPrizeItemPosList4 = [
            { x: 150, y: 750 },
            { x: 372, y: 750 },
            { x: 593, y: 750 },
            { x: 815, y: 750 }
        ];
        this.vipPrizeItemPosList3 = [
            { x: 200, y: 750 },
            { x: 475, y: 750 },
            { x: 750, y: 750 }
        ];
        this.vipPrizeItemList = [];
        this.nowShowingVip = 0;
    }
    onEnable() {
        this.GC = GameCenter_1.default.instance;
        this.self = this.owner;
        this.vipContent = this.self['vipZone'];
        this.coinContent = this.self['coinZone'];
        this.tabCoin = this.self['coinBtn'].getComponent(ExtBaseButton_1.default);
        this.tabCoin.setLabelText('金币');
        this.tabCoin.setLabelOffset(0, 20);
        this.tabCoin.setCallback(() => {
            // this.GC.status.setShop(GameConstant.SHOPTYPE.COIN)
            this.callbackAction.runWith([GameConstant_1.default.USERACTIONTYPE.CHANGESHOPTYPE, GameConstant_1.default.SHOPTYPE.COIN]);
        });
        this.tabVip = this.self['vipBtn'].getComponent(ExtBaseButton_1.default);
        this.tabVip.setLabelText('VIP');
        this.tabVip.setLabelOffset(0, 20);
        this.tabVip.setCallback(() => {
            // this.GC.status.setShop(GameConstant.SHOPTYPE.VIP)
            this.callbackAction.runWith([GameConstant_1.default.USERACTIONTYPE.CHANGESHOPTYPE, GameConstant_1.default.SHOPTYPE.VIP]);
        });
        this.tabDiamond = this.self['diamondBtn'].getComponent(ExtBaseButton_1.default);
        this.tabDiamond.setLabelText('钻石');
        this.tabDiamond.setLabelOffset(0, 20);
        this.tabDiamond.setCallback(() => {
            // this.GC.status.setShop(GameConstant.SHOPTYPE.DIAMOND)
            this.callbackAction.runWith([GameConstant_1.default.USERACTIONTYPE.CHANGESHOPTYPE, GameConstant_1.default.SHOPTYPE.DIAMOND]);
        });
        this.tabs = [this.tabCoin, this.tabVip, this.tabDiamond];
        this.closeBtn = this.self['close'].getComponent(ExtBaseButton_1.default);
        this.closeBtn.setCallback(() => {
            // this.GC.status.closeShop()
            this.callbackAction.runWith(GameConstant_1.default.USERACTIONTYPE.CLOSESHOP);
        });
        this.userVipNowVipTop = this.self['nowVipTop'];
        this.userVipNowVipBenfitA = this.self['vipBeniftA'];
        this.userVipNowVipBenfitB = this.self['vipBeniftB'];
        this.userVipNextVipBtn = this.self['nextVipLevel'].getComponent(ExtBaseButton_1.default);
        this.userVipNextVipBtn.setCallback(() => {
            this.setNextVip();
        });
        this.userVipPrevVipBtn = this.self['prevVipLevel'].getComponent(ExtBaseButton_1.default);
        this.userVipPrevVipBtn.setCallback(() => {
            this.setPrevVip();
        });
        this.userVipRecBtn = this.self['recVipPrize'].getComponent(ExtBaseButton_1.default);
        this.userVipRecBtn.setLabelText('领取礼包');
        this.userVipRecBtn.setLabelFilter([new Laya.GlowFilter('#cef800', 3, 0, 3)]);
        this.userVipRecBtn.toggleDiable(true);
        this.userVipRecBtn.setCallback(() => {
            this.userVipRecBtn.toggleFrozen(true);
            this.callbackAction.runWith(GameConstant_1.default.USERACTIONTYPE.USERVIPREC);
        });
        this.userVipGiftGot = this.self['gotVipPrize'];
        this.userVipGiftGot.visible = false;
        this.userVipNeedCharge = this.self['needCharge'];
        this.userVipNeedChargeText = this.self['needChargeText'];
        this.userVipNowVipBottom = this.self['nowVipBottom'];
        this.userVipNowVipNext = this.self['nowVipNext'];
        this.userVipProgress = this.self['nowVipProgrees'];
        this.userVipProgressDitail = this.self['nowVipProgressDetail'];
        this.userVipFullText = this.self['vipFullText'];
        this.iosNotSupport = this.self['notIosPayLabel'];
        this.iosNotSupport1 = this.self['notIosPayLabel1'];
        this.iosNotSupport.visible = false;
        this.iosNotSupport1.visible = false;
        this.iosNotSupport.text = GameSettings_1.default.IOSshopLabel[0];
        if (GameSettings_1.default.IOSshopLabel.length > 1) {
            this.iosNotSupport1.text = GameSettings_1.default.IOSshopLabel[1];
        }
        this.bottomInfo = this.self['bottomText'];
        this.bottomInfo.text = GameConstant_1.default.PROMOTIONTEXT.PUBLICACCOUNT.replace('$pa$', GameSettings_1.default.wechatPublicAccount);
        this.bottomInfo1 = this.self['bottomText1'];
        this.bottomInfo1.text = GameConstant_1.default.PROMOTIONTEXT.CUSTOMQQ.replace('$qq$', GameSettings_1.default.customQQ);
        // this.bottomInfo.filters = [new Laya.GlowFilter('#104e6f',2,1,1)]
        // this.bottomInfo.editable = false
        for (let i = 0; i < 4; i++) {
            let item = Laya.Pool.getItemByCreateFun('VipPrizeItem', this.vipPrizeItem.create, this.vipPrizeItem);
            let ic = item.getComponent(VipPrizeItemControl_1.default);
            this.vipPrizeItemList.push(ic);
            this.vipContent.addChild(item.pos(this.vipPrizeItemPosList4[i].x, this.vipPrizeItemPosList4[i].y));
        }
        let coinInfo = [];
        GameSettings_1.default.coinGoods.forEach((element) => {
            coinInfo[element.id] = element;
        });
        for (let i = 0; i < 6; i++) {
            let item = Laya.Pool.getItemByCreateFun('ShopItem', this.shopItem.create, this.shopItem);
            let ic = item.getComponent(ShopItemControl_1.default);
            this.coinContent.addChild(item.pos(this.itemPosList[i].x, this.itemPosList[i].y));
            ic.setCallback((info) => {
                if (this.callbackAction) {
                    this.callbackAction.runWith([GameConstant_1.default.USERACTIONTYPE.SHOPPURCH, info]);
                }
            });
            this.shopItemList.push(ic);
        }
        this.shopTip = this.self['ShopTip'];
        this.shopTip.visible = false;
        this.self['shopTipTouch'].on(Laya.Event.CLICK, this, () => {
            this.shopTip.visible = false;
        });
        this.setSelfVip();
        this.nowShowingVip = this.selfVip == 0 ? 1 : this.selfVip;
        this.setShowVip();
        this.setShop(false);
        this.GC.registComponent(GameConstant_1.default.GAMECOMPONENT.SHOP, this, (callback) => {
            this.callbackAction = callback;
        });
    }
    onUpdate() {
        if (this.isShowing != this.GC.status.isOnShop) {
            this.nowShopType = this.GC.status.nowShopType;
            this.setShop(this.GC.status.isOnShop);
        }
        if (this.isShowing && this.nowShopType != this.GC.status.nowShopType) {
            this.nowShopType = this.GC.status.nowShopType;
            this.setTab();
        }
        if (this.isShowing &&
            (this.selfVip != this.GC.nowUser.vip
                || this.selfMinVipRec != this.GC.nowUser.minVipRec
                || this.selfSumRecharge != this.GC.nowUser.sumRecharge)) {
            this.setSelfVip();
            // if(this.nowShopType == GameConstant.SHOPTYPE.VIP){
            //     this.setShowVip()
            // }
            this.setShowVip();
        }
    }
    setShop(flag) {
        this.isShowing = flag;
        this.self.visible = flag;
        this.setTab();
    }
    setTab() {
        this.tabs.forEach((element) => {
            element.toggleChcek(false);
        });
        this.tabs[this.nowShopType].toggleChcek(true);
        if (GameSettings_1.default.isTest) {
            if (Laya.Browser.onIOS) {
                this.self['allTabHolder'].visible = false;
            }
            else {
                this.self['allTabHolder'].visible = true;
            }
        }
        else {
            this.self['allTabHolder'].visible = !GameSettings_1.default.isTest;
        }
        if (this.nowShopType == 1) {
            if (!GameSettings_1.default.isTest) {
                this.vipContent.visible = true;
                this.iosNotSupport.visible = false;
                this.iosNotSupport1.visible = false;
            }
            else {
                if (Laya.Browser.onIOS) {
                    this.vipContent.visible = false;
                    this.iosNotSupport.visible = true;
                    //this.iosNotSupport1.visible = true
                }
                else {
                    this.vipContent.visible = true;
                }
            }
        }
        else {
            this.vipContent.visible = false;
        }
        this.coinContent.visible = this.nowShopType != 1;
        let infoList = null;
        if (this.nowShopType != 1) {
            infoList = this.nowShopType == 0 ? GameSettings_1.default.coinGoods : GameSettings_1.default.diamondGoods;
            for (let i = 0; i < 6; i++) {
                this.shopItemList[i].setInfo(infoList[i], this.nowShopType == 0 ? GameConstant_1.default.SHOPGOODSTYPE.COIN : GameConstant_1.default.SHOPGOODSTYPE.DIAMOND);
                let isShowing = true;
                if (this.nowShopType == 0) {
                    this.shopTip.visible = true;
                }
                else if (this.nowShopType == 2) {
                    if (Laya.Browser.onIOS) {
                        isShowing = false;
                    }
                    else {
                    }
                    if (GameSettings_1.default.isTest) {
                        this.shopTip.visible = false;
                    }
                    else {
                        this.shopTip.visible = isShowing;
                    }
                }
                this.shopItemList[i].setVisible(isShowing);
                this.iosNotSupport.visible = !isShowing;
                if (GameSettings_1.default.IOSshopLabel.length > 1) {
                    this.iosNotSupport1.visible = !isShowing;
                }
            }
        }
        else {
            this.shopTip.visible = false;
        }
    }
    setNextVip() {
        this.nowShowingVip = this.nowShowingVip < 9 ? this.nowShowingVip + 1 : this.nowShowingVip;
        this.setShowVip();
    }
    setPrevVip() {
        this.nowShowingVip = this.nowShowingVip > 1 ? this.nowShowingVip - 1 : 1;
        this.setShowVip();
    }
    getVipRecStatus() {
        if (this.nowShowingVip > this.selfVip) {
            return -1; //不能领
        }
        else if (this.nowShowingVip <= this.selfMinVipRec) {
            return -2; //领过了
        }
        else {
            return 0; //可以领
        }
    }
    setShowVip() {
        const vip = this.nowShowingVip;
        const info = this.getVipInfo(vip);
        this.userVipNowVipTop.skin = this.getVipImage(vip);
        this.userVipNowVipBenfitA.text = `${info.benfit[0]}`;
        this.userVipNowVipBenfitB.text = `${info.benfit[1]}`;
        const count = info.prize.length;
        if (count == 3) {
            for (let i = 0; i < 3; i++) {
                this.vipPrizeItemList[i].owner.pos(this.vipPrizeItemPosList3[i].x, this.vipPrizeItemPosList3[i].y);
                this.vipPrizeItemList[i].setInfo(info.prize[i]);
            }
            this.vipPrizeItemList[3].owner.visible = false;
        }
        else {
            for (let i = 0; i < 4; i++) {
                this.vipPrizeItemList[i].owner.pos(this.vipPrizeItemPosList4[i].x, this.vipPrizeItemPosList4[i].y);
                this.vipPrizeItemList[i].setInfo(info.prize[i]);
            }
            this.vipPrizeItemList[3].owner.visible = true;
        }
        const state = this.getVipRecStatus();
        this.userVipGiftGot.visible = false;
        this.userVipRecBtn.owner.visible = true;
        this.userVipRecBtn.toggleDiable(false);
        this.userVipRecBtn.toggleFrozen(false);
        switch (state) {
            case -1:
                this.userVipRecBtn.toggleDiable(true);
                break;
            case -2:
                this.userVipRecBtn.owner.visible = false;
                this.userVipGiftGot.visible = true;
                break;
        }
    }
    setSelfVip() {
        this.selfVip = this.GC.nowUser.vip;
        this.selfSumRecharge = this.GC.nowUser.sumRecharge;
        this.selfMinVipRec = this.GC.nowUser.minVipRec;
        this.userVipNowVipBottom.skin = this.getVipImage(this.selfVip);
        this.userVipNowVipNext.visible = this.selfVip < GameSettings_1.default.maxVip;
        this.userVipNowVipNext.skin = this.selfVip < GameSettings_1.default.maxVip ? this.getVipImage(this.selfVip + 1) : this.getVipImage(this.selfVip);
        this.selfVipInfo = this.getVipInfo(this.selfVip < GameSettings_1.default.maxVip ? this.selfVip + 1 : this.selfVip);
        this.userVipNeedCharge.value = `${this.selfVipInfo.value - this.selfSumRecharge}`;
        this.userVipProgress.value = this.selfSumRecharge / this.selfVipInfo.value;
        this.userVipProgressDitail.value = `${this.selfSumRecharge}/${this.selfVipInfo.value}`;
        this.userVipFullText.visible = this.selfVip >= GameSettings_1.default.maxVip;
        this.userVipProgressDitail.visible = this.selfVip < GameSettings_1.default.maxVip;
        this.userVipNeedCharge.visible = this.selfVip < GameSettings_1.default.maxVip;
        this.userVipNeedChargeText.visible = this.selfVip < GameSettings_1.default.maxVip;
    }
    getVipImage(vip) {
        return `uibase/textVip_${vip}.png`;
    }
    getVipInfo(vip) {
        let info = null;
        GameSettings_1.default.vipInfo.forEach((element) => {
            if (element.id == vip) {
                info = element;
            }
        });
        return info;
    }
}
exports.default = ShopControl;
},{"../Control/GameCenter":3,"../GameConstant":10,"../GameSettings":11,"../extends/ExtBaseButton":61,"../shop/ShopItemControl":63,"../shop/VipPrizeItemControl":64}],53:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-28 16:00:03
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-06-11 10:54:12
 */
Object.defineProperty(exports, "__esModule", { value: true });
const ExtBaseButton_1 = require("../extends/ExtBaseButton");
const GameCenter_1 = require("../Control/GameCenter");
const GameConstant_1 = require("../GameConstant");
const AudioManager_1 = require("../Control/AudioManager");
class SystemMenuControl extends Laya.View {
    constructor() {
        super();
        this.callback = null;
        this.btnSet = {
            arrow: null,
            music: null,
            sound: null,
            vibr: null,
            auto: null,
            rage: null,
            free: null
        };
        this.btnPos = {
            music: null,
            sound: null,
            vibr: null
        };
        this.btnHiddenX = 700;
        this.btnHiddenY = 0;
        this.isMenuOpen = false;
    }
    onEnable() {
        this.GC = GameCenter_1.default.instance;
        this.audio = AudioManager_1.default.instance;
        this.GC.registComponent(GameConstant_1.default.GAMECOMPONENT.SYSTEMMENU, this, (handler) => {
            this.callback = handler;
        });
        this.btnSet.arrow = this['btnOpen'].getComponent(ExtBaseButton_1.default);
        this.btnSet.music = this['btnMusic'].getComponent(ExtBaseButton_1.default);
        this.btnSet.sound = this['btnSound'].getComponent(ExtBaseButton_1.default);
        this.btnSet.vibr = this['btnShock'].getComponent(ExtBaseButton_1.default);
        this.btnSet.auto = this['btnAuto'].getComponent(ExtBaseButton_1.default);
        this.btnSet.rage = this['btnRage'].getComponent(ExtBaseButton_1.default);
        this.btnSet.free = this['btnPkFree'].getComponent(ExtBaseButton_1.default);
        this.btnPos.music = new Laya.Point(this['btnMusic'].x, this['btnMusic'].y);
        this.btnPos.sound = new Laya.Point(this['btnSound'].x, this['btnSound'].y);
        this.btnPos.vibr = new Laya.Point(this['btnShock'].x, this['btnShock'].y);
        this.btnHiddenY = this['btnOpen'].y;
        this['btnMusic'].pos(this.btnHiddenX, this.btnHiddenY);
        this['btnSound'].pos(this.btnHiddenX, this.btnHiddenY);
        this['btnShock'].pos(this.btnHiddenX, this.btnHiddenY);
        this.btnSet.auto.setCallback(() => {
            if (this.callback && !this.GC.status.isOnMission) {
                this.callback.runWith([GameConstant_1.default.USERACTIONTYPE.SKILLSWITCH, GameConstant_1.default.SKILLSWITCHTYPE.AUTO]);
            }
        });
        this.btnSet.arrow.setCallback(() => {
            this.toggleMenu(!this.isMenuOpen);
        });
        this.btnSet.rage.setAddonItem({
            valueZone: this['addonZone'],
            valueLabel: this['addonValue'],
            cooldownZone: this['coolZone'],
            timeLabel: this['coolLabel'],
            countLabel: this['countNumber'],
            count: 0,
            addonValue: 3,
            duration: 30
        });
        this.btnSet.rage.setCallback(() => {
            if (this.callback && !this.GC.status.isOnMission) {
                this.callback.runWith([GameConstant_1.default.USERACTIONTYPE.SKILLSWITCH, GameConstant_1.default.SKILLSWITCHTYPE.RAGE]);
            }
        }, () => {
            console.log(`Cooldown Completed !`);
            if (this.callback && !this.GC.status.isOnMission) {
                this.callback.runWith([GameConstant_1.default.USERACTIONTYPE.SKILLSWITCH, GameConstant_1.default.SKILLSWITCHTYPE.RAGECOOLDOWN]);
            }
        });
        this.btnSet.music.setCallback(() => {
            if (this.callback && !this.GC.status.isOnMission) {
                this.callback.runWith([GameConstant_1.default.USERACTIONTYPE.MUSIC, this.audio.music]);
            }
        });
        this.btnSet.sound.setCallback(() => {
            if (this.callback && !this.GC.status.isOnMission) {
                this.callback.runWith([GameConstant_1.default.USERACTIONTYPE.SOUND, this.audio.sound]);
            }
        });
        this.btnSet.vibr.setCallback(() => {
            if (this.callback && !this.GC.status.isOnMission) {
                this.callback.runWith([GameConstant_1.default.USERACTIONTYPE.VIBR, this.audio.vibr]);
            }
        });
        Laya.timer.frameLoop(5, this, this._update);
    }
    _update() {
        this.btnSet.auto.toggleChcek(this.GC.fireStatus.auto);
        if (this.btnSet.rage.isChecked != this.GC.fireStatus.rage) {
            this.btnSet.rage.toggleChcek(this.GC.fireStatus.rage);
        }
        if (this.btnSet.music.isChecked == this.audio.music) {
            this.btnSet.music.toggleChcek(!this.audio.music);
        }
        if (this.btnSet.sound.isChecked == this.audio.sound) {
            this.btnSet.sound.toggleChcek(!this.audio.sound);
        }
        if (this.btnSet.vibr.isChecked == this.audio.vibr) {
            this.btnSet.vibr.toggleChcek(!this.audio.vibr);
        }
        this.setRageCount(this.GC.getUserItemCount(GameConstant_1.default.ITEMTYPE.RAGE));
    }
    toggleMenu(show) {
        this.isMenuOpen = show;
        this.btnSet.arrow.toggleFrozen(true);
        Laya.Tween.to(this['btnMusic'], { x: (show ? this.btnPos.music.x : this.btnHiddenX), alpha: (show ? 1 : 0) }, show ? 500 : 1000, show ? Laya.Ease.elasticIn : Laya.Ease.backIn);
        Laya.Tween.to(this['btnSound'], { x: (show ? this.btnPos.sound.x : this.btnHiddenX), alpha: (show ? 1 : 0) }, show ? 500 : 800, show ? Laya.Ease.elasticIn : Laya.Ease.backIn);
        Laya.Tween.to(this['btnShock'], { x: (show ? this.btnPos.vibr.x : this.btnHiddenX), alpha: (show ? 1 : 0) }, show ? 500 : 600, show ? Laya.Ease.elasticIn : Laya.Ease.backIn);
        Laya.timer.once(show ? 500 : 100, this, () => {
            this.btnSet.arrow.toggleFrozen(false);
            this.btnSet.arrow.toggleChcek(show);
        });
    }
    setRageCount(count) {
        this.btnSet.rage.setCount(count);
    }
    setBtnVisible(type, visible) {
        switch (type) {
            case GameConstant_1.default.SKILLSWITCHTYPE.AUTO:
                this['btnRage'].visible = visible;
                break;
            case GameConstant_1.default.SKILLSWITCHTYPE.RAGE:
                this['btnRage'].visible = visible;
                break;
            case GameConstant_1.default.SKILLSWITCHTYPE.PKFREE:
                this['btnPkFree'].visible = visible;
                break;
        }
    }
    getDropTarget(type) {
        let point = null;
        switch (type) {
            case GameConstant_1.default.ITEMTYPE.RAGE:
                point = new Laya.Point(this['btnRage'].x, this['btnRage'].y);
                break;
        }
        if (point) {
            point = this.localToGlobal(point);
        }
        return point;
    }
}
exports.default = SystemMenuControl;
},{"../Control/AudioManager":1,"../Control/GameCenter":3,"../GameConstant":10,"../extends/ExtBaseButton":61}],54:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-06-19 10:48:45
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-06-19 10:49:47
 */
Object.defineProperty(exports, "__esModule", { value: true });
const GameSettings_1 = require("../GameSettings");
class TestScene extends Laya.Scene {
    constructor() {
        super();
    }
    onEnable() {
        GameSettings_1.default.editorTestViewList.forEach((element) => {
            Laya.View.open(element, false, null, Laya.Handler.create(this, (s) => { }));
        });
    }
}
exports.default = TestScene;
},{"../GameSettings":11}],55:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-28 16:00:08
 * @Last Modified by:   Odie Robin
 * @Last Modified time: 2019-05-28 16:00:08
 */
Object.defineProperty(exports, "__esModule", { value: true });
const GameConstant_1 = require("../GameConstant");
const GameCenter_1 = require("../Control/GameCenter");
var Vector2 = Laya.Vector2;
class TouchControl extends Laya.Script {
    constructor() {
        super();
        this.isPress = false;
        this.pressDuration = 0;
        this.pressTimeTolerate = 300;
        this.target = new Laya.Vector2(Laya.stage.width / 2, Laya.stage.height / 2);
        this.weaponCooldowned = true;
        this.isOn = false;
        this.isOnLock = false;
    }
    onEnable() {
        this.GC = GameCenter_1.default.instance;
        this.GC.registComponent(GameConstant_1.default.GAMECOMPONENT.TOUCH, this, (fireStatus, handler) => {
            this.fireStatus = fireStatus;
            this.callbackAction = handler;
            this.isOn = true;
        });
        const sp = this.owner;
        sp.size(Laya.stage.width, Laya.stage.height);
    }
    onUpdate() {
        if (this.isOn) {
            if (this.fireStatus.auto) {
                this._rotate();
                this._fire();
            }
            else {
                if (this.isPress) {
                    this._rotate();
                    this.pressDuration += Laya.timer.delta;
                    if (this.pressDuration >= this.pressTimeTolerate) {
                        this._fire();
                    }
                }
            }
        }
    }
    _rotate() {
        if (this.callbackAction) {
            this.callbackAction.runWith([GameConstant_1.default.TOUCHACTIONTYPE.ROTATE, { x: this.target.x, y: this.target.y }]);
        }
    }
    _fire() {
        if (this.weaponCooldowned) {
            this._rotate();
            if (this.callbackAction) {
                // this.callbackAction(GameConstant.TOUCHACTIONTYPE.FIRE)
                this.callbackAction.runWith([GameConstant_1.default.TOUCHACTIONTYPE.FIRE]);
            }
            this.weaponCooldowned = false;
            Laya.timer.once(1000 / (this.fireStatus ? this.fireStatus.rate : 4), this, () => {
                this.weaponCooldowned = true;
            });
        }
    }
    onMouseUp(e) {
        if (this.isOn) {
            if (this.isPress) {
                this.isPress = false;
                this.pressDuration = 0;
                this._fire();
            }
        }
    }
    onMouseDown() {
        if (this.isOn) {
            if (this.isOnLock) {
                console.log("Try Lock Fish");
                // let fish = this.detectOnLockFish()
                // if(fish){
                //     this.store.onUserLockFish(fish)
                // }else{
                //     this.onMousePress()
                // }
            }
            else {
                this.onMousePress();
            }
        }
    }
    onMouseMove(e) {
        if (this.isOn) {
            if (this.isPress) {
                this.target = new Vector2(Laya.MouseManager.instance.mouseX, Laya.MouseManager.instance.mouseY);
            }
        }
    }
    onMouseOut(e) {
        if (this.isPress) {
            this.isPress = false;
            this.pressDuration = 0;
        }
    }
    onMousePress() {
        this.isPress = true;
        this.pressDuration = 0;
        this.target = new Vector2(Laya.MouseManager.instance.mouseX, Laya.MouseManager.instance.mouseY);
    }
}
exports.default = TouchControl;
},{"../Control/GameCenter":3,"../GameConstant":10}],56:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-28 16:00:14
 * @Last Modified by: ZZL
 * @Last Modified time: 2019-12-19 11:00:13
 */
Object.defineProperty(exports, "__esModule", { value: true });
const ExtBaseButton_1 = require("../extends/ExtBaseButton");
const GameCenter_1 = require("../Control/GameCenter");
const GameConstant_1 = require("../GameConstant");
const GameSettings_1 = require("../GameSettings");
class UserInfoZone extends Laya.View {
    constructor() {
        super();
        this.isOnSlectBattery = false;
        this.isOnFreeBattery = false;
        this.redpackCount = 0;
        this.missionBtnStatus = 0; //0 : 倍率1 1 : 倍率1.2
        this.isSharkingMissionBtn = false;
        this.aquaManRank = -2;
        this.labelSet = {
            redpack: null,
            coin: null,
            diamond: null,
            gunValue: null,
            level: null,
            hp: null
        };
        this.GC = GameCenter_1.default.instance;
        this.GC.userInfoZone = this;
    }
    onEnable() {
        this.GC.registComponent(GameConstant_1.default.GAMECOMPONENT.USERINFO, this, (handler) => {
            this.callbackAction = handler;
        });
        this.redpackCount = this.GC.nowUser.redPacketCnt;
        Laya.View.open('view/Ship.scene', false, null, Laya.Handler.create(this, (s) => {
            this.ship = s;
            const pos = this["batteryPosition"];
            pos.addChild(this.ship);
            this.ship.pos(0, 0);
        }));
        this['btnCoin'].getComponent(ExtBaseButton_1.default).setCallback(() => {
            if (!this.GC.status.isOnMission) {
                this.callbackAction.runWith(GameConstant_1.default.USERACTIONTYPE.USERINFOCOIN);
            }
        });
        this['btnCoinAlt'].on(Laya.Event.CLICK, this, () => {
            if (!this.GC.status.isOnMission) {
                this.callbackAction.runWith(GameConstant_1.default.USERACTIONTYPE.USERINFOCOIN);
            }
        });
        this['btnDiamond'].getComponent(ExtBaseButton_1.default).setCallback(() => {
            if (!this.GC.status.isOnMission) {
                this.callbackAction.runWith(GameConstant_1.default.USERACTIONTYPE.USERINFODIAMOND);
            }
        });
        this['btnDiamondAlt'].on(Laya.Event.CLICK, this, () => {
            if (!this.GC.status.isOnMission) {
                this.callbackAction.runWith(GameConstant_1.default.USERACTIONTYPE.USERINFODIAMOND);
            }
        });
        this['btnAquaMan'].getComponent(ExtBaseButton_1.default).setCallback(() => {
            if (GameSettings_1.default.isAquamanRankOpen) {
                this.callbackAction.runWith(GameConstant_1.default.USERACTIONTYPE.AQUAMANRANK);
            }
        });
        this['btnShare'].visible = GameSettings_1.default.isShareNewOpen;
        this['btnShare'].getComponent(ExtBaseButton_1.default).setCallback(() => {
            if (GameSettings_1.default.isShareNewOpen) {
                this.callbackAction.runWith(GameConstant_1.default.USERACTIONTYPE.OPENSHARENEW);
            }
        });
        this['btnGetReward'].visible = false;
        this['btnGetReward'].getComponent(ExtBaseButton_1.default).setCallback(() => {
            this.callbackAction.runWith(GameConstant_1.default.USERACTIONTYPE.USERINFOVIP);
        });
        const gunValueMinusBtn = this['btnGunValueMinus'].getComponent(ExtBaseButton_1.default);
        gunValueMinusBtn.setCallback(() => {
            if (!this.GC.status.isOnMission) {
                this.callbackAction.runWith(GameConstant_1.default.USERACTIONTYPE.GUNVALUEMINUS);
                gunValueMinusBtn.toggleFrozen(true);
                Laya.timer.once(GameSettings_1.default.durationList.btnPublicCD, this, () => {
                    gunValueMinusBtn.toggleFrozen(false);
                });
            }
        });
        const gunValuePlusBtn = this['btnGunValuePlus'].getComponent(ExtBaseButton_1.default);
        gunValuePlusBtn.setCallback(() => {
            if (!this.GC.status.isOnMission) {
                this.callbackAction.runWith(GameConstant_1.default.USERACTIONTYPE.GUNVALUEPLUS);
                gunValuePlusBtn.toggleFrozen(true);
                Laya.timer.once(GameSettings_1.default.durationList.btnPublicCD, this, () => {
                    gunValuePlusBtn.toggleFrozen(false);
                });
            }
        });
        this['btnRedPack'].getComponent(ExtBaseButton_1.default).setCallback(() => {
            if (!this.GC.status.isOnMission && !this.GC.status.isOnMission) {
                this.callbackAction.runWith(GameConstant_1.default.USERACTIONTYPE.USERINFOREDPACK);
            }
        });
        this['btnMission'].visible = GameSettings_1.default.isMissionOpen;
        if (GameSettings_1.default.isMissionOpen) {
            this['btnMission'].getComponent(ExtBaseButton_1.default).setCallback(() => {
                if (!this.GC.status.isOnMission) {
                    this.callbackAction.runWith(GameConstant_1.default.USERACTIONTYPE.MISSON);
                }
            });
        }
        else {
            this['btnMission'].visible = false;
        }
        for (let i = 0; i < 5; i++) {
            this[`switchGun0${i + 1}`].getComponent(ExtBaseButton_1.default).setCallback(() => {
                this.callbackAction.runWith([GameConstant_1.default.USERACTIONTYPE.SWITCHBATTERY, i + 1]);
                if (this.isOnFreeBattery && `${i + 1}` == this.nowFreeBattery) {
                    this.isOnFreeBattery = false;
                }
                this.isOnSlectBattery = false;
                this.closeSwitchBattery();
            });
            this[`switchGun0${i + 1}`].visible = false;
        }
        this.switchBatteryBtn = this['shipBtn'];
        this.switchBatteryBtn.on(Laya.Event.CLICK, this, () => {
            if (!this.GC.status.isOnMission) {
                if (!this.isOnSlectBattery) {
                    this.isOnSlectBattery = true;
                    this.openSwitchBattery();
                }
            }
        });
        this.switchBatteryCloseBtn = this['shipCloseBtn'];
        this.switchBatteryCloseBtn.on(Laya.Event.CLICK, this, () => {
            if (this.isOnSlectBattery) {
                this.isOnSlectBattery = false;
                this.closeSwitchBattery();
            }
        });
        this['shipCloseBtn'].visible = false;
        this['freeBattery'].visible = false;
        this['freeBatteryTimerZone'].visible = false;
        this.labelSet.redpack = this["redpackLabel"];
        this.labelSet.coin = this["coinLabel"];
        this.labelSet.diamond = this["diamondLabel"];
        this.labelSet.gunValue = this["gunValueLabel"];
        this.labelSet.level = this["lvValue"];
        this.labelSet.hp = this["hpLabel"];
        this.gunDiamondEffect = this['diamondGunEffect'];
        this.gunDiamondEffect.visible = false;
        this.gunActiveEffect = this['activeGunEffect'];
        this.gunActiveEffect.visible = false;
        if (GameSettings_1.default.isAquamanRankOpen) {
            this.setAquaManRank(this.aquaManRank);
        }
        Laya.timer.frameLoop(5, this, this._update);
    }
    _update() {
        if (this.GC && this.GC.status.isUserServerLoginDone) {
            const userInfo = this.GC.nowUser;
            this.setCoin(userInfo.coin);
            this.setDiamond(userInfo.diamond);
            this.setLevel(userInfo.lv);
            if (this.setGunValue(userInfo.curBatteryLv)) {
                this.gunActiveEffect.visible = true;
                this.gunActiveEffect.play(0, false);
            }
            if (userInfo.redPacketCnt > this.redpackCount) {
            }
            this.setRedpack(userInfo.redPacketCnt);
            this.redpackCount = userInfo.redPacketCnt;
            this.gunDiamondEffect.visible = this.GC.fireStatus.rage;
            if (this.isOnSlectBattery) {
                this.setSwitchNowBattery();
            }
            if (this.isOnFreeBattery && this.GC.nowUser.curBatteryid == this.nowFreeBattery) {
                this.cancelFreeBattery();
            }
        }
        if (this.GC && this.GC.status && this.GC.mission && this.GC.mission.MissionData) {
            if (!this.GC.mission.visible && !this.GC.status.isOnMission && (this.GC.mission.MissionData.mainState == 2 || this.GC.mission.MissionData.mainState == 5)) {
                this.shakeMissionBtn();
            }
            else {
                this["btnMission"].scaleX = 1;
                this["btnMission"].scaleY = 1;
            }
        }
        if (this.GC && this.GC.nowUser) {
            this['btnGetReward'].visible = this.GC.isUserHasVipPrize();
        }
    }
    setBattery() {
        this.gunActiveEffect.visible = true;
        this.gunActiveEffect.play(0, false);
    }
    openSwitchBattery() {
        this['shipCloseBtn'].visible = true;
        this.setSwitchNowBattery();
        this['eventZone'].visible = false;
        if (this.isOnFreeBattery) {
            this['freeBattery'].visible = false;
        }
    }
    setMission(data, mission) {
        if (data.mainState == 1 && data.miState == 1) {
            this['btnMission'].skin = GameSettings_1.default.MISSIONBTNPATH[mission.miType];
            this['missionPrize'].value = (parseInt(GameSettings_1.default.missionPrize)); ///10000 + '万'
            this['missionImg'].visible = true;
            this['missionTextBg'].visible = true;
            this['missionText'].value = data.progress + '/' + mission.max;
        }
        else {
            this['missionPrize'].value = (parseInt(GameSettings_1.default.missionPrize));
            this['btnMission'].skin = GameSettings_1.default.MISSIONBTNPATH.Finish;
            this['missionTextBg'].visible = false;
        }
    }
    setSwitchNowBattery() {
        for (let i = 0; i < 5; i++) {
            this[`switchGun0${i + 1}`].visible = true;
            this[`switchGun0${i + 1}`].getComponent(ExtBaseButton_1.default).toggleChcek(this.GC.nowUser.curBatteryid == `${i + 1}`);
            this[`switchGun0${i + 1}`].getComponent(ExtBaseButton_1.default).toggleFrozen(!this.GC.isNowUserHasBattery(i + 1));
            if (i > 0) {
                this[`vipGun0${i + 1}`].visible = !this.GC.isNowUserHasBattery(i + 1);
            }
        }
    }
    closeSwitchBattery() {
        this['shipCloseBtn'].visible = false;
        for (let i = 0; i < 5; i++) {
            this[`switchGun0${i + 1}`].visible = false;
        }
        this['eventZone'].visible = true;
        if (this.isOnFreeBattery) {
            this['freeBattery'].visible = true;
        }
    }
    setFreeBattery(batteyId, duration) {
        this.isOnFreeBattery = true;
        this.nowFreeBattery = `${batteyId}`;
        this['freeBattery'].visible = true;
        const freeBtn = this['freeBattery'].getComponent(ExtBaseButton_1.default);
        freeBtn.setMainSkin(`gun/gun_0${batteyId}.png`);
        freeBtn.setCallback(() => {
            this.callbackAction.runWith([GameConstant_1.default.USERACTIONTYPE.SWITCHBATTERY, batteyId]);
        });
        this['freeDuration'].text = `00:${duration < 10 ? '0' : ''}${duration}`;
        Laya.timer.once(1000, this, this.freeBatteryCountDown, [duration]);
    }
    cancelFreeBattery() {
        this.isOnFreeBattery = false;
    }
    freeBatteryCountDown(duration) {
        if (this.isOnFreeBattery) {
            duration -= 1;
            if (duration <= 0) {
                this['freeBattery'].visible = false;
                this.isOnFreeBattery = false;
            }
            else {
                this['freeDuration'].text = `00:${duration < 10 ? '0' : ''}${duration}`;
                Laya.timer.once(1000, this, this.freeBatteryCountDown, [duration]);
            }
        }
        else {
            this['freeBattery'].visible = false;
        }
    }
    setFreeBatteryEquip(batteryId, duration) {
        // this.isOnFreeBatteryEquiped = true
        this.nowFreeBatteryEquipedId = batteryId;
        Laya.timer.once(1000, this, this.freeBatteryEquipedCountDown, [duration]);
    }
    freeBatteryEquipedCountDown(duration) {
        if (this.GC.status.isOnMission) {
            this['freeBatteryTimerZone'].visible = false;
        }
        else {
            duration -= 1;
            if (duration >= 0) {
                this['freeBatteryTimer'].text = `00:${duration < 10 ? '0' : ''}${duration}`;
                Laya.timer.once(1000, this, this.freeBatteryEquipedCountDown, [duration]);
                this['freeBatteryTimerZone'].visible = this.GC.nowUser.curBatteryid == this.nowFreeBatteryEquipedId;
            }
            else {
                this['freeBatteryTimerZone'].visible = false;
            }
        }
    }
    setLevel(lv) {
        this.labelSet.level.value = `${lv < 10 && lv > 0 ? "0" : ""}${lv}`;
    }
    setCoin(coin) {
        this.labelSet.coin.value = coin >= 10000000 ? `${(coin / 10000).toFixed(0)}万` : coin.toString();
    }
    setDiamond(diamond) {
        this.labelSet.diamond.value = diamond.toString();
    }
    setAquaManRank(rank) {
        this.aquaManRank = rank;
        if (this['aquaManNowRank']) {
            this['aquaManNowRank'].value = rank;
            this['aquaManNowRankHolder'].visible = rank > 0;
            this['aquaManNoList'].visible = rank < 0;
        }
    }
    setGunValue(gunValue) {
        const isDiff = this.labelSet.gunValue.value != gunValue.toString();
        if (isDiff) {
            this.labelSet.gunValue.value = gunValue.toString();
        }
        return isDiff;
    }
    setRedpack(redpack) {
        this.labelSet.redpack.text = redpack;
    }
    setHp(hp) {
        this.labelSet.hp.value = `${hp}`;
    }
    getDropTarget(type) {
        let point = null;
        if (GameConstant_1.default.BATTERYITEMLIST[type]) {
            point = new Laya.Point(this['freeBattery'].x, this['freeBattery'].y);
            point = this.localToGlobal(point);
        }
        else {
            switch (type) {
                case GameConstant_1.default.ITEMTYPE.COIN:
                    point = new Laya.Point(this['btnCoin'].x, this['btnCoin'].y);
                    point = this.localToGlobal(point);
                    break;
                case GameConstant_1.default.ITEMTYPE.REDPACK:
                    point = new Laya.Point(this['btnRedPack'].x, this['btnRedPack'].y);
                    point = this['eventZone'].localToGlobal(point);
                    break;
                case GameConstant_1.default.ITEMTYPE.DIAMOND:
                    point = new Laya.Point(this['btnDiamond'].x, this['btnDiamond'].y);
                    point = this.localToGlobal(point);
                    break;
            }
        }
        return point;
    }
    getRedPacketAnimation() {
        this.scaleBig("btnRedPack");
        Laya.timer.once(200, this, this.scaleSmall, ["btnRedPack"], false);
    }
    shakeMissionBtn() {
        if (!this.isSharkingMissionBtn) {
            this.isSharkingMissionBtn = true;
            if (this.missionBtnStatus == 0) {
                Laya.Tween.to(this["btnMission"], { scaleX: 1, scaleY: 1 }, 200, null, Laya.Handler.create(this, this.checkMissionBtnStatus));
            }
            else {
                Laya.Tween.to(this["btnMission"], { scaleX: 1.2, scaleY: 1.2 }, 200, null, Laya.Handler.create(this, this.checkMissionBtnStatus));
            }
        }
    }
    checkMissionBtnStatus() {
        if (this.missionBtnStatus == 0) {
            this.missionBtnStatus = 1;
        }
        else {
            this.missionBtnStatus = 0;
        }
        this.isSharkingMissionBtn = false;
    }
    scaleSmall(objName) {
        Laya.Tween.to(this[objName], { scaleX: 1, scaleY: 1 }, 200);
    }
    scaleBig(objName) {
        Laya.Tween.to(this[objName], { scaleX: 1.3, scaleY: 1.3 }, 200);
    }
}
exports.default = UserInfoZone;
},{"../Control/GameCenter":3,"../GameConstant":10,"../GameSettings":11,"../extends/ExtBaseButton":61}],57:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-28 16:00:19
 * @Last Modified by: ZZL
 * @Last Modified time: 2019-08-15 18:56:18
 */
Object.defineProperty(exports, "__esModule", { value: true });
const ExtBaseButton_1 = require("../extends/ExtBaseButton");
const GameCenter_1 = require("../Control/GameCenter");
const GameConstant_1 = require("../GameConstant");
const GameSettings_1 = require("../GameSettings");
class UserLoginZone extends Laya.View {
    // private exportJson : any = {}
    onEnable() {
        this.GC = GameCenter_1.default.instance;
        this.btnLogin = this['loginBtn'].getComponent(ExtBaseButton_1.default);
        this.btnLogin.setLabelText(GameSettings_1.default.loginBtnLabel);
        this.btnLogin.setLabelFilter([new Laya.GlowFilter("#ffffff", 0, 2, 2)]);
        this.btnLogin.setCallback(() => {
            if (GameSettings_1.default.isNative) {
                this.GC.status.setLoading(true);
                this.GC.platform.login({
                    success: (res) => {
                        this.GC.serverLogin(res.code, res.nickName, res.avatar, res.openId, res.unionId);
                    },
                    fail: (code) => {
                        let desc = '微信授权失败！';
                        switch (code) {
                            case -1:
                                desc = '微信授权失败！';
                                break;
                            case -2:
                                desc = '微信授权取消！';
                                break;
                            case -1:
                                desc = '微信授权无法继续！';
                                break;
                        }
                        this.GC.status.setAlert({
                            desc: desc
                        });
                    }
                });
            }
        });
        if (!GameSettings_1.default.isNative) {
            const platform = this.GC.platform;
            const systemInfo = this.GC.systemInfo;
            const _this = this;
            platform.getSetting({
                success(res) {
                    console.log(res.authSetting);
                    if (res.authSetting["scope.userInfo"]) {
                        console.log("用户已授权");
                        platform.getUserInfo({
                            success(res) {
                                console.log(res);
                                //此时可进行登录操作
                                _this.login(res.userInfo.nickName, res.userInfo.avatarUrl);
                            }
                        });
                    }
                    else {
                        console.log("用户未授权");
                        // const systemInfo = this.GC.systemInfo
                        const GC_1 = GameCenter_1.default.instance;
                        if (GameSettings_1.default.isSendTrack) {
                            GC_1.sendTrace({
                                eventId: GameConstant_1.default.TRACKEVENTID.AUTH
                            });
                        }
                        let button = platform.createUserInfoButton({
                            type: 'text',
                            text: '',
                            style: {
                                left: 0,
                                top: 0,
                                width: systemInfo.screenWidth,
                                height: systemInfo.screenHeight,
                                backgroundColor: '#00000000',
                                color: '#ffffff',
                                fontSize: 20,
                                textAlign: "center",
                                lineHeight: systemInfo.screenHeight,
                            }
                        });
                        button.onTap((res) => {
                            if (res.userInfo) {
                                console.log("用户授权:", res);
                                if (GameSettings_1.default.isSendTrack) {
                                    this.GC.sendTrace({
                                        eventId: GameConstant_1.default.TRACKEVENTID.AUTHDONE
                                    });
                                }
                                //此时可进行登录操作
                                _this.login(res.userInfo.nickName, res.userInfo.avatarUrl);
                                button.destroy();
                            }
                            else {
                                console.log("用户拒绝授权:", res);
                            }
                        });
                    }
                }
            });
        }
    }
    login(nickName, avatar) {
        // const nickName = this.exportJson.userInfo.nickName
        // const avatar = this.exportJson.userInfo.avatarUrl
        this.GC.platform.login({
            success: (res) => {
                this.GC.serverLogin(res.code, nickName, avatar);
            }
        });
    }
}
exports.default = UserLoginZone;
},{"../Control/GameCenter":3,"../GameConstant":10,"../GameSettings":11,"../extends/ExtBaseButton":61}],58:[function(require,module,exports){
"use strict";
/*
 * @Author: ZZL
 * @Date: 2019-11-01 15:35:03
 * @Last Modified by: ZZL
 * @Last Modified time: 2019-11-08 14:03:16
 */
Object.defineProperty(exports, "__esModule", { value: true });
const ShipControl_1 = require("./ShipControl");
const GameCenter_1 = require("../Control/GameCenter");
const GameConstant_1 = require("../GameConstant");
class RobotShipControl extends ShipControl_1.default {
    constructor() {
        super();
        this.isActivation = false;
        //public isInit : boolean = false
        this.robotBatteryID = "1";
    }
    onEnable() {
        this.GC = GameCenter_1.default.instance;
        if (!this.isInit) {
            this.init(GameConstant_1.default.GAMECOMPONENT.ROBOTSHIP, () => {
                Laya.timer.loop(1000 / this.GC.getBatterySetting(this.robotBatteryID).autoRate, this, this.robotUpdate);
            });
        }
        this._children.forEach(element => {
            element.pivotY = 265;
        });
    }
    onDisable() {
        Laya.timer.clearAll(this.robotUpdate);
    }
    robotUpdate() {
        if (this.isActivation) {
            if (this.GC.robot.robotInfo.batteryId != this.robotBatteryID) {
                Laya.timer.clearAll(this);
                this.robotBatteryID = this.GC.robot.robotInfo.batteryId;
                this.setBattery(this.robotBatteryID);
                Laya.timer.loop(1000 / this.GC.getBatterySetting(this.robotBatteryID).autoRate, this, this.robotUpdate);
            }
            if (this.GC.robot.robotInfo.coin >= this.GC.robot.robotInfo.battertLv) {
                this.GC.robot.robotInfo.coin -= this.GC.robot.robotInfo.battertLv;
                this.nowBattery.fireOnce("robot_" + this.GC.getBulletId());
            }
        }
    }
}
exports.default = RobotShipControl;
},{"../Control/GameCenter":3,"../GameConstant":10,"./ShipControl":51}],59:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-28 16:00:48
 * @Last Modified by:   Odie Robin
 * @Last Modified time: 2019-05-28 16:00:48
 */
Object.defineProperty(exports, "__esModule", { value: true });
class BatteryComponent extends Laya.Script {
}
exports.default = BatteryComponent;
},{}],60:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-28 15:58:08
 * @Last Modified by:   Odie Robin
 * @Last Modified time: 2019-05-28 15:58:08
 */
Object.defineProperty(exports, "__esModule", { value: true });
class BatteryControl extends Laya.Script {
}
exports.default = BatteryControl;
},{}],61:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-28 16:00:58
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-06-14 17:27:29
 */
Object.defineProperty(exports, "__esModule", { value: true });
const AudioManager_1 = require("../Control/AudioManager");
const GameConstant_1 = require("../GameConstant");
class ExtBaseButton extends Laya.Script {
    constructor() {
        super(...arguments);
        /** @prop {name:widthValue,tips:"定义宽度",type:Int,default:0}*/
        this.widthValue = 0;
        /** @prop {name:heightValue,tips:"定义高度",type:Int,default:0}*/
        this.heightValue = 0;
        /** @prop {name:scaleDuration,tips:"定义缩放时长",type:Int,default:100}*/
        this.scaleDuration = 100;
        /** @prop {name:scaleSize,tips:"定义缩放比例",type:Number,default:0.8}*/
        this.scaleSize = 0.8;
        /** @prop {name:scaleDuration,tips:"定义缩放基础比例",type:Number,default:1}*/
        this.scaleOri = 1;
        this.onClicked = null;
        this.onCooldownDone = null;
        this.nowState = 0; // 0 nomal,1 hover, 2 down
        this.isDisable = false;
        this.isChecked = false;
        this.isFrozen = false;
        this.isCheckBox = false;
        this.isCooldown = false;
        this.isPurchasing = false;
        this.isSilence = false;
        this.newLabel = null;
        this.labelInited = false;
        this.labelText = null;
        this.labelFilters = [];
        this.labelOffset = null;
        this.valueZone = null;
        this.valueLabel = null;
        this.countLabel = null;
        this.cooldownZone = null;
        this.cooldownTimeLabel = null;
        this.isOnCooldown = false;
        this.coverColor = '#000000';
    }
    setCallback(callback, cooldownDone = null) {
        this.onClicked = callback;
        this.onCooldownDone = cooldownDone;
    }
    triggerClick() {
        this.onMouseUp();
    }
    toggleChcek(checked = false) {
        this.isChecked = checked;
        this.owner.skin = checked && this.checkSkin ? this.checkSkin : this.mainSkin;
        if (this.valueZone)
            this.valueZone.visible = !checked;
        if (this.isCooldown) {
            this.toggleCooldown(checked);
        }
    }
    toggleDiable(disabled = false) {
        this.isDisable = disabled;
        this.owner.gray = this.isDisable;
    }
    toggleFrozen(freeze) {
        this.isFrozen = freeze;
    }
    toggleSilence(silence) {
        this.isSilence = silence;
    }
    toggleCooldown(cooldown) {
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
    }
    scaleSmall() {
        Laya.Tween.to(this.owner, { scaleX: this.scaleSize, scaleY: this.scaleSize }, this.scaleDuration);
    }
    scaleBig() {
        Laya.Tween.to(this.owner, { scaleX: this.scaleOri, scaleY: this.scaleOri }, this.scaleDuration);
    }
    onMouseOver() {
    }
    onMouseOut() {
        this.scaleBig();
    }
    onMouseDown() {
        if (!this.isDisable && !this.isFrozen) {
            this.scaleSmall();
        }
    }
    onMouseUp() {
        this.scaleBig();
        //[AUDIO]=======[AUDIO]
        AudioManager_1.default.instance.playSound(GameConstant_1.default.MUSICTYPE.TOUCH);
        if (!this.isDisable && !this.isFrozen && this.onClicked && !this.isSilence) {
            this.onClicked();
        }
    }
    // public onClick(){
    //     this.onMouseDown()
    // }
    onEnable() {
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
            this.newLabel = new Laya.Label(`${this.labelText ? this.labelText : 'Label'}`);
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
            const offset = this.labelOffset ? this.labelOffset : new Laya.Point(0, -5);
            this.owner.addChild(this.newLabel.size(this.button.width, this.labelSetting[2] + 10).pos(this.button.width / 2 + offset.x, this.button.height / 2 + offset.y));
            this.labelInited = true;
        }
        if (this.coolDownSetting && this.coolDownSetting[0]) {
            this.isCooldown = true;
            this.cover = new Laya.Sprite();
            let image = new Laya.Image(this.button.skin);
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
    }
    setMainSkin(skin) {
        this.owner.skin = skin;
    }
    setLabelText(text) {
        if (this.labelInited) {
            this.newLabel.text = text;
        }
        else {
            this.labelText = text;
        }
    }
    setLabelFilter(filters) {
        if (this.labelInited) {
            this.newLabel.filters = filters;
        }
        else {
            this.labelFilters = filters;
        }
    }
    setLabelOffset(x, y) {
        if (this.labelInited) {
            this.newLabel.pos(this.newLabel.x + x, this.newLabel.y + y);
        }
        else {
            this.labelOffset = new Laya.Point(x, y);
        }
    }
    setAddonItem(param) {
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
            this.countLabel.text = `${this.countValue}`;
        if (this.valueLabel)
            this.valueLabel.changeText(`${param.addonValue}`);
        this.setValueZone();
    }
    setCount(count) {
        this.countValue = count;
        if (this.countLabel) {
            this.countLabel.text = `${count}`;
            this.setValueZone();
        }
    }
    setValue(text) {
        if (this.valueLabel) {
            this.valueLabel.changeText(`${text}`);
        }
    }
    setValueZone() {
        if (this.valueZone) {
            this.valueZone.visible = !this.isChecked && !this.isOnCooldown && this.countValue == 0;
        }
    }
    coverDown() {
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
    }
    countTime() {
        let totalSeconds = this.timeLeft / 1000;
        let hours = Math.floor(totalSeconds / 3600);
        let minius = Math.floor((totalSeconds - hours * 3600) / 60);
        let second = Math.floor(totalSeconds - hours * 3600 - minius * 60);
        let hoursStr = hours > 0
            ? hours >= 10
                ? hours
                : "0" + hours
            : "";
        let miniusStr = minius > 0
            ? minius >= 10
                ? minius
                : "0" + minius
            : "00";
        let secondStr = second > 0
            ? second >= 10
                ? second
                : "0" + second
            : "00";
        return hoursStr != ""
            ? hoursStr + ":" + miniusStr + ":" + secondStr
            : miniusStr + ":" + secondStr;
    }
}
exports.default = ExtBaseButton;
},{"../Control/AudioManager":1,"../GameConstant":10}],62:[function(require,module,exports){
"use strict";
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-31 16:14:04
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-05-31 19:39:30
 */
Object.defineProperty(exports, "__esModule", { value: true });
const ExtBaseButton_1 = require("../extends/ExtBaseButton");
const GameConstant_1 = require("../GameConstant");
class RedPackShopItemControl extends Laya.Script {
    constructor() {
        super(...arguments);
        this.callback = null;
    }
    onEnable() {
        this.self = this.owner;
        this.self._children.forEach((element) => {
            switch (element.name) {
                case 'purch':
                    this.purchBtn = element.getComponent(ExtBaseButton_1.default);
                    this.purchBtn.setCallback(() => {
                        console.log(`purch item ${this.info}`);
                        if (this.callback) {
                            this.callback(this.info);
                        }
                    });
                    break;
                case 'cost':
                    this.itemValue = element;
                    break;
                case 'redPackItemImage':
                    this.redPackZoneImage = element;
                    break;
                case 'redPackItemValue':
                    this.redPackZoneValue = element;
                    break;
                // case 'coinItem':
                //     this.coinZone = element as Laya.Sprite
                //     break
                case 'coinItemBg':
                    this.coinZoneBg = element;
                    break;
                case 'coinItemValue':
                    this.coinZoneValue = element;
                    break;
                case 'coinItemBonus':
                    this.coinZoneBonus = element;
                    break;
                case 'vipItemImage':
                    this.vipZoneImage = element;
                    break;
                case 'vipItemBonus':
                    this.vipZoneBonus = element;
                    break;
                case 'vipItemValue':
                    this.vipZoneValue = element;
                    break;
            }
        });
    }
    setCallbck(callback) {
        // if(this.purchBtn){
        //     this.purchBtn.setCallback(callback(this.info))
        // }else{
        //     this.callback = callback
        // }
        this.callback = callback;
    }
    //{"id":1,"price":5,"value":60000,"bonus":0,goodsType:}
    setInfo(info) {
        this.info = info;
        switch (info.goodsType) {
            case GameConstant_1.default.SHOPGOODSTYPE.REDPACK:
                this.redPackZoneValue.text = `${info.value}元`;
                break;
            case GameConstant_1.default.SHOPGOODSTYPE.REDPACKCOIN:
                this.coinZoneBonus.visible = info.bonus > 0;
                if (info.bonus > 0) {
                    this.coinZoneBonus.skin = `shop/redPackCoinDiscount_${info.bonus}.png`;
                }
                this.coinZoneBg.skin = `shop/redPackCoinItem_${info.iconId}.png`;
                this.coinZoneValue.value = `${info.value}`;
                break;
            case GameConstant_1.default.SHOPGOODSTYPE.REDPACKVIP:
                this.vipZoneBonus.skin = `shop/redPackVipDiscount_${info.bonus}.png`;
                this.vipZoneValue.value = `${info.value}`;
                break;
        }
        this.redPackZoneImage.visible = info.goodsType == GameConstant_1.default.SHOPGOODSTYPE.REDPACK;
        this.redPackZoneValue.visible = info.goodsType == GameConstant_1.default.SHOPGOODSTYPE.REDPACK;
        this.coinZoneBonus.visible = info.goodsType == GameConstant_1.default.SHOPGOODSTYPE.REDPACKCOIN;
        this.coinZoneBg.visible = info.goodsType == GameConstant_1.default.SHOPGOODSTYPE.REDPACKCOIN;
        this.coinZoneValue.visible = info.goodsType == GameConstant_1.default.SHOPGOODSTYPE.REDPACKCOIN;
        this.vipZoneBonus.visible = info.goodsType == GameConstant_1.default.SHOPGOODSTYPE.REDPACKVIP;
        this.vipZoneValue.visible = info.goodsType == GameConstant_1.default.SHOPGOODSTYPE.REDPACKVIP;
        this.vipZoneImage.visible = info.goodsType == GameConstant_1.default.SHOPGOODSTYPE.REDPACKVIP;
        this.itemValue.value = `${info.price}`;
    }
}
exports.default = RedPackShopItemControl;
},{"../GameConstant":10,"../extends/ExtBaseButton":61}],63:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const ExtBaseButton_1 = require("../extends/ExtBaseButton");
const GameConstant_1 = require("../GameConstant");
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-05-30 14:02:43
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-05-31 16:42:14
 */
class ShopItemControl extends Laya.Script {
    constructor() {
        super(...arguments);
        /** @prop {name:goodsType,tips:"商品类型",type:Int,default:0}*/
        this.goodsType = 0;
        this.needIcon = false;
    }
    onEnable() {
        this.self = this.owner;
        this.self._children.forEach((element) => {
            switch (element.name) {
                case 'price':
                    this.priceLabel = element;
                    break;
                case 'price2':
                    this.priceLabel2 = element;
                    break;
                case 'value':
                    this.valueLabel = element;
                    break;
                case 'purch':
                    this.purchBtn = element.getComponent(ExtBaseButton_1.default);
                    this.purchBtn.setCallback(() => {
                        if (this.callback) {
                            this.callback(this.info);
                        }
                    });
                    break;
                case 'bg':
                    this.itemBg = element;
                    break;
                case 'icon':
                    this.itemIcon = element;
                    break;
                case 'bonus':
                    this.bonusImage = element;
                    break;
            }
        });
    }
    setCallback(callback) {
        this.callback = callback;
    }
    //{"id":1,"price":5,"value":60000,"bonus":0,goodsType:}
    setInfo(info, goodsType) {
        info.goodsType = goodsType;
        this.info = info;
        this.needIcon = info.goodsType == GameConstant_1.default.SHOPGOODSTYPE.COIN;
        this.itemIcon.visible = this.needIcon;
        this.priceLabel.visible = !this.needIcon;
        this.priceLabel2.visible = this.needIcon;
        const price = this.needIcon ? `${info.price}` : `￥${info.price}`;
        this.priceLabel.value = price;
        this.priceLabel2.value = price;
        this.valueLabel.value = `${info.value}`;
        const bg = `shop/${goodsType == GameConstant_1.default.SHOPGOODSTYPE.COIN ? "coin" : "diamond"}Item_${info.id}.png`;
        this.itemBg.skin = bg;
        this.bonusImage.visible = info.bonus > 0;
        if (info.bonus > 0) {
            this.bonusImage.skin = `shop/Discount_${info.bonus}.png`;
        }
    }
    setVisible(flag) {
        this.self.visible = flag;
    }
}
exports.default = ShopItemControl;
},{"../GameConstant":10,"../extends/ExtBaseButton":61}],64:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const GameSettings_1 = require("../GameSettings");
const GameConstant_1 = require("../GameConstant");
/*
 * @Author: Odie Robin (odierobin@gmail.com)
 * @Date: 2019-06-03 14:28:25
 * @Last Modified by: Odie Robin
 * @Last Modified time: 2019-06-06 17:20:01
 */
class VipPrizeItemControl extends Laya.Script {
    onEnable() {
        this.self = this.owner;
        this.self._children.forEach((element) => {
            switch (element.name) {
                case 'icon':
                    this.icon = element;
                    break;
                case 'count':
                    this.count = element;
                    break;
            }
        });
    }
    setInfo(info) {
        // this.icon.skin = `item/Item${info.id.toLowerCase()}.png`
        this.icon.skin = GameSettings_1.default.itemIconList[info.id] || GameSettings_1.default.itemIconList['COIN'];
        let text = `${info.count || info.desc}`;
        if (info.id == GameConstant_1.default.ITEMTYPE.COIN && text.indexOf('万') < 0) {
            let value = parseInt(text);
            if (value >= 10000) {
                value = Math.floor(value / 10000);
            }
            text = `${value}万`;
        }
        this.count.value = text;
        this.count.spaceX = text.length > 3 ? -20 : -10;
        this.count.visible = text && text != '-1' ? true : false;
    }
}
exports.default = VipPrizeItemControl;
},{"../GameConstant":10,"../GameSettings":11}],65:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class TestFishItemSceneControl extends Laya.Script {
    onEnable() {
        this.self = this.owner;
        window['test'] = this;
        this.fish = Laya.Pool.getItemByCreateFun('testFish', this.FishPrefab.create, this.FishPrefab);
        this.self.addChild(this.fish.pos(Laya.stage.width / 2, Laya.stage.height / 2));
        this.drop = Laya.Pool.getItemByCreateFun('testDrop', this.dropPrefab.create, this.dropPrefab);
        this.fish.addChild(this.drop.pos(0, 50));
    }
}
exports.default = TestFishItemSceneControl;
},{}],66:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var Vector2 = Laya.Vector2;
class Tarsis {
    static Vector2Magnitude(v2) {
        return Math.sqrt(v2.x * v2.x + v2.y * v2.y);
    }
    static Vector2SqrtMagnitude(v2) {
        return v2.x * v2.x + v2.y + v2.y;
    }
    static Vector2Normalize(v2) {
        let meg = this.Vector2Magnitude(v2);
        if (meg > this.kEpsilon) {
            return new Vector2(v2.x / meg, v2.y / meg);
        }
        else {
            return new Vector2(0, 0);
        }
    }
    static Vector2Angle(from, to) {
        let deg2Rad = 360 / Math.PI / 2;
        let denominator = Math.sqrt((from.x * from.x + from.y * from.y) * (to.x * to.x + to.y * to.y));
        if (denominator < this.kEpsilonNormalSqrt)
            return 0;
        let dot = Math.max(-1, Math.min(1, from.x * to.x + from.y * to.y / denominator));
        return Math.acos(dot) * deg2Rad;
    }
    static Vector2Plus(lhs, rhs) {
        return new Vector2(lhs.x + rhs.x, lhs.y + rhs.y);
    }
    static Vector2Minus(lhs, rhs) {
        return new Vector2(lhs.x - rhs.x, lhs.y - rhs.y);
    }
    static Vector2Dot(lhs, rhs) {
        return lhs.x * rhs.x + lhs.y * rhs.y;
    }
    static Vector2Rotate(v, degrees) {
        let sin = Math.sin(degrees * Math.PI / 180);
        let cos = Math.cos(degrees * Math.PI / 180);
        let tx = v.x;
        let ty = v.y;
        return new Vector2((cos * tx) - (sin * ty), (sin * tx) + (cos * ty));
    }
    static GetNowRathio() {
        return Laya.stage.width / Laya.stage.height > 9 / 16 ? Laya.stage.width / 1080 : Laya.stage.height / 1920;
    }
    static GetSprite3DProjection(target, camera) {
        let result = new Laya.Vector3(-1000, -1000, -1000);
        camera.viewport.project(target.transform.position, camera.projectionViewMatrix, result);
        return result;
    }
    static GetTransform3DProjection(trans, camera) {
        let result = new Laya.Vector3(-1000, -1000, -1000);
        camera.viewport.project(trans.position, camera.projectionViewMatrix, result);
        return result;
    }
    static BesizerEvaluate(time, start, end, ctrol) {
        let leftTime = 1 - time;
        let x = start.x * leftTime * leftTime + 2 * ctrol.x * leftTime * time + end.x * time * time;
        let y = start.y * leftTime * leftTime + 2 * ctrol.y * leftTime * time + end.y * time * time;
        return new Laya.Point(x, y);
    }
    static PointMagnitude(p) {
        return Math.sqrt(p.x * p.x + p.y * p.y);
    }
    static PointNormalize(p) {
        let meg = this.PointMagnitude(p);
        if (meg > this.kEpsilon) {
            return new Laya.Point(p.x / meg, p.y / meg);
        }
        else {
            return new Laya.Point(0, 0);
        }
    }
    static PointAngle(from, to) {
        let deg2Rad = 360 / Math.PI / 2;
        let denominator = Math.sqrt((from.x * from.x + from.y * from.y) * (to.x * to.x + to.y * to.y));
        if (denominator < this.kEpsilonNormalSqrt)
            return 0;
        let dot = Math.max(-1, Math.min(1, from.x * to.x + from.y * to.y / denominator));
        return Math.acos(dot) * deg2Rad;
    }
    static PointPlus(lhs, rhs) {
        return new Laya.Point(lhs.x + rhs.x, lhs.y + rhs.y);
    }
    static PointMinus(lhs, rhs) {
        return new Laya.Point(lhs.x - rhs.x, lhs.y - rhs.y);
    }
    static PointDot(lhs, rhs) {
        return lhs.x * rhs.x + lhs.y * rhs.y;
    }
    static GetAngle(lhs, rhs) {
        var x = rhs.x - lhs.x;
        var y = rhs.y - lhs.y;
        var hypotenuse = Math.sqrt(Math.pow(x, 2) + Math.pow(y, 2));
        var cos = x / hypotenuse;
        var radian = Math.acos(cos);
        var angle = 180 / (Math.PI / radian);
        if (y < 0) {
            angle = -angle;
        }
        else if ((y == 0) && (x < 0)) {
            angle = 180;
        }
        return angle;
    }
    /**
     * 贝赛尔插值算法中间函数
     * @param t 时间
     * @param points 初始点数组
     * @param count 阶数（-1）
     */
    static BezierInterpolation(t, points, count) {
        let tmpPoint = [];
        for (let i = 1; i < count; ++i) {
            for (let j = 0; j < count - i; ++j) {
                if (i == 1) {
                    tmpPoint[j] = new Laya.Point(points[j].x * (1 - t) + points[j + 1].x * t, points[j].y * (1 - t) + points[j + 1].y * t);
                    continue;
                }
                tmpPoint[j] = new Laya.Point(tmpPoint[j].x * (1 - t) + tmpPoint[j + 1].x * t, tmpPoint[j].y * (1 - t) + tmpPoint[j + 1].y * t);
            }
        }
        return tmpPoint[0];
    }
    /**
     * 贝赛尔插值算法
     * @param points 初始点数组
     * @param count 阶数（-1）
     * @param outCount 输出数组长度
     */
    static BezierCurvePoints(points, count, outCount) {
        let outPoints = [];
        const step = 1.0 / outCount;
        let t = 0;
        for (let i = 0; i < outCount; i++) {
            outPoints[i] = this.BezierInterpolation(t, points, count);
            t += step;
        }
        outPoints.push(new Laya.Point(points[points.length - 1].x, points[points.length - 1].y));
        return outPoints;
    }
    static BezierCurvePath(points, fromRight = false) {
        let outPut = { points: points, pathLen: 0, pointLenInPath: [], rightPath: fromRight };
        let len = 0;
        let arr = [];
        let dir = [];
        for (let i = 0; i < points.length; i++) {
            const element = points[i];
            let prev = i > 0 ? points[i - 1] : element;
            const temp = Math.sqrt((element.x - prev.x) * (element.x - prev.x) + (element.y - prev.y) * (element.y - prev.y));
            len += temp;
            arr.push(len);
        }
        outPut.pathLen = len;
        outPut.pointLenInPath = arr;
        return outPut;
    }
    static ParseQueryString(url) {
        let params = {};
        let arr = url.split("?");
        if (arr.length > 1) {
            let arr1 = arr[1].split("&");
            for (var i = 0; i < arr1.length; i++) {
                let arr2 = arr1[i].split('=');
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
        // console.log(params); 
        return params;
    }
    static CubicCurveAlgorithmControlPoints(points) {
        let firstControlPoints = [];
        let secondControlPoints = [];
        let count = points.length - 1;
        if (count == 1) {
            let P0 = points[0];
            let P3 = points[1];
            let P1x = (2 * P0.x + P3.x) / 3;
            let P1y = (2 * P0.y + P3.y) / 3;
            firstControlPoints.push({ x: P1x, y: P1y });
            let P2x = (2 * P1x - P0.x);
            let P2y = (2 * P1y - P0.y);
            secondControlPoints.push({ x: P2x, y: P2y });
        }
        else {
            let rhsArray = [];
            let a = [];
            let b = [];
            let c = [];
            for (let i = 0; i < count; i++) {
                let rhsValueX = 0;
                let rhsValueY = 0;
                let P0 = points[i];
                let P3 = points[i + 1];
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
            for (let i = 1; i < count; i++) {
                let rhsValueX = rhsArray[i].x;
                let rhsValueY = rhsArray[i].y;
                let prevRhsValueX = rhsArray[i - 1].x;
                let prevRhsValueY = rhsArray[i - 1].y;
                let m = a[i] / b[i - 1];
                let b1 = b[i] - m * c[i - 1];
                b[i] = b1;
                let r2x = rhsValueX - m * prevRhsValueX;
                let r2y = rhsValueY - m * prevRhsValueY;
                rhsArray[i] = { x: r2x, y: r2y };
            }
            let lastControlPointX = rhsArray[count - 1].x / b[count - 1];
            let lastControlPointY = rhsArray[count - 1].y / b[count - 1];
            firstControlPoints[count - 1] = { x: lastControlPointX, y: lastControlPointY };
            for (let i = count - 2; i >= 0; i--) {
                let nextControlPoint = firstControlPoints[i + 1];
                if (nextControlPoint) {
                    let controlPointX = (rhsArray[i].x - c[i] * nextControlPoint.x) / b[i];
                    let controlPointY = (rhsArray[i].y - c[i] * nextControlPoint.y) / b[i];
                    firstControlPoints[i] = { x: controlPointX, y: controlPointY };
                }
            }
            for (let i = 0; i < count; i++) {
                if (i == count - 1) {
                    let P3 = points[i + 1];
                    let P1 = firstControlPoints[i];
                    if (P1) {
                        let controlPointX = (P3.x + P1.x) / 2;
                        let controlPointY = (P3.y + P1.y) / 2;
                        secondControlPoints.push({ x: controlPointX, y: controlPointY });
                    }
                }
                else {
                    let P3 = points[i + 1];
                    let nextP1 = firstControlPoints[i + 1];
                    if (nextP1) {
                        let controlPointX = 2 * P3.x - nextP1.x;
                        let controlPointY = 2 * P3.y - nextP1.y;
                        secondControlPoints.push({ x: controlPointX, y: controlPointY });
                    }
                }
            }
        }
        let controlPoints = [];
        for (let i = 0; i < count; i++) {
            let firstControlPoint = firstControlPoints[i];
            let secondControlPoint = secondControlPoints[i];
            if (firstControlPoint && secondControlPoint) {
                let segment = { controlPoint1: firstControlPoint, controlPoint2: secondControlPoint };
                controlPoints.push(segment);
            }
        }
        return controlPoints;
    }
    static CubicCurveAlgorithmInterpolation(points, pointDistance = 10) {
        const cpList = this.CubicCurveAlgorithmControlPoints(points);
        let list = [];
        for (let i = 0; i < points.length; i++) {
            if (i > 0) {
                const p1 = points[i - 1];
                const p2 = cpList[i - 1].controlPoint1;
                const p3 = cpList[i - 1].controlPoint2;
                const p4 = points[i];
                const count = Math.ceil(Math.sqrt(Math.pow((p4.x - p1.x), 2) + Math.pow((p4.y - p1.y), 2)) / pointDistance);
                const step = 1.0 / count;
                let t = 0;
                for (let j = 0; j < count; j++) {
                    let x = Math.pow((1 - t), 3) * p1.x + 3 * p2.x * t * (1 - t) * (1 - t) + 3 * p3.x * t * t * (1 - t) + p4.x * Math.pow(t, 3);
                    let y = Math.pow((1 - t), 3) * p1.y + 3 * p2.y * t * (1 - t) * (1 - t) + 3 * p3.y * t * t * (1 - t) + p4.y * Math.pow(t, 3);
                    list.push({ x: x, y: y });
                    t += step;
                }
            }
        }
        list.push(points[points.length - 1]);
        return list;
    }
    static SetupLabel(label, setting) {
        label.fontSize = setting.fontSize;
        label.color = setting.color;
        label.stroke = setting.stroke || 0;
        label.strokeColor = setting.strokeColor || "#FFFFFF";
        label.align = setting.align || "center";
        label.bold = setting.bold || false;
        label.valign = setting.valign || "middle";
        label.anchorX = setting.anchorX || label.anchorX;
        label.anchorY = setting.anchorY || label.anchorY;
        if (setting.filter) {
            let arr = [];
            setting.filter.forEach(info => {
                arr.push(new Laya.GlowFilter(info.color, info.blur, info.x, info.y));
            });
            label.filters = arr;
        }
        return label;
    }
    static GetTimeDetail(time, isMillisecond = false) {
        let totalSeconds = isMillisecond ? time / 1000 : time;
        let hours = Math.floor(totalSeconds / 3600);
        let minius = Math.floor((totalSeconds - hours * 3600) / 60);
        let seconds = Math.floor(totalSeconds - hours * 3600 - minius * 60);
        let milliseconds = isMillisecond ? seconds : seconds * 1000;
        let hoursStr = hours > 0
            ? hours >= 10
                ? hours
                : "0" + hours
            : "";
        let miniusStr = minius > 0
            ? minius >= 10
                ? minius
                : "0" + minius
            : "00";
        let secondStr = seconds > 0
            ? seconds >= 10
                ? seconds
                : "0" + seconds
            : "00";
        let millisecondsStr = milliseconds;
        let full = hoursStr + ":" + miniusStr + ":" + secondStr + ":" + millisecondsStr;
        let compact = hours > 0
            ? hoursStr + ":" + miniusStr
            : miniusStr + ":" + secondStr;
        return {
            hours: hours,
            minius: minius,
            seconds: seconds,
            milliseconds: milliseconds,
            full: full,
            compact: compact
        };
    }
    static FormatDate(fmt) {
        var dateTime = new Date();
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
    }
    static RandomRange(min, max) {
        return min + Math.floor(Math.random() * (max - min));
    }
    static RandomRangeTarget(target) {
        return target.min + Math.floor(Math.random() * (target.max - target.min));
    }
    static RandomArrayItem(array) {
        return array[this.RandomRange(0, array.length)];
    }
    static GetLanguageSafeName(code, isCap = false) {
        code = code.replace("-", "_");
        return isCap ? code.toUpperCase() : code.toLowerCase();
    }
    /**
     * 转换rgb数组为"#"开头的颜色字符串
     * @param rgbarr rgb数组，[R,G,B]
     */
    static RGBToHex(rgbarr) {
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
    }
    /**
     * 转换web颜色字符串为rgb的数组：[R,G,B]
     * @param hex 字符串，“#”开头，#f00或#ff00cd
     */
    static HexToRGBArr(hex) {
        var rgb = [];
        hex = hex.substr(1);
        if (hex.length === 3) {
            hex = hex.replace(/(.)/g, '$1$1');
        }
        for (let i = 0; i < 3; i++) {
            const color = hex.substr(i * 2, 2);
            rgb.push(parseInt(color, 0x10));
        }
        return rgb;
    }
    /**
     * Erzeugt eine UUID nach RFC 4122
     */
    static uuid() {
        return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (char) => {
            let random = Math.random() * 16 | 0; // Nachkommastellen abschneiden
            let value = char === "x" ? random : (random % 4 + 8); // Bei x Random 0-15 (0-F), bei y Random 0-3 + 8 = 8-11 (8-b) gemäss RFC 4122
            return value.toString(16); // Hexadezimales Zeichen zurückgeben
        });
    }
}
exports.default = Tarsis;
Tarsis.kEpsilon = 0.00001;
Tarsis.kEpsilonNormalSqrt = 1e-15;
class LowPassFilter {
    constructor(tau) {
        this.iteration = 0;
        this.tau = tau;
    }
    NextStep(h, raw) {
        if (this.iteration == 0) { // if it's the first iteration
            this.filteredValue = raw; // just initate filteredValue
        }
        else {
            let alpha = Math.exp(-h / this.tau); // calculate alfa value based on time step and filter's time constant
            this.filteredValue = alpha * this.filteredValue + (1 - alpha) * raw; // calculate new filteredValue from previous value and new raw value
        }
        this.iteration += 1; // increment iteration number
        return this.filteredValue;
    }
    Reset() {
        this.iteration = 0; // reset iteration count / force filteredValue initalization
    }
}
class ViewControl extends Laya.Script {
    onEnable() {
        this.self = this.owner;
        this.view = this.owner;
    }
    setShow(show) {
        this.self.visible = show;
    }
    filtAllChildren(action) {
        for (let index = 0; index < this.self.numChildren; index++) {
            const element = this.self.getChildAt(index);
            action(element, this);
        }
    }
}
exports.ViewControl = ViewControl;
},{}],67:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class TarsisHttp {
    static StartHttpCall(params) {
        console.log(params);
        const settings = Object.assign({ url: '', isPost: false, data: null, onSuccess: null, onError: null, onProgress: null, timeout: 10000, responseType: 'text' }, params);
        var xhr = new Laya.HttpRequest();
        let postData = '';
        xhr.http.timeout = settings.timeout;
        xhr.once(Laya.Event.COMPLETE, this, (data) => {
            if (settings.onSuccess) {
                settings.onSuccess(data);
            }
            else {
                console.log("[HTTP] success @ " + data);
            }
        });
        xhr.once(Laya.Event.ERROR, this, (data) => {
            if (settings.onError) {
                settings.onError(data);
            }
            else {
                console.log("[HTTP] error @ " + data);
            }
        });
        xhr.on(Laya.Event.PROGRESS, this, (data) => {
            if (settings.onProgress) {
                settings.onProgress(data);
            }
            else {
                console.log("[HTTP] progress @ " + data);
            }
        });
        if (settings.data) {
            let index = 0;
            for (const key of Object.keys(settings.data)) {
                if (index > 0) {
                    postData += "&";
                }
                index += 1;
                postData += key + "=" + settings.data[key];
            }
        }
        xhr.send(`${settings.url}${!settings.isPost && postData ? '?' + postData : ''}`, settings.isPost ? postData : '', `${settings.isPost ? 'post' : 'get'}`, settings.responseType);
    }
}
exports.default = TarsisHttp;
},{}],68:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class TarsisSocket {
    constructor() {
        this.isOpen = false;
        this.onOpen = null;
        this.onError = null;
        this.onClose = null;
        this.onMsg = null;
    }
    init(url, onOpen, onError, onClose, onMsg) {
        this.onOpen = onOpen;
        this.onClose = onClose;
        this.onError = onError;
        this.onMsg = onMsg;
        this.connect(url);
    }
    close() {
        this.socket.close();
    }
    connect(url) {
        this.socket = new Laya.Socket();
        // this.socket.timeout = 10000
        // this.socket.connectByUrl("ws://echo.websocket.org:80")
        this.socket.connectByUrl(url);
        this.output = this.socket.output;
        this.socket.on(Laya.Event.OPEN, this, this.onSocketOpen);
        this.socket.on(Laya.Event.CLOSE, this, this.onSocketClose);
        this.socket.on(Laya.Event.MESSAGE, this, this.onMessageReveived);
        this.socket.on(Laya.Event.ERROR, this, this.onConnectError);
    }
    onSocketOpen() {
        console.log("[SOCKET] Socket Connected");
        this.isOpen = true;
        // 发送字符串
        // this.socket.send("demonstrate <sendString>");
        // 使用output.writeByte发送
        // var message: string = "demonstrate <output.writeByte>";
        // for (var i: number = 0; i < message.length; ++i) {
        //     this.output.writeByte(message.charCodeAt(i));
        // }
        // this.socket.flush();
        if (this.onOpen)
            this.onOpen();
    }
    onSocketClose() {
        console.log("[SOCKET] Socket closed");
        this.isOpen = false;
        if (this.onClose)
            this.onClose();
    }
    onMessageReveived(message) {
        // console.log("[SOCKET] Message from server:");
        let msg = "";
        if (typeof message == "string") {
            // console.log(message);
            msg = message;
        }
        else if (message instanceof ArrayBuffer) {
            console.log(new Laya.Byte(message).readUTFBytes());
            msg = new Laya.Byte(message).readUTFBytes();
        }
        this.socket.input.clear();
        if (this.onMsg)
            this.onMsg(msg);
    }
    onConnectError(e) {
        console.log("[SOCKET] Error : " + e);
        if (this.onError)
            this.onError(e);
    }
    sendMessge(msg) {
        if (this.isOpen) {
            try {
                this.socket.send(JSON.stringify(msg));
            }
            catch (error) {
                if (this.onError)
                    this.onError(error);
            }
        }
    }
}
exports.default = TarsisSocket;
},{}]},{},[12])