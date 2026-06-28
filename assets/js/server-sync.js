/**
 * RP-Hub Server Sync Layer
 * 负责：与 RP-Hub 后端通信、JWT 持久化、自动刷新令牌、本地/服务端模式切换。
 * 设计为单例（window.RPHubServerSync），供 app.js 按需调用，不强制侵入。
 * 当未登录或未配置服务器时，所有方法返回安全默认值，原本地逻辑不受影响。
 */
(function () {
    'use strict';

    const STORAGE_KEYS = {
        baseUrl: 'rphub_server_baseurl',
        accessToken: 'rphub_server_access_token',
        refreshToken: 'rphub_server_refresh_token',
        user: 'rphub_server_user',
        mode: 'rphub_server_mode', // 'local' | 'server'
        lastSync: 'rphub_server_last_sync',
    };

    const EVENT_CHANGE = 'rphub:auth-change';
    const EVENT_SYNC_START = 'rphub:sync-start';
    const EVENT_SYNC_END = 'rphub:sync-end';

    function lsGet(key, fallback) {
        try {
            const v = localStorage.getItem(key);
            return v === null ? fallback : v;
        } catch (_) { return fallback; }
    }
    function lsSet(key, value) {
        try { localStorage.setItem(key, value === null || value === undefined ? '' : String(value)); } catch (_) { }
    }
    function lsDel(key) {
        try { localStorage.removeItem(key); } catch (_) { }
    }
    function lsGetJSON(key, fallback) {
        const raw = lsGet(key, null);
        if (raw === null || raw === '') return fallback;
        try { return JSON.parse(raw); } catch (_) { return fallback; }
    }
    function lsSetJSON(key, value) {
        try { localStorage.setItem(key, JSON.stringify(value)); } catch (_) { }
    }

    class ServerSync {
        constructor() {
            this.baseUrl = (lsGet(STORAGE_KEYS.baseUrl, '') || '').replace(/\/+$/, '');
            this.accessToken = lsGet(STORAGE_KEYS.accessToken, '') || '';
            this.refreshToken = lsGet(STORAGE_KEYS.refreshToken, '') || '';
            this.user = lsGetJSON(STORAGE_KEYS.user, null);
            this.mode = lsGet(STORAGE_KEYS.mode, 'local') === 'server' ? 'server' : 'local';
            this.lastSync = parseInt(lsGet(STORAGE_KEYS.lastSync, '0'), 10) || 0;
            this._refreshing = null;
            this._listeners = { [EVENT_CHANGE]: [], [EVENT_SYNC_START]: [], [EVENT_SYNC_END]: [] };
        }

        // ---------- Event helpers ----------
        on(event, cb) {
            if (!this._listeners[event]) this._listeners[event] = [];
            this._listeners[event].push(cb);
            return () => {
                this._listeners[event] = this._listeners[event].filter(x => x !== cb);
            };
        }
        _emit(event, payload) {
            (this._listeners[event] || []).forEach(cb => { try { cb(payload); } catch (e) { console.warn('listener err', e); } });
            try { window.dispatchEvent(new CustomEvent(event, { detail: payload })); } catch (_) { }
        }

        // ---------- State ----------
        get isLoggedIn() { return !!this.accessToken && !!this.user; }
        get isServerMode() { return this.mode === 'server' && this.isLoggedIn; }
        get isAdmin() { return this.isLoggedIn && this.user?.role === 'admin'; }

        setBaseUrl(url) {
            this.baseUrl = (url || '').trim().replace(/\/+$/, '');
            lsSet(STORAGE_KEYS.baseUrl, this.baseUrl);
        }

        setMode(mode) {
            const m = mode === 'server' ? 'server' : 'local';
            if (this.mode === m) return;
            this.mode = m;
            lsSet(STORAGE_KEYS.mode, m);
            this._emit(EVENT_CHANGE, { mode: m });
        }

        _persistSession(token, refreshToken, user) {
            this.accessToken = token || '';
            this.refreshToken = refreshToken || '';
            this.user = user || null;
            lsSet(STORAGE_KEYS.accessToken, this.accessToken);
            lsSet(STORAGE_KEYS.refreshToken, this.refreshToken);
            lsSetJSON(STORAGE_KEYS.user, this.user);
            this._emit(EVENT_CHANGE, { user: this.user });
        }

        _clearSession() {
            this.accessToken = '';
            this.refreshToken = '';
            this.user = null;
            lsDel(STORAGE_KEYS.accessToken);
            lsDel(STORAGE_KEYS.refreshToken);
            lsDel(STORAGE_KEYS.user);
            lsDel(STORAGE_KEYS.lastSync);
            this.lastSync = 0;
            this._emit(EVENT_CHANGE, { user: null });
        }

        _decodeJwtPayload(token) {
            try {
                const payload = String(token || '').split('.')[1];
                if (!payload) return null;
                const padded = payload.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - payload.length % 4) % 4);
                return JSON.parse(atob(padded));
            } catch (_) {
                return null;
            }
        }

        _shouldRefreshAccessToken() {
            const payload = this._decodeJwtPayload(this.accessToken);
            const exp = Number(payload?.exp || 0);
            if (!exp) return false;
            return Date.now() >= exp * 1000 - 60 * 1000;
        }

        async _ensureFreshAccessToken() {
            if (!this.accessToken || !this.refreshToken || !this._shouldRefreshAccessToken()) return true;
            return this._refreshAccessToken();
        }

        // ---------- HTTP ----------
        async _request(path, options = {}) {
            if (!this.baseUrl) {
                const e = new Error('未配置服务器地址');
                e.code = 'NO_BASEURL';
                throw e;
            }
            await this._ensureFreshAccessToken();
            const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
            if (this.accessToken && !headers.Authorization) {
                headers.Authorization = 'Bearer ' + this.accessToken;
            }
            let res;
            try {
                res = await fetch(this.baseUrl + path, { ...options, headers });
            } catch (e) {
                const err = new Error('网络错误：' + (e.message || 'fetch failed'));
                err.code = 'NETWORK';
                throw err;
            }
            if (res.status === 401 && this.refreshToken && !options._retried) {
                const refreshed = await this._refreshAccessToken();
                if (refreshed) {
                    return this._request(path, { ...options, headers: { ...(options.headers || {}), Authorization: 'Bearer ' + this.accessToken }, _retried: true });
                }
            }
            let body = null;
            const text = await res.text();
            if (text) {
                try { body = JSON.parse(text); } catch (_) { body = text; }
            }
            if (!res.ok) {
                const e = new Error((body && body.error) || ('HTTP ' + res.status));
                e.status = res.status;
                e.body = body;
                if (res.status === 401) e.code = 'UNAUTHORIZED';
                throw e;
            }
            return body;
        }

        async _rawRequest(path, options = {}) {
            if (!this.baseUrl) {
                const e = new Error('未配置服务器地址');
                e.code = 'NO_BASEURL';
                throw e;
            }
            await this._ensureFreshAccessToken();
            const headers = { ...(options.headers || {}) };
            if (this.accessToken && !headers.Authorization) {
                headers.Authorization = 'Bearer ' + this.accessToken;
            }
            let res;
            try {
                res = await fetch(this.baseUrl + path, { ...options, headers });
            } catch (e) {
                const err = new Error('网络错误：' + (e.message || 'fetch failed'));
                err.code = 'NETWORK';
                throw err;
            }
            if (res.status === 401 && this.refreshToken && !options._retried) {
                const refreshed = await this._refreshAccessToken();
                if (refreshed) {
                    return this._rawRequest(path, {
                        ...options,
                        headers: { ...(options.headers || {}), Authorization: 'Bearer ' + this.accessToken },
                        _retried: true,
                    });
                }
            }
            if (!res.ok) {
                const text = await res.text().catch(() => '');
                let body = null;
                if (text) {
                    try { body = JSON.parse(text); } catch (_) { body = text; }
                }
                const e = new Error((body && body.error) || ('HTTP ' + res.status));
                e.status = res.status;
                e.body = body;
                if (res.status === 401) e.code = 'UNAUTHORIZED';
                throw e;
            }
            return res;
        }

        async _refreshAccessToken() {
            if (this._refreshing) return this._refreshing;
            this._refreshing = (async () => {
                try {
                    const res = await fetch(this.baseUrl + '/api/auth/refresh', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ refreshToken: this.refreshToken }),
                    });
                    if (!res.ok) throw new Error('refresh failed');
                    const data = await res.json();
                    if (data.token) {
                        this.accessToken = data.token;
                        this.refreshToken = data.refreshToken || this.refreshToken;
                        this.user = data.user || this.user;
                        lsSet(STORAGE_KEYS.accessToken, this.accessToken);
                        lsSet(STORAGE_KEYS.refreshToken, this.refreshToken);
                        lsSetJSON(STORAGE_KEYS.user, this.user);
                        this._emit(EVENT_CHANGE, { user: this.user, refreshed: true });
                        return true;
                    }
                    throw new Error('no token in response');
                } catch (e) {
                    // Refresh failed: log out
                    this._clearSession();
                    return false;
                } finally {
                    this._refreshing = null;
                }
            })();
            return this._refreshing;
        }

        // ---------- Auth API ----------
        async getPublicConfig() {
            if (!this.baseUrl) return null;
            try {
                const res = await fetch(this.baseUrl + '/api/config');
                if (!res.ok) return null;
                return await res.json();
            } catch (_) { return null; }
        }

        async register(username, password) {
            const data = await this._request('/api/auth/register', {
                method: 'POST',
                body: JSON.stringify({ username, password }),
            });
            this._persistSession(data.token, data.refreshToken, data.user);
            return data.user;
        }

        async login(username, password) {
            const data = await this._request('/api/auth/login', {
                method: 'POST',
                body: JSON.stringify({ username, password }),
            });
            this._persistSession(data.token, data.refreshToken, data.user);
            return data.user;
        }

        async logout() {
            try {
                if (this.baseUrl && this.refreshToken) {
                    await fetch(this.baseUrl + '/api/auth/logout', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ refreshToken: this.refreshToken }),
                    }).catch(() => { });
                }
            } finally {
                this._clearSession();
                this.setMode('local');
            }
        }

        async fetchMe() {
            if (!this.accessToken) return null;
            try {
                const data = await this._request('/api/auth/me');
                this.user = data.user;
                lsSetJSON(STORAGE_KEYS.user, this.user);
                this._emit(EVENT_CHANGE, { user: this.user });
                return this.user;
            } catch (e) {
                if (e.code === 'UNAUTHORIZED') this._clearSession();
                return null;
            }
        }

        async updateProfile(patch) {
            const data = await this._request('/api/auth/me', {
                method: 'PATCH',
                body: JSON.stringify(patch),
            });
            if (data.user) {
                this.user = data.user;
                lsSetJSON(STORAGE_KEYS.user, this.user);
                this._emit(EVENT_CHANGE, { user: this.user });
            }
            return this.user;
        }

        async proxyChat(payload, options = {}) {
            if (!this.isLoggedIn) return null;
            return this._rawRequest('/api/proxy/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload || {}),
                signal: options.signal,
            });
        }

        async proxyNaiGenerate(payload, options = {}) {
            if (!this.isLoggedIn) return null;
            return this._rawRequest('/api/proxy/nai-generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload || {}),
                signal: options.signal,
            });
        }

        // ---------- Sync API ----------
        async pullAll() {
            if (!this.isServerMode) return null;
            this._emit(EVENT_SYNC_START, { type: 'pull' });
            try {
                const data = await this._request('/api/sync/all');
                this.lastSync = Date.now();
                lsSet(STORAGE_KEYS.lastSync, String(this.lastSync));
                return data;
            } finally {
                this._emit(EVENT_SYNC_END, { type: 'pull' });
            }
        }

        async pullBootstrap() {
            if (!this.isServerMode) return null;
            this._emit(EVENT_SYNC_START, { type: 'bootstrap' });
            try {
                const data = await this._request('/api/sync/bootstrap');
                this.lastSync = Date.now();
                lsSet(STORAGE_KEYS.lastSync, String(this.lastSync));
                return data;
            } catch (e) {
                if (e?.status === 404) {
                    return this.pullAll();
                }
                throw e;
            } finally {
                this._emit(EVENT_SYNC_END, { type: 'bootstrap' });
            }
        }

        async pullBootstrapDiff(known = {}, knownHashes = {}) {
            if (!this.isServerMode) return null;
            this._emit(EVENT_SYNC_START, { type: 'bootstrap-diff' });
            try {
                const data = await this._request('/api/sync/bootstrap-diff', {
                    method: 'POST',
                    body: JSON.stringify({ known: known || {}, knownHashes: knownHashes || {} }),
                });
                this.lastSync = Date.now();
                lsSet(STORAGE_KEYS.lastSync, String(this.lastSync));
                return data;
            } catch (e) {
                if (e?.status === 404) {
                    return this.pullBootstrap();
                }
                throw e;
            } finally {
                this._emit(EVENT_SYNC_END, { type: 'bootstrap-diff' });
            }
        }

        async putGlobal(name, value) {
            if (!this.isServerMode) return null;
            return this._request('/api/sync/global/' + encodeURIComponent(name), {
                method: 'PUT',
                body: JSON.stringify({ value }),
            });
        }

        async getScoped(name, id) {
            if (!this.isServerMode) return null;
            return this._request(`/api/sync/scoped/${encodeURIComponent(name)}/${encodeURIComponent(id)}`);
        }

        async getScopedChatDiff(id, state = {}) {
            if (!this.isServerMode || !id) return null;
            return this._request(`/api/sync/scoped/chat/${encodeURIComponent(id)}/diff`, {
                method: 'POST',
                body: JSON.stringify({
                    knownIds: Array.isArray(state.knownIds) ? state.knownIds : [],
                    knownHashes: Array.isArray(state.knownHashes) ? state.knownHashes : [],
                }),
            });
        }

        async putScopedChatConditional(id, value, options = {}) {
            if (!this.isServerMode || !id) return null;
            return this._request(`/api/sync/scoped/chat/${encodeURIComponent(id)}/conditional`, {
                method: 'PUT',
                body: JSON.stringify({
                    value,
                    baseUpdatedAt: Number(options.baseUpdatedAt || 0),
                    baseHash: options.baseHash || '',
                    force: options.force === true,
                }),
            });
        }

        async putScoped(name, id, value) {
            if (!this.isServerMode) return null;
            return this._request(`/api/sync/scoped/${encodeURIComponent(name)}/${encodeURIComponent(id)}`, {
                method: 'PUT',
                body: JSON.stringify({ value }),
            });
        }

        async deleteScoped(name, id) {
            if (!this.isServerMode) return null;
            return this._request(`/api/sync/scoped/${encodeURIComponent(name)}/${encodeURIComponent(id)}`, { method: 'DELETE' });
        }

        async bulkSync({ global = {}, scoped = {}, deletes = {} } = {}) {
            if (!this.isServerMode) return null;
            this._emit(EVENT_SYNC_START, { type: 'bulk' });
            try {
                const r = await this._request('/api/sync/bulk', {
                    method: 'POST',
                    body: JSON.stringify({ global, scoped, deletes }),
                });
                this.lastSync = Date.now();
                lsSet(STORAGE_KEYS.lastSync, String(this.lastSync));
                return r;
            } finally {
                this._emit(EVENT_SYNC_END, { type: 'bulk' });
            }
        }

        async uploadImageCache(cacheKey, blob) {
            if (!this.isServerMode || !cacheKey || !blob) return null;
            if (blob.size > 16 * 1024 * 1024) {
                const e = new Error('图片缓存超过 16MB，已跳过服务器缓存');
                e.code = 'IMAGE_CACHE_TOO_LARGE';
                throw e;
            }
            const res = await this._rawRequest('/api/image-cache/' + encodeURIComponent(cacheKey), {
                method: 'PUT',
                headers: { 'Content-Type': blob.type || 'application/octet-stream' },
                body: blob,
            });
            const text = await res.text();
            try { return text ? JSON.parse(text) : { ok: true }; } catch (_) { return { ok: true }; }
        }

        async downloadImageCache(cacheKey) {
            if (!this.isServerMode || !cacheKey) return null;
            try {
                const res = await this._rawRequest('/api/image-cache/' + encodeURIComponent(cacheKey) + '?optional=1', {
                    method: 'GET',
                });
                if (res.status === 204) return null;
                const blob = await res.blob();
                return {
                    blob,
                    mimeType: res.headers.get('content-type') || blob.type || 'image/png',
                    size: Number(res.headers.get('content-length') || blob.size || 0),
                };
            } catch (e) {
                if (e.status === 404) return null;
                throw e;
            }
        }

        async wipeData() {
            if (!this.isServerMode) return null;
            return this._request('/api/sync/wipe', { method: 'DELETE' });
        }

        // ---------- Public library API ----------
        async libraryList(params = {}) {
            const qs = new URLSearchParams();
            for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') qs.set(k, v);
            const path = '/api/library' + (qs.toString() ? '?' + qs.toString() : '');
            return this._request(path);
        }
        async libraryTags() { return this._request('/api/library/tags'); }
        async libraryGet(uuid) { return this._request('/api/library/' + encodeURIComponent(uuid)); }
        async librarySubmit(payload) {
            return this._request('/api/library/submit', { method: 'POST', body: JSON.stringify(payload) });
        }
        async libraryMySubmissions() {
            return this._request('/api/library/my/submissions');
        }
        async libraryDeleteMine(uuid) {
            return this._request('/api/library/my/' + encodeURIComponent(uuid), { method: 'DELETE' });
        }

        // ---------- Announcements ----------
        async listAnnouncements() {
            if (!this.baseUrl) return { announcements: [] };
            try {
                return await this._request('/api/announcements');
            } catch (_) { return { announcements: [] }; }
        }

        // ---------- Admin API (admin only) ----------
        adminUsers(params = {}) {
            const qs = new URLSearchParams();
            for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') qs.set(k, v);
            return this._request('/api/admin/users' + (qs.toString() ? '?' + qs.toString() : ''));
        }
        adminUser(id) { return this._request('/api/admin/users/' + id); }
        adminCreateUser(payload) { return this._request('/api/admin/users', { method: 'POST', body: JSON.stringify(payload) }); }
        adminUpdateUser(id, patch) { return this._request('/api/admin/users/' + id, { method: 'PATCH', body: JSON.stringify(patch) }); }
        adminDeleteUser(id) { return this._request('/api/admin/users/' + id, { method: 'DELETE' }); }
        adminStats(range = '7d') { return this._request('/api/admin/stats?range=' + encodeURIComponent(range)); }
        adminAudit(params = {}) {
            const qs = new URLSearchParams();
            for (const [k, v] of Object.entries(params)) if (v) qs.set(k, v);
            return this._request('/api/admin/audit' + (qs.toString() ? '?' + qs.toString() : ''));
        }
        adminAnnouncements() { return this._request('/api/admin/announcements'); }
        adminCreateAnnouncement(payload) { return this._request('/api/admin/announcements', { method: 'POST', body: JSON.stringify(payload) }); }
        adminUpdateAnnouncement(id, patch) { return this._request('/api/admin/announcements/' + id, { method: 'PATCH', body: JSON.stringify(patch) }); }
        adminDeleteAnnouncement(id) { return this._request('/api/admin/announcements/' + id, { method: 'DELETE' }); }
        adminLibraryList(params = {}) {
            const qs = new URLSearchParams();
            for (const [k, v] of Object.entries(params)) if (v) qs.set(k, v);
            return this._request('/api/library/admin/list' + (qs.toString() ? '?' + qs.toString() : ''));
        }
        adminLibraryPending(params = {}) {
            const qs = new URLSearchParams();
            for (const [k, v] of Object.entries(params)) if (v) qs.set(k, v);
            return this._request('/api/library/admin/pending' + (qs.toString() ? '?' + qs.toString() : ''));
        }
        adminLibraryReview(id, status, note = '') {
            return this._request('/api/library/admin/review/' + id, { method: 'POST', body: JSON.stringify({ status, note }) });
        }
        adminLibraryPreview(id) { return this._request('/api/library/admin/card/' + id); }
        adminLibraryDelete(id) { return this._request('/api/library/admin/card/' + id, { method: 'DELETE' }); }
        adminApiUsage(params = {}) {
            const qs = new URLSearchParams();
            for (const [k, v] of Object.entries(params)) if (v) qs.set(k, v);
            return this._request('/api/admin/api-usage' + (qs.toString() ? '?' + qs.toString() : ''));
        }
        adminApiUsageSummary(range = '7d') {
            return this._request('/api/admin/api-usage/summary?range=' + encodeURIComponent(range));
        }
        adminMaintenanceOverview() {
            return this._request('/api/admin/maintenance/overview');
        }
        adminRebuildSyncHashes() {
            return this._request('/api/admin/maintenance/rebuild-sync-hashes', { method: 'POST' });
        }
        adminCleanupImageCacheTemp() {
            return this._request('/api/admin/maintenance/cleanup-image-cache-temp', { method: 'POST' });
        }
    }

    window.RPHubServerSync = new ServerSync();
})();
