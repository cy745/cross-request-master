import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, test } from "node:test";
import axios from "axios";
import { YApiAuthService } from "../src/services/yapi/auth";
import { YApiAuthCache } from "../src/services/yapi/authCache";

type AxiosLike = {
  get: (...args: any[]) => Promise<any>;
  post: (...args: any[]) => Promise<any>;
};

const axiosLike = axios as unknown as AxiosLike;
const originalPost = axiosLike.post;

const TEST_BASE_URL = "https://yapi-ldap.test";
const TEST_EMAIL = "qiuqiu";
const TEST_PASSWORD = "secret123";

function createTempHome(): string {
  return mkdtempSync(path.join(tmpdir(), "yapi-auth-ldap-"));
}

function mockSetCookie(
  yapiToken: string,
  yapiUid: string = "1142",
  expiresInDays: number = 7,
): string[] {
  const expires = new Date(Date.now() + expiresInDays * 86400 * 1000).toUTCString();
  return [
    `_yapi_token=${yapiToken}; path=/; expires=${expires}; secure; httponly`,
    `_yapi_uid=${yapiUid}; path=/; expires=${expires}; secure; httponly`,
  ];
}

afterEach(() => {
  axiosLike.post = originalPost;
});

describe("YApiAuthService LDAP login", () => {
  test("loginByLdap POSTs to /api/user/login_by_ldap and saves session", async () => {
    const homeDir = createTempHome();
    const origHome = process.env.HOME;
    process.env.HOME = homeDir;

    const expectedToken = "ldap-jwt-token-abc123";
    axiosLike.post = async (url: string, data: any) => {
      assert.equal(url, `${TEST_BASE_URL}/api/user/login_by_ldap`);
      assert.deepEqual(data, { email: TEST_EMAIL, password: TEST_PASSWORD });
      return {
        headers: { "set-cookie": mockSetCookie(expectedToken, "42") },
      };
    };

    try {
      const service = new YApiAuthService(TEST_BASE_URL, TEST_EMAIL, TEST_PASSWORD, "error");
      const session = await service.loginByLdap();

      assert.equal(session.yapiToken, expectedToken);
      assert.equal(session.yapiUid, "42");

      // 验证 session 已写入缓存
      const cache = new YApiAuthCache(TEST_BASE_URL, "error");
      const cached = cache.loadSession();
      assert.equal(cached?.yapiToken, expectedToken);
    } finally {
      process.env.HOME = origHome;
    }
  });

  test("loginByLdap uses cached session when valid", async () => {
    const homeDir = createTempHome();
    const origHome = process.env.HOME;
    process.env.HOME = homeDir;

    // 预写入一个有效的 session
    const validToken = "cached-valid-token";
    const cache = new YApiAuthCache(TEST_BASE_URL, "error");
    cache.saveSession({
      yapiToken: validToken,
      yapiUid: "42",
      expiresAt: Date.now() + 86400 * 1000, // 1 天后过期
      updatedAt: Date.now(),
    });

    let postCount = 0;
    axiosLike.post = async () => {
      postCount += 1;
      return { headers: { "set-cookie": mockSetCookie("fresh-token") } };
    };

    try {
      const service = new YApiAuthService(TEST_BASE_URL, TEST_EMAIL, TEST_PASSWORD, "error");

      // 不 force，应该走缓存
      const session = await service.loginByLdap(false);
      assert.equal(session.yapiToken, validToken);
      assert.equal(postCount, 0, "不应发起网络请求");
    } finally {
      process.env.HOME = origHome;
    }
  });

  test("loginByLdap forces re-login when cached session is expired", async () => {
    const homeDir = createTempHome();
    const origHome = process.env.HOME;
    process.env.HOME = homeDir;

    // 预写入过期 session（1 小时前过期）
    const expiredToken = "expired-token";
    const cache = new YApiAuthCache(TEST_BASE_URL, "error");
    cache.saveSession({
      yapiToken: expiredToken,
      yapiUid: "42",
      expiresAt: Date.now() - 3600 * 1000,
      updatedAt: Date.now() - 86400 * 1000,
    });

    const freshToken = "fresh-ldap-token";
    axiosLike.post = async () => {
      return { headers: { "set-cookie": mockSetCookie(freshToken) } };
    };

    try {
      const service = new YApiAuthService(TEST_BASE_URL, TEST_EMAIL, TEST_PASSWORD, "error");
      const session = await service.loginByLdap(false);
      assert.equal(session.yapiToken, freshToken, "过期后应重新登录获取新 token");
    } finally {
      process.env.HOME = origHome;
    }
  });

  test("loginByLdap throws on error response from server", async () => {
    axiosLike.post = async () => {
      return {
        headers: {},
        data: { errcode: 40011, errmsg: "LDAP 认证失败" },
      };
    };

    const service = new YApiAuthService(TEST_BASE_URL, TEST_EMAIL, TEST_PASSWORD, "error");
    await assert.rejects(
      async () => await service.loginByLdap(true),
      /LDAP 认证失败/,
    );
  });

  test("loginByLdap throws when no _yapi_token in response", async () => {
    axiosLike.post = async () => {
      return {
        headers: { "set-cookie": ["_yapi_uid=42; path=/"] },
      };
    };

    const service = new YApiAuthService(TEST_BASE_URL, TEST_EMAIL, TEST_PASSWORD, "error");
    await assert.rejects(
      async () => await service.loginByLdap(true),
      /未返回 _yapi_token/,
    );
  });

  test("getCookieHeaderWithLogin with useLdap calls loginByLdap", async () => {
    const homeDir = createTempHome();
    const origHome = process.env.HOME;
    process.env.HOME = homeDir;

    const ldapToken = "ldap-via-getCookieHeader";
    axiosLike.post = async (url: string) => {
      assert.match(url, /\/api\/user\/login_by_ldap$/);
      return { headers: { "set-cookie": mockSetCookie(ldapToken, "42") } };
    };

    try {
      const service = new YApiAuthService(TEST_BASE_URL, TEST_EMAIL, TEST_PASSWORD, "error");
      const cookie = await service.getCookieHeaderWithLogin({ forceLogin: true, useLdap: true });

      assert.ok(cookie.includes(ldapToken), `Cookie 应包含 LDAP token: ${cookie}`);
      assert.ok(cookie.includes("_yapi_uid=42"), `Cookie 应包含 uid: ${cookie}`);
    } finally {
      process.env.HOME = origHome;
    }
  });

  test("loginByLdap caches session on successful login", async () => {
    const homeDir = createTempHome();
    const origHome = process.env.HOME;
    process.env.HOME = homeDir;

    const token = "should-be-cached";
    axiosLike.post = async () => {
      return { headers: { "set-cookie": mockSetCookie(token) } };
    };

    try {
      const service = new YApiAuthService(TEST_BASE_URL, TEST_EMAIL, TEST_PASSWORD, "error");
      await service.loginByLdap(true);

      // 第二次调用应使用缓存
      let postCount = 0;
      axiosLike.post = async () => {
        postCount += 1;
        return { headers: { "set-cookie": mockSetCookie("other-token") } };
      };

      const session = await service.loginByLdap(false);
      assert.equal(session.yapiToken, token, "应从缓存读取");
      assert.equal(postCount, 0);
    } finally {
      process.env.HOME = origHome;
    }
  });
});
