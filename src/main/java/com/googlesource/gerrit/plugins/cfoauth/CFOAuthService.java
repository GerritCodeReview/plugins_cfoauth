// Copyright (C) 2015 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.googlesource.gerrit.plugins.cfoauth;

import com.google.common.base.CharMatcher;
import com.google.gerrit.extensions.annotations.PluginName;
import com.google.gerrit.extensions.auth.oauth.OAuthLoginProvider;
import com.google.gerrit.extensions.auth.oauth.OAuthServiceProvider;
import com.google.gerrit.extensions.auth.oauth.OAuthToken;
import com.google.gerrit.extensions.auth.oauth.OAuthUserInfo;
import com.google.gerrit.extensions.auth.oauth.OAuthVerifier;
import com.google.gerrit.reviewdb.client.AccountExternalId;
import com.google.gerrit.server.config.AuthConfig;
import com.google.gerrit.server.config.CanonicalWebUrl;
import com.google.gerrit.server.config.PluginConfig;
import com.google.gerrit.server.config.PluginConfigFactory;
import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.Singleton;

import java.io.IOException;

@Singleton
class CFOAuthService implements OAuthServiceProvider, OAuthLoginProvider {

  private static final String OAUTH_VERSION = "2.0";
  private static final String NAME = "Cloud Foundry UAA OAuth2";

  private final UAAClient uaaClient;
  private final String providerId;

  @Inject
  CFOAuthService(PluginConfigFactory cfgFactory,
      AuthConfig authConfig,
      @PluginName String pluginName,
      @CanonicalWebUrl Provider<String> urlProvider) {
    PluginConfig cfg = cfgFactory.getFromGerritConfig(pluginName);
    String uaaServerUrl = CharMatcher.is('/')
        .trimTrailingFrom(cfg.getString(InitOAuthConfig.SERVER_URL));
    String redirectUrl = CharMatcher.is('/')
        .trimTrailingFrom(urlProvider.get()) + "/oauth";
    this.uaaClient = new UAAClient(uaaServerUrl,
        cfg.getString(InitOAuthConfig.CLIENT_ID),
        cfg.getString(InitOAuthConfig.CLIENT_SECRET),
        cfg.getBoolean(InitOAuthConfig.VERIFIY_SIGNATURES, true),
        authConfig.isUserNameToLowerCase(),
        redirectUrl);
    this.providerId = pluginName + ":" + OAuthModule.EXPORT_ID;
  }

  @Override
  public String getAuthorizationUrl() {
    return uaaClient.getAuthorizationUrl();
  }

  @Override
  public OAuthToken getAccessToken(OAuthVerifier rv) {
    if (rv == null || rv.getValue() == null) {
      throw new UAAClientException("Must provide an authorization code");
    }
    return getAsOAuthToken(uaaClient.getAccessToken(rv.getValue()));
  }

  @Override
  public OAuthUserInfo getUserInfo(OAuthToken token) throws IOException {
    if (token == null) {
      throw new UAAClientException("Must provide an access token");
    }
    return getAsOAuthUserInfo(uaaClient.toAccessToken(token.getToken()));
  }

  @Override
  public OAuthUserInfo login(String username, String secret)
      throws IOException {
    if (username == null || secret == null) {
      throw new IOException("Authentication error");
    }
    AccessToken accessToken;
    try {
      if (uaaClient.isAccessTokenForClient(username, secret)) {
        // "secret" is an access token for a client, i.e. a
        // technical user; send it to UAA for verification
        if (!uaaClient.verifyAccessToken(secret)) {
          throw new IOException("Authentication error");
        }
        return getAsOAuthUserInfo(username);
      } else {
        if (uaaClient.isAccessTokenForUser(username, secret)) {
          // "secret" is an access token for an ordinary user;
          // send it to UAA for verification
          if (!uaaClient.verifyAccessToken(secret)) {
            throw new IOException("Authentication error");
          }
          accessToken = uaaClient.toAccessToken(secret);
        } else {
          // "secret" is not an access token but likely a password;
          // send username and password to UAA and try to get an access
          // token; if that succeeds the user is authenticated
          accessToken = uaaClient.getAccessToken(username, secret);
        }
        return getAsOAuthUserInfo(accessToken);
      }
    } catch (UAAClientException e) {
      throw new IOException("Authentication error", e);
    }
  }

  @Override
  public String getVersion() {
    return OAUTH_VERSION;
  }

  @Override
  public String getName() {
    return NAME;
  }

  private OAuthToken getAsOAuthToken(AccessToken accessToken) {
    return new OAuthToken(accessToken.getValue(), null, null,
        accessToken.getExpiresAt() * 1000, providerId);
  }

  private OAuthUserInfo getAsOAuthUserInfo(AccessToken accessToken) {
    UserInfo userInfo = accessToken.getUserInfo();
    userInfo.setDisplayName(
        uaaClient.getDisplayName(accessToken.getValue()));
    return new OAuthUserInfo(userInfo.getExternalId(),
        userInfo.getUserName(), userInfo.getEmailAddress(),
        userInfo.getDisplayName(), null);
  }

  private static OAuthUserInfo getAsOAuthUserInfo(String username) {
    return new OAuthUserInfo(AccountExternalId.SCHEME_EXTERNAL + username,
        username, null, null, null);
  }
}
