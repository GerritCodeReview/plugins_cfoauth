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
import com.google.gerrit.extensions.auth.oauth.OAuthServiceProvider;
import com.google.gerrit.extensions.auth.oauth.OAuthToken;
import com.google.gerrit.extensions.auth.oauth.OAuthUserInfo;
import com.google.gerrit.extensions.auth.oauth.OAuthVerifier;
import com.google.gerrit.server.config.CanonicalWebUrl;
import com.google.gerrit.server.config.PluginConfig;
import com.google.gerrit.server.config.PluginConfigFactory;
import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.Singleton;

import java.io.IOException;

@Singleton
class CFOAuthService implements OAuthServiceProvider {

  private static final String OAUTH_VERSION = "2.0";
  private static final String NAME = "Cloud Foundry UAA OAuth2";

  private final UAAClient uaaClient;

  @Inject
  CFOAuthService(PluginConfigFactory cfgFactory,
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
        redirectUrl);
  }

  @Override
  public String getAuthorizationUrl() {
    return uaaClient.getAuthorizationUrl();
  }

  @Override
  public OAuthToken getAccessToken(OAuthVerifier rv) {
    return getAsOAuthToken(uaaClient.getAccessToken(rv.getValue()));
  }

  @Override
  public OAuthUserInfo getUserInfo(OAuthToken token) throws IOException {
    AccessToken accessToken = uaaClient.toAccessToken(token.getToken());
    String displayName = uaaClient.getDisplayName(token.getToken());
    return getAsOAuthUserInfo(accessToken, displayName);
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
    return new OAuthToken(accessToken.getValue(), null, null);
  }

  private OAuthUserInfo getAsOAuthUserInfo(AccessToken accessToken,
      String displyName) {
    return new OAuthUserInfo(accessToken.getExternalId(),
        accessToken.getUserName(), accessToken.getEmailAddress(),
        displyName, null);
  }
}
