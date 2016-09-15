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
import com.google.gerrit.extensions.client.AuthType;
import com.google.gerrit.pgm.init.api.ConsoleUI;
import com.google.gerrit.pgm.init.api.InitFlags;
import com.google.gerrit.pgm.init.api.InitStep;
import com.google.gerrit.pgm.init.api.Section;
import com.google.inject.Inject;

class InitOAuthConfig implements InitStep {
  static final String PLUGIN_SECTION = "plugin";
  static final String SERVER_URL = "serverUrl";
  static final String CLIENT_ID = "clientId";
  static final String CLIENT_SECRET = "clientSecret";
  static final String VERIFIY_SIGNATURES = "verifySignatures";

  static final String DEFAULT_SERVER_URL = "http://localhost:8080/uaa";
  static final String DEFAULT_CLIENT_ID = "gerrit";

  private final InitFlags flags;
  private final ConsoleUI ui;
  private final Section cfg;
  private final String redirectUrl;

  @Inject
  InitOAuthConfig(InitFlags flags, ConsoleUI ui,
      Section.Factory sections,
      @PluginName String pluginName) {
    this.flags = flags;
    this.ui = ui;
    this.cfg = sections.get(PLUGIN_SECTION, pluginName);
    this.redirectUrl = getRedirectUrl(sections);
  }

  @Override
  public void run() throws Exception {
    AuthType authType =
        flags.cfg.getEnum(AuthType.values(), "auth", null, "type", null);
    if (authType != AuthType.OAUTH) {
      return;
    }
    ui.header("Cloud Foundry UAA OAuth 2.0 Authentication Provider");
    cfg.string("UAA server URL", SERVER_URL, DEFAULT_SERVER_URL);
    cfg.string("Client id", CLIENT_ID, DEFAULT_CLIENT_ID);
    cfg.passwordForKey("Client secret", CLIENT_SECRET);
    cfg.set(VERIFIY_SIGNATURES, Boolean.toString(
        ui.yesno(true, "Verify token signatures", VERIFIY_SIGNATURES)));
    flags.cfg.setString("auth", null, "logouturl", CharMatcher.is('/')
        .trimTrailingFrom(cfg.get(SERVER_URL)) + "/logout.do?redirect="
            + redirectUrl);
  }

  private static String getRedirectUrl(Section.Factory sections) {
    Section gerrit = sections.get("gerrit", null);
    return CharMatcher.is('/').trimTrailingFrom(gerrit.get("canonicalWebUrl"));
  }

  @Override
  public void postRun() throws Exception {
  }
}
