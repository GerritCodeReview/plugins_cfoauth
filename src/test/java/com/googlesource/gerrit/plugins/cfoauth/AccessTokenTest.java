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

import static com.googlesource.gerrit.plugins.cfoauth.AccessToken.UNDEFINED;
import static com.googlesource.gerrit.plugins.cfoauth.TestUtils.*;
import static org.junit.Assert.*;

import org.junit.Test;

public class AccessTokenTest {

  private static final String TOKEN_VALUE = "tokenvalue";
  private static final String ANOTHER_TOKEN_VALUE = "anothertokenvalue";
  private static final long EXPIRES_AT = 4711L;

  private static final AccessToken TOKEN =
      new AccessToken(TOKEN_VALUE, FOO, BAR, EXPIRES_AT);
  private static AccessToken TOKEN_DIFFERENT_VALUE =
      new AccessToken(ANOTHER_TOKEN_VALUE, FOO, BAR, EXPIRES_AT);
  private static AccessToken TOKEN_DIFFERENT_NAME =
      new AccessToken(TOKEN_VALUE, ANOTHER_FOO, BAR, EXPIRES_AT);
  private static AccessToken TOKEN_DIFFERENT_EMAIL =
      new AccessToken(TOKEN_VALUE, FOO, ANOTHER_BAR, EXPIRES_AT);
  private static final AccessToken TOKEN_DIFFERENT_EXPIRES =
      new AccessToken(TOKEN_VALUE, FOO, BAR, EXPIRES_AT + 1);

  @Test
  public void testCreateAccessToken() throws Exception {
    assertAccessToken(TOKEN, FOO, BAR, null, TOKEN_VALUE, EXPIRES_AT);
  }

  @Test
  public void testUndefined() throws Exception {
    assertAccessToken(UNDEFINED, "", "", "", "", 0);
    assertTrue(UNDEFINED.isExpired());
  }

  @Test
  public void testExpiresAt() throws Exception {
    assertTrue(TOKEN.isExpired());
    assertFalse(new AccessToken(TOKEN_VALUE, FOO, BAR,
        System.currentTimeMillis() + 10).isExpired());
  }

  @Test
  public void testEquals() throws Exception {
    assertTrue(TOKEN.equals(TOKEN));
    assertFalse(TOKEN.equals(TOKEN_DIFFERENT_VALUE));
    assertFalse(TOKEN_DIFFERENT_VALUE.equals(TOKEN));
    assertFalse(TOKEN.equals(TOKEN_DIFFERENT_NAME));
    assertFalse(TOKEN_DIFFERENT_NAME.equals(TOKEN));
    assertFalse(TOKEN.equals(TOKEN_DIFFERENT_EMAIL));
    assertFalse(TOKEN_DIFFERENT_EXPIRES.equals(TOKEN));
    assertFalse(TOKEN.equals(TOKEN_DIFFERENT_EXPIRES));
    assertFalse(TOKEN.equals(null));
    assertFalse(TOKEN.equals(MR_FOO));
  }

  @Test(expected=IllegalArgumentException.class)
  public void testMissingValue() throws Exception {
    new AccessToken(null, FOO, BAR, EXPIRES_AT);
  }

  private void assertAccessToken(AccessToken accessToken, String username,
      String emailAddress, String displayName, String value, long expiresAt) {
    assertUserInfo(accessToken.getUserInfo(), username,
        emailAddress, displayName);
    assertEquals(value, accessToken.getValue());
    assertEquals(expiresAt, accessToken.getExpiresAt());
    assertTrue(accessToken.isExpired());
  }
}
