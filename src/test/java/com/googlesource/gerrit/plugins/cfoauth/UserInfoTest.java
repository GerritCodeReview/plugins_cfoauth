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

import static com.googlesource.gerrit.plugins.cfoauth.TestUtils.*;
import static org.junit.Assert.*;

import org.junit.Test;

public class UserInfoTest {

  private static final UserInfo USER = new UserInfo(FOO, BAR);
  private static final UserInfo USER_DIFFERENT_NAME =
      new UserInfo(ANOTHER_FOO, BAR);
  private static final UserInfo USER_DIFFERENT_EMAIL =
      new UserInfo(FOO, ANOTHER_BAR);
  private static final UserInfo USER_DISPLAYNAME =
      new UserInfo(FOO, BAR, MR_FOO);

  @Test
  public void testCreateUserInfo() throws Exception {
    assertUserInfo(USER, FOO, BAR, null);
    assertUserInfo(USER_DISPLAYNAME, FOO, BAR, MR_FOO);
  }

  @Test
  public void testDisplayName() throws Exception {
    UserInfo userInfo = new UserInfo(FOO, BAR);
    assertUserInfo(userInfo, FOO, BAR, null);
    userInfo.setDisplayName(MR_FOO);
    assertUserInfo(userInfo, FOO, BAR, MR_FOO);
    userInfo.setDisplayName(null);
    assertUserInfo(userInfo, FOO, BAR, null);
  }

  @Test
  public void testEquals() throws Exception {
    assertTrue(USER.equals(USER));
    assertFalse(USER.equals(USER_DIFFERENT_NAME));
    assertFalse(USER_DIFFERENT_NAME.equals(USER));
    assertFalse(USER.equals(USER_DIFFERENT_EMAIL));
    assertFalse(USER_DIFFERENT_EMAIL.equals(USER));
    assertTrue(USER.equals(USER_DISPLAYNAME));
    assertTrue(USER_DISPLAYNAME.equals(USER));
    assertFalse(USER.equals(null));
    assertFalse(USER.equals(MR_FOO));
  }

  @Test(expected=IllegalArgumentException.class)
  public void testMissingUserName() throws Exception {
    new UserInfo(null, BAR);
  }

  @Test(expected=IllegalArgumentException.class)
  public void testMissingEmailAddress() throws Exception {
    new UserInfo(FOO, null);
  }

}
