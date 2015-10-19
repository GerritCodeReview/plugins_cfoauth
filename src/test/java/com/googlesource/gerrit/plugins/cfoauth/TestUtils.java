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

import static org.junit.Assert.assertEquals;

public class TestUtils {

  static final String FOO = "foo";
  static final String BAR = "bar";
  static final String MR_FOO = "Mr. Foo";
  static final String ANOTHER_FOO = "anotherfoo";
  static final String ANOTHER_BAR = "anotherbar";

  static void assertUserInfo(UserInfo userInfo, String username,
      String emailAddress, String displayName) {
    assertEquals(username, userInfo.getUserName());
    assertEquals(emailAddress, userInfo.getEmailAddress());
    if (displayName != null) {
      assertEquals(displayName, userInfo.getDisplayName());
    } else {
      assertEquals(username, userInfo.getDisplayName());
    }
  }

}
