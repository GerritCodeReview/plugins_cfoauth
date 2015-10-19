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

import com.google.gerrit.reviewdb.client.AccountExternalId;

import java.io.Serializable;
import java.util.Objects;

class UserInfo implements Serializable {

  private static final long serialVersionUID = 1L;

  private final String externalId;
  private final String username;
  private final String emailAddress;
  private String displayName;

  /**
   * Creates a user info object.
   *
   * @param username the name of a resource owner.
   * @param emailAddress the email address of a resource owner.
   */
  UserInfo(String username, String emailAddress) {
    if (username == null) {
      throw new IllegalArgumentException("username must not be null");
    }
    if (emailAddress == null) {
      throw new IllegalArgumentException("emailAddress must not be null");
    }
    this.username = username;
    this.externalId = AccountExternalId.SCHEME_EXTERNAL + username;
    this.emailAddress = emailAddress;
    this.displayName = username;
  }

  /**
   * Creates a user info object.
   *
   * @param username the name of a resource owner.
   * @param emailAddress the email address of a resource owner.
   * @param displayName the display name of a resource owner or
   * <code>null</code>. In that case the {@link #getUserName()}
   * will be assigned.
   */
  UserInfo(String username, String emailAddress, String displayName) {
    this(username, emailAddress);
    setDisplayName(displayName);
  }

  /**
   * Returns the external id of the resource owner.
   */
  String getExternalId() {
    return externalId;
  }

  /**
   * Returns the name of the resource owner.
   */
  String getUserName() {
    return username;
  }

  /**
   * Returns the email address of the resource owner.
   */
  String getEmailAddress() {
    return emailAddress;
  }

  /**
   * Returns the display name of the resource owner.
   */
  String getDisplayName() {
    return displayName;
  }

  /**
   * Sets the display name of the resource owner.
   *
   * @param displayName the display name of a resource owner or
   * <code>null</code>. In that case {@link #getUserName()}
   * will be assigned.
   */
  void setDisplayName(String displayName) {
    this.displayName = displayName != null? displayName : username;
  }

  @Override
  public String toString() {
    return "{externalId':'" + externalId
        + "','username':'" + username
        + "','emailAddress':'" + emailAddress
        + "','displayName':'" + displayName + "'}";
  }

  @Override
  public int hashCode() {
    return Objects.hash(username, emailAddress);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
        return true;
    }
    if (!(obj instanceof UserInfo)) {
      return false;
    }
    UserInfo userInfo = (UserInfo) obj;
    return username.equals(userInfo.username) &&
        emailAddress.equals(userInfo.emailAddress);
  }
}
