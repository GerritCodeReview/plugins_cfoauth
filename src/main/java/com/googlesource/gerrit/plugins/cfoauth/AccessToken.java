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

import java.io.Serializable;
import java.util.Objects;

class AccessToken implements Serializable {

  private static final long serialVersionUID = 1L;

  private final UserInfo userInfo;
  private final String value;
  private final long expiresAt;

  /** Representation of an undefined access token, which
   * has no owner and no value.
   */
  public static final AccessToken UNDEFINED = new AccessToken();

  private AccessToken() {
    this("", "", "", 0);
  }

  /**
   * Creates an access token.
   *
   * @param value the raw value of the access token.
   * @param username the name of the token owner.
   * @param emailAddress the email address of the token owner.
   * @param expiresAt time to expiration of this tokens in seconds
   * since midnight January, 1st, 1970.
   */
  public AccessToken(String value, String username, String emailAddress,
      long expiresAt) {
    if (value == null) {
      throw new IllegalArgumentException("token value must not be null");
    }
    this.userInfo = new UserInfo(username, emailAddress);
    this.value = value;
    this.expiresAt = expiresAt;
  }

  /**
   * Returns the value of the access token.
   */
  public String getValue() {
    return value;
  }

  /**
   * Returns the timestamp when this token will expire in seconds
   * since midnight January, 1st, 1970.
   */
  public long getExpiresAt() {
    return expiresAt;
  }

  /**
   * Returns <code>true</code> if this token has already expired.
   */
  public boolean isExpired() {
    return System.currentTimeMillis() > expiresAt * 1000;
  }

  /**
   * Returns information about the token owner.
   */
  public UserInfo getUserInfo() {
    return userInfo;
  }

  /**
   * Returns the external id of the token owner.
   */
  public String getExternalId() {
    return userInfo.getExternalId();
  }

  /**
   * Returns the name of the token owner.
   */
  public String getUserName() {
    return userInfo.getUserName();
  }

  /**
   * Returns the email address of the token owner.
   */
  public String getEmailAddress() {
    return userInfo.getEmailAddress();
  }

  /**
   * Returns the display name of the token owner.
   */
  public String getDisplayName() {
    return userInfo.getDisplayName();
  }

  /**
   * Sets the display name of the token owner.
   *
   * @param displayName the display name of the token owner or
   * <code>null</code>. In that case {@link #getUserName()}
   * will be assigned.
   */
  public void setDisplayName(String displayName) {
    userInfo.setDisplayName(displayName);
  }

  @Override
  public String toString() {
    return "{'value':'" + value
        + "','externalId':'" + userInfo.getExternalId()
        + "','username':'" + userInfo.getUserName()
        + "','emailAddress':'" + userInfo.getEmailAddress()
        + "','displayName':'" + userInfo.getDisplayName()
        + "','expiresAt':" + expiresAt + "}";
  }

  @Override
  public int hashCode() {
    return Objects.hash(value, expiresAt, userInfo);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
        return true;
    }
    if (!(obj instanceof AccessToken)) {
      return false;
    }
    AccessToken accessToken = (AccessToken) obj;
    return value.equals(accessToken.value) &&
        expiresAt == accessToken.expiresAt &&
        userInfo.equals(accessToken.userInfo);
  }
}
