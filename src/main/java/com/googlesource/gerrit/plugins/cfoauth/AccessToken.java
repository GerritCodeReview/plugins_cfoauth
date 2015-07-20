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

import java.util.Objects;

class AccessToken {

  private final String value;

  private final String externalId;
  private final String username;
  private final String emailAddress;
  private final long expiresAt;

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
    if (username == null) {
      throw new IllegalArgumentException("username must not be null");
    }
    if (emailAddress == null) {
      throw new IllegalArgumentException("emailAddress must not be null");
    }
    this.value = value;
    this.username = username;
    this.externalId = AccountExternalId.SCHEME_EXTERNAL + username;
    this.emailAddress = emailAddress;
    this.expiresAt = expiresAt;
  }

  /**
   * Returns the value of the access token.
   */
  public String getValue() {
    return value;
  }

  /**
   * Returns the external id of the token owner.
   */
  public String getExternalId() {
    return externalId;
  }

  /**
   * Returns the name of the token owner.
   */
  public String getUserName() {
    return username;
  }

  /**
   * Returns the email address of the token owner.
   */
  public String getEmailAddress() {
    return emailAddress;
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

  @Override
  public String toString() {
    return "{'value':'" + value
        + "','externalId':'" + externalId
        + "','userName':'" + username
        + "','emailAddress':'" + emailAddress
        + "','expiresAt':" + expiresAt + "}";
  }

  @Override
  public int hashCode() {
    return value.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
        return true;
    }
    if (!(obj instanceof AccessToken)) {
      return false;
    }
    return Objects.equals(value, ((AccessToken) obj).value);
  }
}
