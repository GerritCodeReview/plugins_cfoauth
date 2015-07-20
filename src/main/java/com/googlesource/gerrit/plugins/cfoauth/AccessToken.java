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

public class AccessToken implements Serializable {

  private static final long serialVersionUID = 826403042671440419L;

  private final String value;

  private final String externalId;
  private final String userName;
  private final String emailAddress;
  private final long expiresAt;

  /** Representation of an undefined access token, which
   * has no owner and no value.
   */
  public static final AccessToken UNDEFINED = new AccessToken();

  private AccessToken() {
    this(null, null, null, 0);
  }

  /**
   * Creates an access token.
   *
   * @param value the raw value of the access token.
   * @param userName the name of the token owner.
   * @param emailAddress the email address of the token owner.
   * @param expiresAt time to expiration of this tokens in seconds
   * since midnight January, 1st, 1970.
   */
  public AccessToken(String value, String userName, String emailAddress,
      long expiresAt) {
    this.externalId = "external:" + userName;
    this.userName = userName;
    this.emailAddress = emailAddress;
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
   * Returns the external id of the token owner.
   */
  public String getExternalId() {
    return externalId;
  }

  /**
   * Returns the name of the token owner.
   */
  public String getUserName() {
    return userName;
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
        + "','userName':'" + userName
        + "','emailAddress':'" + emailAddress
        + "','expiresAt':" + expiresAt + "}";
  }

  @Override
  public int hashCode() {
    return value.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (!(obj instanceof AccessToken)) return false;
    AccessToken other = (AccessToken) obj;
    if (value == null) {
      return other.value == null;
    }
    return value.equals(other.value);
  }
}
