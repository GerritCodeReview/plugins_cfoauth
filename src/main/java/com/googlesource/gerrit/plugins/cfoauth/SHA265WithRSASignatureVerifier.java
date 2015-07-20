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

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.apache.commons.codec.binary.Base64.decodeBase64;
import static org.apache.commons.codec.binary.Base64.decodeInteger;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.text.MessageFormat;

class SHA265WithRSASignatureVerifier implements SignatureVerifier {

  private static final String RSA = "RSA";
  private static final String RS256 = "RS256";
  private static final String SHA265_WITH_RSA = "SHA256withRSA";

  private final RSAPublicKey publicKey;

  public SHA265WithRSASignatureVerifier(String modulus,
      String publicExponent) {
    RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(
        decodeInteger(modulus.getBytes(US_ASCII)),
        decodeInteger(publicExponent.getBytes(US_ASCII)));
    KeyFactory keyFactory = null;
    try {
      keyFactory = KeyFactory.getInstance(RSA);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(
          "Runtime does not support SHA256withRSA signatures", e);
    }
    try {
      this.publicKey = (RSAPublicKey)keyFactory.generatePublic(publicKeySpec);
    } catch (InvalidKeySpecException e) {
      throw new IllegalArgumentException(MessageFormat.format(
          "Invalid RSA public key specification: mod={1}, exp={2}",
          publicKeySpec.getModulus(),
          publicKeySpec.getPublicExponent()), e);
    }
  }

  @Override
  public boolean verify(String content, String signature) {
    Signature rsa = null;
    try {
      rsa = Signature.getInstance(SHA265_WITH_RSA);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(
          "Runtime does not support SHA256withRSA signatures", e);
    }
    try {
      rsa.initVerify(publicKey);
    } catch (InvalidKeyException e) {
      throw new IllegalArgumentException(MessageFormat.format(
          "Invalid public key: {0}", publicKey), e);
    }
    try {
      rsa.update(content.getBytes(US_ASCII));
      return rsa.verify(decodeBase64(signature.getBytes(US_ASCII)));
    } catch (SignatureException e) {
      throw new IllegalArgumentException(MessageFormat.format(
          "Invalid signature: {0}", signature), e);
    }
  }

  @Override
  public boolean supports(String algorithm) {
    return RS256.equalsIgnoreCase(algorithm)
        || SHA265_WITH_RSA.equalsIgnoreCase(algorithm);
  }

}
