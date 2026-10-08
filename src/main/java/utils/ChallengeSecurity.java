package utils;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.servlet.http.HttpSession;

/**
 * Small, dependency free helpers shared by the challenge servlets to enforce server side security
 * decisions (synchronizer tokens, session bound state and URL validation).
 *
 * <p>This file is part of the Security Shepherd Project.
 *
 * <p>The Security Shepherd project is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 */
public class ChallengeSecurity {

  private static final SecureRandom secureRandom = new SecureRandom();

  private ChallengeSecurity() {}

  /**
   * Generates an unpredictable token suitable for anti-CSRF nonces and password reset tokens.
   *
   * @return 64 hex characters of cryptographically secure randomness
   */
  public static String randomToken() {
    byte[] bytes = new byte[32];
    secureRandom.nextBytes(bytes);
    StringBuilder sb = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }

  /**
   * Returns the synchronizer token stored server side in the session under the supplied name,
   * creating one if the session does not hold one yet. The value never leaves the server in a
   * cookie, so a cross-site request cannot carry it automatically.
   *
   * @param ses The user's session
   * @param name The session attribute name of the token
   * @return The session bound token
   */
  public static String getOrCreateSessionNonce(HttpSession ses, String name) {
    Object current = ses.getAttribute(name);
    if (current == null || current.toString().isEmpty()) {
      String token = randomToken();
      ses.setAttribute(name, token);
      return token;
    }
    return current.toString();
  }

  /**
   * Checks a submitted synchronizer token against the one bound to the session. Missing, empty or
   * mismatching tokens are rejected.
   *
   * @param ses The user's session
   * @param name The session attribute name of the token
   * @param submitted The token submitted with the request
   * @return True only if the submitted token matches the session bound token
   */
  public static boolean isValidSessionNonce(HttpSession ses, String name, String submitted) {
    if (ses == null || submitted == null || submitted.isEmpty()) {
      return false;
    }
    Object expected = ses.getAttribute(name);
    if (expected == null || expected.toString().isEmpty()) {
      return false;
    }
    return constantTimeEquals(expected.toString(), submitted);
  }

  /**
   * Compares two strings in constant time.
   *
   * @param a First string
   * @param b Second string
   * @return True if both are non null and equal
   */
  public static boolean constantTimeEquals(String a, String b) {
    if (a == null || b == null) {
      return false;
    }
    return MessageDigest.isEqual(
        a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Validates that the supplied value is a well formed absolute http(s) URL with a host.
   *
   * @param candidate The user supplied URL
   * @return The normalised URL, or null if the value is not a safe http(s) URL
   */
  public static String safeHttpUrl(String candidate) {
    if (candidate == null) {
      return null;
    }
    try {
      URI uri = new URI(candidate.trim());
      String scheme = uri.getScheme();
      if (scheme != null
          && (scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))
          && uri.getHost() != null
          && !uri.getHost().isEmpty()) {
        return uri.toASCIIString();
      }
    } catch (URISyntaxException e) {
      // Not a valid URL
    }
    return null;
  }
}
