package servlets.module.challenge;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Locale;
import java.util.ResourceBundle;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.encoder.Encode;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Bad Crypto Challenge Three Really bad crypto algorithm to break. Will reveal key if spaces are
 * submitted <br>
 * <br>
 * This file is part of the Security Shepherd Project.
 *
 * <p>The Security Shepherd project is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.<br>
 *
 * <p>The Security Shepherd project is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.<br>
 *
 * <p>You should have received a copy of the GNU General Public License along with the Security
 * Shepherd project. If not, see <http://www.gnu.org/licenses/>.
 *
 * @author Mark Denihan
 */
public class BrokenCrypto3 extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(BrokenCrypto3.class);
  private static String levelName = "Broken Crypto Challenge 3";
  public static String levelHash =
      "2da053b4afb1530a500120a49a14d422ea56705a7e3fc405a77bc269948ccae1";
  private static final int GCM_IV_LENGTH = 12;
  private static final int GCM_TAG_BITS = 128;
  private static final SecureRandom RANDOM = new SecureRandom();
  private static final SecretKey ENCRYPTION_KEY = generateKey();

  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // Setting IpAddress To Log and taking header for original IP if forwarded from proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));

    HttpSession ses = request.getSession(true);
    if (Validate.validateSession(ses)) {
      ShepherdLogManager.setRequestIp(
          request.getRemoteAddr(),
          request.getHeader("X-Forwarded-For"),
          ses.getAttribute("userName").toString());
      log.debug(levelName + " servlet accessed by: " + ses.getAttribute("userName").toString());
      String htmlOutput = new String();

      PrintWriter out = response.getWriter();
      out.print(getServletInfo());

      // Translation Stuff
      Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
      ResourceBundle errors = ResourceBundle.getBundle("i18n.servlets.errors", locale);
      ResourceBundle bundle =
          ResourceBundle.getBundle(
              "i18n.servlets.challenges.insecureCryptoStorage.insecureCryptoStorage", locale);
      try {
        String userData = request.getParameter("userData");
        log.debug("User Submitted - " + userData);

        log.debug("Decrypting user input");
        // Authenticated decryption with a server side key that is unrelated to the level result
        String decryptedUserData = decrypt(userData);
        log.debug("Decrypted to: " + decryptedUserData);

        htmlOutput =
            "<h2 class='title'>"
                + bundle.getString("insecureCryptoStorage.3.plaintextResult")
                + "</h2><p>"
                + bundle.getString("insecureCryptoStorage.3.plaintextResult.message")
                + "<br/><br/><em>"
                + Encode.forHtml(decryptedUserData)
                + "</em></p>";
      } catch (Exception e) {
        log.fatal(levelName + " - " + e.toString());
        htmlOutput = errors.getString("error.funky");
      }
      out.write(htmlOutput);
    } else {
      log.error(levelName + " servlet accessed with no session");
    }
  }

  /**
   * Encrypts the supplied plain text with AES-GCM using a randomly generated server side key. The
   * key is independent of the level result and never leaves the server.
   *
   * @param plainText Text to encrypt
   * @return Base64 encoded IV and authenticated cipher text
   * @throws Exception If encryption fails
   */
  public static String encrypt(String plainText) throws Exception {
    byte[] iv = new byte[GCM_IV_LENGTH];
    RANDOM.nextBytes(iv);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, ENCRYPTION_KEY, new GCMParameterSpec(GCM_TAG_BITS, iv));
    byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
    byte[] output = new byte[iv.length + cipherText.length];
    System.arraycopy(iv, 0, output, 0, iv.length);
    System.arraycopy(cipherText, 0, output, iv.length, cipherText.length);
    return Base64.getEncoder().encodeToString(output);
  }

  /**
   * Decrypts and authenticates the supplied cipher text. The previous home made repeating key XOR
   * cipher used the level result as its key, so submitting chosen cipher text revealed the key.
   * AES-GCM with a random server key provides confidentiality and rejects forged or tampered cipher
   * text instead of returning attacker controlled plain text.
   *
   * @param encoded Base64 encoded IV and cipher text
   * @return The plain text revealed from the decryption
   * @throws Exception If the cipher text is malformed or fails authentication
   */
  public static String decrypt(String encoded) throws Exception {
    if (encoded == null) {
      throw new IllegalArgumentException("No cipher text submitted");
    }
    byte[] input = Base64.getDecoder().decode(encoded.trim());
    if (input.length < GCM_IV_LENGTH + (GCM_TAG_BITS / 8)) {
      throw new IllegalArgumentException("Cipher text too short");
    }
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(
        Cipher.DECRYPT_MODE,
        ENCRYPTION_KEY,
        new GCMParameterSpec(GCM_TAG_BITS, input, 0, GCM_IV_LENGTH));
    byte[] plain = cipher.doFinal(input, GCM_IV_LENGTH, input.length - GCM_IV_LENGTH);
    return new String(plain, StandardCharsets.UTF_8);
  }

  private static SecretKey generateKey() {
    try {
      KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
      keyGenerator.init(256, RANDOM);
      return keyGenerator.generateKey();
    } catch (Exception e) {
      throw new IllegalStateException("Could not create encryption key", e);
    }
  }
}
