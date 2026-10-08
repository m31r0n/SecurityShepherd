package servlets.module.challenge;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Locale;
import java.util.ResourceBundle;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.encoder.Encode;
import utils.Hash;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Failure to Restrict URL Access Challenge 2 (Admin) <br>
 * <br>
 * This class is the target functionality for the challenge. The information required to find this
 * admin function is contained in the javascript of the JSP page associated with the level. This
 * level returns a user specific key. <br>
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
public class UrlAccess2Admin extends HttpServlet {

  // Sql Challenge 4
  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(UrlAccess2Admin.class);
  private static String levelResult = "40b675e3d404c52b36abe31d05842b283975ec62e8";
  private static String levelName = "URL Access 2 (Admin)";

  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // Setting IpAddress To Log and taking header for original IP if forwarded from proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    HttpSession ses = request.getSession(true);

    // Translation Stuff
    Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
    ResourceBundle errors = ResourceBundle.getBundle("i18n.servlets.errors", locale);
    ResourceBundle bundle =
        ResourceBundle.getBundle("i18n.servlets.challenges.urlAccess.urlAccess2", locale);

    if (Validate.validateSession(ses)) {
      ShepherdLogManager.setRequestIp(
          request.getRemoteAddr(),
          request.getHeader("X-Forwarded-For"),
          ses.getAttribute("userName").toString());
      log.debug(levelName + " servlet accessed by: " + ses.getAttribute("userName").toString());
      PrintWriter out = response.getWriter();
      out.print(getServletInfo());
      String htmlOutput = new String();

      try {
        String userData = request.getParameter("adminData");
        // Authorisation check: this is an administrative function. Hiding it from the menu is not
        // access control, so the caller must hold this level's administrator role, which is only
        // ever granted server side. Unauthorised callers are refused.
        boolean levelAdmin = Boolean.TRUE.equals(ses.getAttribute("urlAccess2LevelAdmin"));
        if (!levelAdmin) {
          log.error("Unauthorised call to admin function by " + ses.getAttribute("userName"));
        }
        boolean tamperedRequest =
            !levelAdmin || !"youAreAnAdminOfAwesomenessWoopWoop".equalsIgnoreCase(userData);
        if (!tamperedRequest) {
          log.debug("No request tampering detected");
        } else {
          log.debug("User Submitted - " + userData);
        }

        if (!tamperedRequest) {
          String userKey =
              Hash.generateUserSolution(levelResult, (String) ses.getAttribute("userName"));
          htmlOutput =
              "<h2 class='title'>"
                  + bundle.getString("admin.clicked")
                  + "</h2>"
                  + "<p>"
                  + bundle.getString("admin.keyMessage.1")
                  + "<br /> "
                  + "<a>"
                  + userKey
                  + "</a><br />"
                  + bundle.getString("admin.keyMessage.2")
                  + "</p>";
        } else {
          htmlOutput =
              "<h2 class='title'>"
                  + bundle.getString("response.failure")
                  + "</h2>"
                  + "<p>"
                  + bundle.getString("response.failue.message")
                  + "</p>"
                  + "<!-- "
                  + Encode.forHtml(userData)
                  + " -->";
        }
      } catch (Exception e) {
        out.write(errors.getString("error.funky"));
        log.fatal(levelName + " - " + e.toString());
      }
      log.debug("Outputting HTML");
      out.write(htmlOutput);
    } else {
      log.error(levelName + " servlet accessed with no session");
    }
  }
}
