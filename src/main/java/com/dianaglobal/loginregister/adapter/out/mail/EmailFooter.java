// src/main/java/com/dianaglobal/loginregister/adapter/out/mail/EmailFooter.java
package com.dianaglobal.loginregister.adapter.out.mail;

import java.time.Year;

/**
 * Utility class for generating consistent email footers across all email services.
 * This ensures uniform appearance and easy maintenance.
 */
public final class EmailFooter {

    private EmailFooter() {
        // Utility class - prevent instantiation
    }

    /**
     * Generates a standardized footer for emails.
     * Uses proper vertical alignment to prevent misalignment issues.
     * 
     * @return HTML footer string
     */
    public static String generate() {
        int year = Year.now().getValue();
        
        return """
            <div style="background:linear-gradient(135deg,#0a2239,#0e4b68);color:#fff;
                        padding:8px 18px;text-align:center;font-size:14px;line-height:1.2;">
              <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" style="border-collapse:collapse;">
                <tr>
                  <td style="text-align:center;vertical-align:middle;">
                    <span role="img" aria-label="lightning" 
                          style="color:#ffd200;font-size:18px;vertical-align:middle;margin-right:6px;">&#x26A1;&#xFE0E;</span>
                    <span style="vertical-align:middle;">© %d · Powered by <strong>AndesCore Software</strong></span>
                  </td>
                </tr>
              </table>
            </div>
            """.formatted(year);
    }

    /**
     * Generates a footer for table-based email layouts.
     * Use this for emails that use table structure.
     * 
     * @return HTML footer table row string
     */
    public static String generateTableRow() {
        int year = Year.now().getValue();
        
        return """
            <tr>
              <td style="padding:8px 18px;background:linear-gradient(135deg,#0a2239,#0e4b68);text-align:center;color:#ffffff;font-size:14px;line-height:1.2;">
                <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" style="border-collapse:collapse;">
                  <tr>
                    <td style="text-align:center;vertical-align:middle;">
                      <span role="img" aria-label="lightning" 
                            style="color:#ffd200;font-size:18px;vertical-align:middle;margin-right:6px;">&#x26A1;&#xFE0E;</span>
                      <span style="vertical-align:middle;">© %d · Powered by <strong>AndesCore Software</strong></span>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
            """.formatted(year);
    }
}
