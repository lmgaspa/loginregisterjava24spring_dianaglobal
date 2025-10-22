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
                        padding:10px 18px;text-align:center;font-size:14px;line-height:1.4;">
              <span role="img" aria-label="lightning" 
                    style="color:#ffd200;font-size:16px;vertical-align:text-bottom;margin-right:4px;">&#x26A1;&#xFE0E;</span>
              <span style="vertical-align:text-bottom;">© %d · Powered by <strong>AndesCore Software</strong></span>
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
              <td style="padding:10px 18px;background:linear-gradient(135deg,#0a2239,#0e4b68);text-align:center;color:#ffffff;font-size:14px;line-height:1.4;">
                <span role="img" aria-label="lightning" 
                      style="color:#ffd200;font-size:16px;vertical-align:text-bottom;margin-right:4px;">&#x26A1;&#xFE0E;</span>
                <span style="vertical-align:text-bottom;">© %d · Powered by <strong>AndesCore Software</strong></span>
              </td>
            </tr>
            """.formatted(year);
    }
}
