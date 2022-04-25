# Exam MS-220: Troubleshooting Microsoft Exchange Online – Skills Measured

## Table of Contents

* [Troubleshoot mail flow issues (20–25%)](#_Toc101652758)
* [Troubleshoot compliance and retention issues (25–30%)](#_Toc101652763)
* [Troubleshoot mail client issues (20–25%)](#_Toc101652769)
* [Troubleshoot Exchange Online configuration issues (15–20%)](#_Toc101652774)
* [Troubleshoot hybrid and migration issues (10–15%)](#_Toc101652779)

## Troubleshoot mail flow issues (20–25%)

### Troubleshoot Exchange Online mail flow issues

* review and interpret message headers  
  * [View internet message headers in Outlook (microsoft.com)](https://support.microsoft.com/en-us/office/view-internet-message-headers-in-outlook-cd039382-dc6e-4264-ac74-c048563d212c)  
  * [Anti-spam message headers  * Office 365 | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spam-message-headers?view=o365-worldwide)  
* review and interpret message trace results and policies associated with those results  
  * [Run a message trace and view the results in the Exchange admin center in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/monitoring/trace-an-email-message/run-a-message-trace-and-view-results)  
  * [Message trace in the modern EAC in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/monitoring/trace-an-email-message/message-trace-modern-eac)  
  * [Message Trace FAQ in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/monitoring/trace-an-email-message/message-trace-faq)  
* determine whether a transport rule or conditional routing rule is affecting mail flow  
  * [Which mail flow rule (also known as a transport rule) or DLP policy was applied to a message?](https://docs.microsoft.com/en-us/exchange/monitoring/trace-an-email-message/message-trace-faq#which-mail-flow-rule-also-known-as-a-transport-rule-or-dlp-policy-was-applied-to-a-message)  
  * [Scenario Conditional mail routing in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/conditional-mail-routing)  
* identify rules that are evaluated and policies that are applied when sending or receiving email
  * [Test a mail flow rule in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/test-mail-flow-rules)  
* troubleshoot issues where users cannot send or receive email and no NDR is generated or displayed  
  * [Find and fix email delivery issues as an Office 365 for business admin  * Exchange | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/troubleshoot/email-delivery/email-delivery-issues)  
  * [Delivery receipts aren&#39;t created  * Exchange | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/troubleshoot/email-delivery/delivery-receipts-are-not-generated)  

* troubleshoot issues where mail destined for one tenant is incorrectly routed to another tenant  
  * [Troubleshooting mail sent to Microsoft 365  * Office 365 | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/troubleshooting-mail-sent-to-office-365?view=o365-worldwide)  
  * [Set up connectors for secure mail flow with a partner organization in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/set-up-connectors-for-secure-mail-flow-with-a-partner)  

* troubleshoot delivery delays  
  * [Mail delivery issues  * Exchange | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/troubleshoot/email-delivery/mail-issues)  

#### Troubleshoot mail flow issues with external systems  

* read and analyze SMTP protocol logs for hybrid deployments and third-party systems  
  * [Protocol logging | Microsoft Docs](https://docs.microsoft.com/en-us/Exchange/mail-flow/connectors/protocol-logging?view=exchserver-2019)
* troubleshoot issues related to mail flow for hybrid deployments  
  * [Transport routing in Exchange hybrid deployments | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/transport-routing)
  * [Demystifying and troubleshooting hybrid mail flow: when is a message internal?  * Microsoft Tech Community](https://techcommunity.microsoft.com/t5/exchange-team-blog/demystifying-and-troubleshooting-hybrid-mail-flow-when-is-a/ba-p/1420838)
* troubleshoot DNS-related mail flow issues  
  * [Mail flow best practices for Exchange Online, Microsoft 365, and Office 365 (overview) | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/mail-flow-best-practices/mail-flow-best-practices#understanding-how-dns-records-control-mail-flow)
* troubleshoot SMTP relay issues  
  * [How to set up a multifunction device or application to send email using Microsoft 365 or Office 365 | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/mail-flow-best-practices/how-to-set-up-a-multifunction-device-or-application-to-send-email-using-microsoft-365-or-office-365)
  * [Fix issues with printers, scanners, and LOB applications that send email using Microsoft 365 or Office 365 | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/mail-flow-best-practices/fix-issues-with-printers-scanners-and-lob-applications-that-send-email-using-off)
* troubleshoot SMTP certificate issues  
  * [Set up connectors for secure mail flow with a partner organization in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/set-up-connectors-for-secure-mail-flow-with-a-partner)
  * [How Exchange Online uses TLS to secure email connections  * Microsoft Purview | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/exchange-online-uses-tls-to-secure-email-connections?view=o365-worldwide)

### Troubleshoot other mail flow issues

* identify types of NDRs and interpret NDR data  
  * [Email non-delivery reports in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/mail-flow-best-practices/non-delivery-reports-in-exchange-online/non-delivery-reports-in-exchange-online)
* determine which active rules impact email attachments  
  * [Use mail flow rules to inspect message attachments in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/inspect-message-attachments#:~:text=Mail%20flow%20rules%20allow%20you%20to%20examine%20email,you%20can%20do%20by%20using%20mail%20flow%20rules%3A)
* determine which rules are triggered when an email arrives at a user's inbox  
  * [Mail flow rule procedures in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/mail-flow-rule-procedures)
  * [Message Trace FAQ in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/monitoring/trace-an-email-message/message-trace-faq)
* troubleshoot issues related to blocked attachment types  
  * [Common attachment blocking scenarios for mail flow rules in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/common-attachment-blocking-scenarios)
* troubleshoot issues with corrupted inbox rules  
  * [Delete junk email rules by using MFCMAPI  * Exchange | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/troubleshoot/administration/delete-junk-email-rules-mfcmapi-exchange)
  * [The rules on this computer do not match the rules on Microsoft Exchange](https://support.microsoft.com/en-us/office/the-rules-on-this-computer-do-not-match-the-rules-on-microsoft-exchange-d032e037-b224-429e-b325-633afde9b5f0?ui=en-us&amp;rs=en-us&amp;ad=us)

### Troubleshoot issues reported by Microsoft Defender for Office 365

* determine why an email is marked as spam**
  * [Anti-spam protection  * Office 365 | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spam-protection?view=o365-worldwide)
  * [Anti-spam message headers  * Office 365 | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spam-message-headers?view=o365-worldwide)
* determine why messages are being quarantined**
  * [Find and release quarantined messages as a user  * Office 365 | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/find-and-release-quarantined-messages-as-a-user?view=o365-worldwide)
  * [Manage quarantined messages and files as an admin  * Office 365 | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/manage-quarantined-messages-and-files?view=o365-worldwide)
* determine whether the sender SPF DMARC and DKIM records are valid**
  * [Email authentication in Microsoft 365  * Office 365 | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/email-validation-and-authentication?view=o365-worldwide)
  * [How Sender Policy Framework (SPF) prevents spoofing  * Office 365 | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/how-office-365-uses-spf-to-prevent-spoofing?view=o365-worldwide#SPFTroubleshoot)
  * [How to use DKIM for email in your custom domain  * Office 365 | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/use-dkim-to-validate-outbound-email?view=o365-worldwide)
  * [Use DMARC to validate email, setup steps  * Office 365 | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/use-dmarc-to-validate-email?view=o365-worldwide)
* troubleshoot spam filter policies**
  * [Configure spam filter policies  * Office 365 | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/configure-your-spam-filter-policies?view=o365-worldwide)
* troubleshoot messages that are categorized as false positive or false negative**
  * [Was a message marked as spam?](https://docs.microsoft.com/en-us/exchange/monitoring/trace-an-email-message/message-trace-faq#was-a-message-marked-as-spam)

## Troubleshoot compliance and retention issues (25–30%)

### Troubleshoot compliance issues

* identify roles required to perform eDiscovery actions
  * [Assign eDiscovery permissions in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/security-and-compliance/in-place-ediscovery/assign-ediscovery-permissions)
  * [Assign eDiscovery permissions in Exchange Server | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/policy-and-compliance/ediscovery/assign-permissions?view=exchserver-2019)
* describe Compliance center retention policies**
  * [Learn about retention policies &amp; labels to automatically retain or delete content  * Microsoft Purview | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/retention?view=o365-worldwide)
  * [Learn about retention for Exchange  * Microsoft Purview | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/retention-policies-exchange?view=o365-worldwide)
* troubleshoot eDiscovery issues**
  * [Microsoft Purview eDiscovery solutions  * Microsoft Purview | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/ediscovery?view=o365-worldwide)
* determine what types of holds are associated with an item**
  * [How to identify the hold on an Exchange Online mailbox  * Microsoft Purview | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/identify-a-hold-on-an-exchange-online-mailbox?view=o365-worldwide)
* troubleshoot in-place and eDiscovery holds**
  * [Increase the Recoverable Items quota for mailboxes on hold  * Microsoft Purview | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/increase-the-recoverable-quota-for-mailboxes-on-hold?view=o365-worldwide)
* search for and delete email messages in an organization**
  * [Delete items in the Recoverable Items folder  * Microsoft Purview | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/delete-items-in-the-recoverable-items-folder-of-mailboxes-on-hold?view=o365-worldwide)
* determine how to clear or purge recoverable item folders**
  * [Delete items in the Recoverable Items folder  * Microsoft Purview | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/delete-items-in-the-recoverable-items-folder-of-mailboxes-on-hold?view=o365-worldwide)

### Troubleshoot retention issues

* describe retention tag types and actions  
  * [Retention tags and retention policies in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/security-and-compliance/messaging-records-management/retention-tags-and-policies)
* describe the process for calculating item retention age**
  * [How retention age is calculated in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/security-and-compliance/messaging-records-management/retention-age)
* troubleshoot issues creating and applying retention policies**
  * [Create a Retention Policy in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/security-and-compliance/messaging-records-management/create-a-retention-policy)
  * [Apply a retention policy to mailboxes in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/security-and-compliance/messaging-records-management/apply-retention-policy)
* review and interpret Messaging Records Management (MRM) mailbox diagnostics logs**
  * [Messaging records management errors and events: Exchange 2013 Help | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/messaging-records-management-errors-and-events-exchange-2013-help)
* interpret message properties used by message records management (MRM)**
  * [Messaging Records Management (MRM) and Retention Policies in Office 365.  * Office 365 | Microsoft Docs](https://docs.microsoft.com/en-us/office365/troubleshoot/retention/mrm-and-retention-policy)

### Troubleshoot Office Message Encryption (OME) and S/Mime issues

* troubleshoot issues with messages that are not encrypted or decrypted as expected**
  * [Message encryption FAQ | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/ome-faq?view=o365-worldwide)
  * [Message encryption version comparison  * Microsoft Purview | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/ome-version-comparison?view=o365-worldwide)

* troubleshoot issues where external users cannot decrypt messages but internal users can decrypt messages**
  * [Email encryption in Microsoft 365  * Microsoft Purview | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/email-encryption?view=o365-worldwide)
  * [Exchange Online mail encryption with AD RMS  * Microsoft Purview | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/information-rights-management-in-exchange-online?view=o365-worldwide)
  * [S/MIME for message signing and encryption | Microsoft Docs](https://docs.microsoft.com/en-us/Exchange/policy-and-compliance/smime/smime?view=exchserver-2019)

* troubleshoot issues reading, replying to, or forwarding protected messages from Microsoft 365 on mobile devices  
  * [Manage Office 365 Message Encryption  * Microsoft Purview | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/manage-office-365-message-encryption?view=o365-worldwide#enable-service-side-decryption-of-email-messages-for-ios-mail-app-users)
  * [Message encryption FAQ | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/ome-faq?view=o365-worldwide)

* troubleshoot mail flow rules  
  * [Define mail flow rules to encrypt email messages  * Microsoft Purview | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/define-mail-flow-rules-to-encrypt-email?view=o365-worldwide)

* troubleshoot revocation issues for encrypted emails  
  * [Revoke email encrypted by Advanced Message Encryption  * Microsoft Purview | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/revoke-ome-encrypted-mail?view=o365-worldwide)
  * [Set an expiration date for email encrypted by Microsoft Purview Advanced Message Encryption  * Microsoft Purview | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/ome-advanced-expiration?view=o365-worldwide)

* troubleshoot S/Mime issues  
  * [S/MIME in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/security-and-compliance/smime-exo/smime-exo)

-

### Troubleshoot mailbox auditing Issues

* troubleshoot issues searching audit logs  
  * [Manage mailbox auditing  * Microsoft Purview | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/enable-mailbox-auditing?view=o365-worldwide)
  * [Search the audit log in the Microsoft Purview compliance portal  * Microsoft Purview | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/search-the-audit-log-in-security-and-compliance?view=o365-worldwide)
  * [Search the audit log to troubleshoot common scenarios  * Microsoft Purview | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/auditing-troubleshooting-scenarios?view=o365-worldwide)
* troubleshoot user actions (for example user reports an item is deleted but they say they did not delete)**
  * [Search the audit log to troubleshoot common scenarios  * Microsoft Purview | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/auditing-troubleshooting-scenarios?view=o365-worldwide#determine-if-a-user-deleted-email-items)
* troubleshoot bulk actions including email creation, moves, modifications, and deletion**
  * [Detailed properties in the audit log  * Microsoft Purview | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/detailed-properties-in-the-office-365-audit-log?view=o365-worldwide)
* track non-owner actions  
  * [Search the audit log to troubleshoot common scenarios  * Microsoft Purview | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/auditing-troubleshooting-scenarios?view=o365-worldwide)
* troubleshoot audit log retention period issue 
  * [Manage audit log retention policies  * Microsoft Purview | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/audit-log-retention-policies?view=o365-worldwide)
* troubleshoot auditing not working  
  * [Microsoft Purview auditing solutions  * Microsoft Purview | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/auditing-solutions-overview?view=o365-worldwide)  

### Troubleshoot journaling

* troubleshoot duplicate journal entries  
  * [Journaling in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/security-and-compliance/journaling/journaling#troubleshooting)
* troubleshoot mail not being journaled  
  * [Manage journaling in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/security-and-compliance/journaling/manage-journaling)
* troubleshoot journal OME decryption issues  
  * [Office 365 Message Encryption  * Microsoft Purview | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/ome?view=o365-worldwide)
  * [Journal report decryption: Exchange 2013 Help | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/journal-report-decryption-exchange-2013-help)

# Troubleshoot mail client issues (20–25%)

### Troubleshoot connectivity and authentication issues

**describe how to obtain Outlook client configuration information**

  * [Autodiscover for Exchange | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/client-developer/exchange-web-services/autodiscover-for-exchange)
**troubleshoot Exchange authentication policies**
  * [Disable Basic authentication in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/disable-basic-authentication-in-exchange-online)
**troubleshoot client access rules**
  * [Procedures for Client Access Rules in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/client-access-rules/procedures-for-client-access-rules)
**troubleshoot issues with modern authentication**
  * [Enable or disable modern authentication for Outlook in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/enable-or-disable-modern-authentication-in-exchange-online)
  * [How modern authentication works for Office 2013 and Office 2016 client apps  * Microsoft 365 Enterprise | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/enterprise/modern-auth-for-office-2013-and-2016?view=o365-worldwide)
  * [Remote Connectivity Analyzer tests for Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/remote-connectivity-analyzer-tests)
**troubleshoot Outlook on the Web (OWA) sign in issues**
  * [Listing some issues for Exchange Online  * Exchange | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/troubleshoot/exchange-online-welcome)
  * [Remote Connectivity Analyzer tests for Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/remote-connectivity-analyzer-tests)
**troubleshoot auto-discover issues**
  * [Listing some issues for Exchange Online  * Exchange | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/troubleshoot/exchange-online-welcome)
  * [Remote Connectivity Analyzer tests for Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/remote-connectivity-analyzer-tests)
**outlook client cannot connect to Exchange Online mailbox**
  * [Fix Outlook connection problems in Microsoft 365  * Exchange | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/troubleshoot/outlook-issues/outlook-connection-issues)
  * [Remote Connectivity Analyzer tests for Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/remote-connectivity-analyzer-tests)
**troubleshoot Outlook continuously asking for Exchange Online password**
  * [Outlook continually prompts for password when you try to connect to Office 365  * Outlook | Microsoft Docs](https://docs.microsoft.com/en-us/outlook/troubleshoot/authentication/continually-prompts-password-office-365)

-

### Troubleshoot calendaring Issues

**review and analyze mailbox and calendar diagnostic logs**

  * [Get-CalendarDiagnosticLog (ExchangePowerShell) | Microsoft Docs](https://docs.microsoft.com/en-us/powershell/module/exchange/get-calendardiagnosticlog?view=exchange-ps#:~:text=The%20Calendar%20Diagnostic%20logs%20track%20all%20calendar%20items,the%20Syntax%20section%20below%2C%20see%20Exchange%20cmdlet%20syntax.)
**troubleshoot broken manager/delegation issues**
  * [Overview of delegation in an Office 365 hybrid environment  * Exchange | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/troubleshoot/send-emails/overview-delegation-office-365-hybrid)
  * [Delegate can&#39;t send on behalf of after migration  * Exchange | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/troubleshoot/send-emails/delegate-cannot-send-on-behalf-of-after-migration)
  * [Delegates not listed correctly after migration  * Exchange | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/troubleshoot/send-emails/delegates-not-listed-correctly-in-outlook-after-migration)
**troubleshoot Resource Booking Assistant issues**
  * [Manage resource mailboxes in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/recipients-in-exchange-online/manage-resource-mailboxes)

### Troubleshoot calendar sharing issues

 * troubleshoot permissions issues related to calendar sharing
  * [Share calendar and contacts in Microsoft 365  * Outlook | Microsoft Docs](https://docs.microsoft.com/en-us/outlook/troubleshoot/calendaring/how-to-share-calendar-and-contacts)
 * troubleshoot issues publishing and accessing calendars shared with external users
  * [Share calendars with external users  * Microsoft 365 admin | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/admin/manage/share-calendars-with-external-users?view=o365-worldwide)
  * [Calendar sharing in Microsoft 365](https://support.microsoft.com/en-us/office/calendar-sharing-in-microsoft-365-b576ecc3-0945-4d75-85f1-5efafb8a37b4)
 * determine why content for a published calendar is not up to date
  * [Calendar sharing in Microsoft 365](https://support.microsoft.com/en-us/office/calendar-sharing-in-microsoft-365-b576ecc3-0945-4d75-85f1-5efafb8a37b4)

-

### Troubleshoot issues with mobile devices

 * identify mobile device access states and what the states indicate
  * [Controlling Exchange ActiveSync device access using the Allow/Block/Quarantine list  * Microsoft Tech Community](https://techcommunity.microsoft.com/t5/exchange-team-blog/controlling-exchange-activesync-device-access-using-the-allow/ba-p/588930)
  * [deviceManagementExchangeAccessStateReason enum type  * Microsoft Graph v1.0 | Microsoft Docs](https://docs.microsoft.com/en-us/graph/api/resources/intune-devices-devicemanagementexchangeaccessstatereason?view=graph-rest-1.0)
 * review mobile devices statistics to confirm the reason for a block
  * [Get-ActiveSyncDeviceStatistics (ExchangePowerShell) | Microsoft Docs](https://docs.microsoft.com/en-us/powershell/module/exchange/get-activesyncdevicestatistics?view=exchange-ps)
  * [Get-MobileDeviceStatistics (ExchangePowerShell) | Microsoft Docs](https://docs.microsoft.com/en-us/powershell/module/exchange/get-mobiledevicestatistics?view=exchange-ps)
 * review the Allow Blocked Quarantine (ABQ) list to identify blocked or quarantined devices
  * [Mobile devices not quarantined as expected  * Exchange | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/troubleshoot/mobile-devices/mobile-devices-not-quarantined-as-expected)
 * troubleshoot Exchange device access rules
  * [Client Access Rules in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/client-access-rules/client-access-rules)
  * [Procedures for Client Access Rules in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/client-access-rules/procedures-for-client-access-rules)
 * review and interpret ActiveSync logs to troubleshoot Outlook Sync EAS connection issues
  * [Collect ActiveSync device logs to troubleshoot sync issues for mobile devices  * Exchange | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/troubleshoot/mobile-devices/issues-for-mobile-devices)
 * troubleshoot connectivity issues with native ActiveSync
  * [Troubleshoot ActiveSync with Exchange Server  * Exchange | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/troubleshoot/client-connectivity/troubleshoot-activesync-with-exchange-server)
  * [Current issues with Microsoft Exchange ActiveSync and third-party devices](https://support.microsoft.com/en-us/topic/current-issues-with-microsoft-exchange-activesync-and-third-party-devices-53a1ffbe-504c-a424-012a-cb4456e94ba9)

-

# Troubleshoot Exchange Online configuration issues (15–20%)

### Troubleshoot provisioning issues

**interpret and troubleshoot validation errors encountered during object provisioning**

  * [Azure AD Connect: Troubleshoot errors during synchronization | Microsoft Docs](https://docs.microsoft.com/en-us/azure/active-directory/hybrid/tshoot-connect-sync-errors)
**determine when to restore or recover an inactive mailbox**
  * [Learn about inactive mailboxes  * Microsoft Purview | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/inactive-mailboxes-in-office-365?view=o365-worldwide)
  * [Restore an inactive mailbox  * Microsoft Purview | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/restore-an-inactive-mailbox?view=o365-worldwide)
  * [Recover an inactive mailbox  * Microsoft Purview | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/recover-an-inactive-mailbox?view=o365-worldwide)
**troubleshoot issues managing resource mailboxes**
  * [Room and equipment mailboxes  * Microsoft 365 admin | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/admin/manage/room-and-equipment-mailboxes?view=o365-worldwide)
**troubleshoot issues purging deleted users**
  * [Restore or permanently remove recently deleted user  * Azure AD | Microsoft Docs](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-users-restore)
  * [Delete an inactive mailbox  * Microsoft Purview | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/delete-an-inactive-mailbox?view=o365-worldwide)

-

### Troubleshoot recipient issues

**troubleshoot automatic email forwarding**

  * [Configure email forwarding  * Microsoft 365 admin | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/admin/email/configure-email-forwarding?view=o365-worldwide)
  * [Configuring and controlling external email forwarding in Microsoft 365.  * Office 365 | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/external-email-forwarding?view=o365-worldwide)
**troubleshoot matching issues with Azure AD**
  * [Azure AD Connect: When you already have Azure AD | Microsoft Docs](https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-install-existing-tenant)
 * Older article explaining the principle &amp; mechanics: [Azure Active Directory Synchronization: Object Matching  * Dave Stork&#39;s IMHO (dirteam.com)](https://dirteam.com/dave/2015/04/15/azure-active-directory-synchronization-object-matching/)
**troubleshoot distribution list membership issues (including dynamic distribution groups)**
  * [Create and manage distribution groups in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/recipients-in-exchange-online/manage-distribution-groups/manage-distribution-groups)
  * [View members of a dynamic distribution group in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/recipients-in-exchange-online/manage-dynamic-distribution-groups/view-group-members)
**troubleshoot issues with archive mailboxes including auto-expanding archive mailboxes**
  * [Exchange Online Archiving service description  * Service Descriptions | Microsoft Docs](https://docs.microsoft.com/en-us/office365/servicedescriptions/exchange-online-archiving-service-description/exchange-online-archiving-service-description)

-

### Troubleshoot org-wide settings

**troubleshoot domain setup and configuration issues**

  * [Add a domain to Microsoft 365  * Microsoft 365 admin | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/admin/setup/add-domain?view=o365-worldwide)
  * [Find and fix issues after adding your domain or DNS records  * Microsoft 365 admin | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/admin/get-help-with-domains/find-and-fix-issues?view=o365-worldwide)
**troubleshoot address book policies**
  * [Address book policies in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/address-books/address-book-policies/address-book-policies)
  * [Address book policy procedures in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/address-books/address-book-policies/address-book-policy-procedures)
**troubleshoot address lists**
  * [Address lists in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/address-books/address-lists/address-lists)
  * [Address list procedures in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/address-books/address-lists/address-list-procedures)
**troubleshoot allowed file types**
  * [Reduce malware threats via file attachment blocking  * Exchange | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/troubleshoot/antispam-and-protection/how-to-reduce-malware-threats-via-file-attachment-blocking)
  * [Use transport rules to inspect message attachments: Exchange 2013 Help | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/use-transport-rules-to-inspect-message-attachments-exchange-2013-help)
**troubleshoot mailbox plans**
  * [Mailbox plans in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/recipients-in-exchange-online/manage-user-mailboxes/mailbox-plans)
**troubleshoot Client-Access Services (CAS) mailbox plans**
  * [Get-CASMailboxPlan (ExchangePowerShell) | Microsoft Docs](https://docs.microsoft.com/en-us/powershell/module/exchange/get-casmailboxplan?view=exchange-ps)

### Troubleshoot public folder Issues

**troubleshoot Exchange Online access to public folders**

  * [Public folders in Microsoft 365, Office 365, and Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/collaboration-exo/public-folders/public-folders)
  * [Public folder procedures in Microsoft 365, Office 365, and Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/collaboration-exo/public-folders/public-folder-procedures)
**troubleshoot mail-enabled public folders**
  * [Mail-enable or mail-disable a public folder in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/collaboration-exo/public-folders/enable-or-disable-mail-for-public-folder)
**troubleshoot issues sending email to public folders**
  * [Assign &quot;Send As&quot; or &quot;Send on Behalf&quot; permissions for mail-enabled public folders in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/collaboration-exo/public-folders/assign-permissions-mail-enabled-pfs)
**troubleshoot hybrid access to public folders**
  * [Configure Exchange Server public folders for a hybrid deployment | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/hybrid-deployment/set-up-modern-hybrid-public-folders)
  * [Exchange Online: Configure public folders for a hybrid deployment | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/hybrid-deployment/set-up-exo-hybrid-public-folders)
**troubleshoot load-balancing issues for public folders**
  * [Considerations when deploying public folders | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/collaboration/public-folders/deployment-considerations?view=exchserver-2019)
  * [FAQ: Public folders | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/collaboration/public-folders/faq?view=exchserver-2019)

# Troubleshoot hybrid and migration issues (10–15%)

### Troubleshoot hybrid configuration issues

**troubleshoot Hybrid Configuration Wizard issues**

  * [Hybrid Configuration wizard | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/hybrid-configuration-wizard)
  * [Hybrid Configuration wizard FAQs | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/hybrid-configuration-wizard-faqs)
**troubleshoot hybrid mail flow issues**
  * [Demystifying and troubleshooting hybrid mail flow: when is a message internal?  * Microsoft Tech Community](https://techcommunity.microsoft.com/t5/exchange-team-blog/demystifying-and-troubleshooting-hybrid-mail-flow-when-is-a/ba-p/1420838)
  * [Troubleshoot a hybrid deployment | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/hybrid-deployment/troubleshoot-a-hybrid-deployment)
  * [Manage mail flow using a third-party cloud service with Exchange Online and on-premises mailboxes in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/mail-flow-best-practices/manage-mail-flow-on-office-365-and-on-prem)
**troubleshoot free/busy issues for hybrid deployments**
  * [Troubleshoot free/busy issues in Exchange hybrid  * Exchange | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/troubleshoot/calendars/troubleshoot-freebusy-issues-in-exchange-hybrid)
  * [Demystifying Hybrid Free/Busy: Finding errors and troubleshooting  * Microsoft Tech Community](https://techcommunity.microsoft.com/t5/exchange-team-blog/demystifying-hybrid-free-busy-finding-errors-and-troubleshooting/ba-p/607727)
**troubleshoot issues synchronizing remote recipient attributes with Exchange Online**
  * [Attributes synchronized by Azure AD Connect | Microsoft Docs](https://docs.microsoft.com/en-us/azure/active-directory/hybrid/reference-connect-sync-attributes-synchronized)
  * [Exchange Online object is not present or updated in Azure AD Connect (microsoft.com)](https://support.microsoft.com/en-us/topic/exchange-online-object-is-not-present-or-updated-in-azure-ad-connect-9d6d371c-b575-839e-0952-81b1875120a7)

### Troubleshoot migration issues

 * troubleshoot endpoint creation issues
  * [New-MigrationEndpoint (ExchangePowerShell) | Microsoft Docs](https://docs.microsoft.com/en-us/powershell/module/exchange/new-migrationendpoint?view=exchange-ps)
  * [Manage migration batches in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/mailbox-migration/manage-migration-batches)
 * review migration users and move requests
  * [Migration users status report in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/mailbox-migration/migration-users-status-report)
 * troubleshoot slow migrations
  * [Troubleshooting Slow Migrations  * Microsoft Tech Community](https://techcommunity.microsoft.com/t5/exchange-team-blog/troubleshooting-slow-migrations/ba-p/1795706)
  * [Tune Exchange Online performance  * Microsoft 365 Enterprise | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/enterprise/tune-exchange-online-performance?view=o365-worldwide)
 * troubleshoot Data Consistency Score (DCS) issues
  * [Migrations with Data Consistency Score (DCS) – more than you ever wanted to know!  * Microsoft Tech Community](https://techcommunity.microsoft.com/t5/exchange-team-blog/migrations-with-data-consistency-score-dcs-more-than-you-ever/ba-p/2393406)
  * [Track and Prevent Migration Data Loss in Exchange Online | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/mailbox-migration/track-prevent-data-loss-dcs)
 * troubleshoot failed migrations
  * [Troubleshooting Failed Migrations  * Microsoft Tech Community](https://techcommunity.microsoft.com/t5/exchange-team-blog/troubleshooting-failed-migrations/ba-p/1746234)
  * [Troubleshoot migration issues in Exchange hybrid  * Exchange | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/troubleshoot/move-or-migrate-mailboxes/troubleshoot-migration-issues-in-exchange-hybrid)
 * troubleshoot public folder migration issues
  * [Public folder procedures | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/collaboration/public-folders/procedures?view=exchserver-2019)
  * [Best practices for public folder preparation before migrations  * Microsoft Tech Community](https://techcommunity.microsoft.com/t5/exchange-team-blog/best-practices-for-public-folder-preparation-before-migrations/ba-p/1909222)
  * [Batch migrate Exchange Server public folders to Microsoft 365 or Office 365 | Microsoft Docs](https://docs.microsoft.com/en-us/Exchange/collaboration/public-folders/migrate-to-exchange-online?view=exchserver-2019)

-
