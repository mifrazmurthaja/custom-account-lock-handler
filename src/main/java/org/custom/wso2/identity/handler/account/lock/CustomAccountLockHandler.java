package org.custom.wso2.identity.handler.account.lock;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.custom.wso2.identity.handler.account.lock.internal.CustomAccountServiceDataHolder;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityMgtConstants;
import org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockException;
import org.wso2.carbon.identity.handler.event.account.lock.internal.AccountServiceDataHolder;
import org.wso2.carbon.identity.handler.event.account.lock.util.AccountUtil;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Custom Account Lock Handler POST_SET_USER_CLAIMS implementation.
 */
public class CustomAccountLockHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(CustomAccountLockHandler.class);

    private static ThreadLocal<String> lockedState = new ThreadLocal<>();

    private enum lockedStates {LOCKED_MODIFIED, UNLOCKED_MODIFIED, LOCKED_UNMODIFIED, UNLOCKED_UNMODIFIED}

    public String getName() {
        return "custom.account.lock.handler";
    }

    public String getFriendlyName() {
        return "Custom Account Locking";
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        Map<String, Object> eventProperties = event.getEventProperties();
        String userName = (String) eventProperties.get(IdentityEventConstants.EventProperty.USER_NAME);
        UserStoreManager userStoreManager = (UserStoreManager) eventProperties.get(IdentityEventConstants.EventProperty.USER_STORE_MANAGER);
        String userStoreDomainName = AccountUtil.getUserStoreDomainName(userStoreManager);
        String tenantDomain = (String) eventProperties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN);

        Property[] identityProperties = null;
        Boolean accountLockedEnabled = false;
        String accountLockTime = "0";
        int maximumFailedAttempts = 0;
        double unlockTimeRatio = 1;
        String adminPasswordResetAccountLockNotificationProperty = IdentityUtil.getProperty(
                AccountConstants.ADMIN_FORCE_PASSWORD_RESET_ACCOUNT_LOCK_NOTIFICATION_ENABLE_PROPERTY);
        boolean adminForcePasswordResetLockNotificationEnabled =
                adminPasswordResetAccountLockNotificationProperty == null ||
                        Boolean.parseBoolean(adminPasswordResetAccountLockNotificationProperty);
        String adminPasswordResetAccountUnlockNotificationProperty = IdentityUtil.getProperty(
                AccountConstants.ADMIN_FORCE_PASSWORD_RESET_ACCOUNT_UNLOCK_NOTIFICATION_ENABLE_PROPERTY);
        boolean adminForcePasswordResetUnlockNotificationEnabled =
                adminPasswordResetAccountUnlockNotificationProperty == null ||
                        Boolean.parseBoolean(adminPasswordResetAccountUnlockNotificationProperty);
        try {
            identityProperties = CustomAccountServiceDataHolder.getInstance()
                    .getIdentityGovernanceService().getConfiguration(getPropertyNames(), tenantDomain);
        } catch (IdentityGovernanceException e) {
            throw new IdentityEventException("Error while retrieving Account Locking Handler properties.", e);
        }

        for (Property identityProperty : identityProperties) {
            if (AccountConstants.ACCOUNT_LOCKED_PROPERTY.equals(identityProperty.getName())) {
                accountLockedEnabled = Boolean.parseBoolean(identityProperty.getValue());
            }
        }
        if (!accountLockedEnabled) {

            if (log.isDebugEnabled()) {
                log.debug("Account lock handler is disabled in tenant: " + tenantDomain);
            }
            return;
        }

        if (IdentityEventConstants.Event.POST_SET_USER_CLAIMS.equals(event.getEventName())) {
            PrivilegedCarbonContext.startTenantFlow();
            try {
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain, true);
                handlePostSetUserClaimValues(event, userName, userStoreManager, userStoreDomainName, tenantDomain,
                        identityProperties, maximumFailedAttempts, accountLockTime, unlockTimeRatio,
                        adminForcePasswordResetLockNotificationEnabled, adminForcePasswordResetUnlockNotificationEnabled);
            } finally {
                PrivilegedCarbonContext.endTenantFlow();
            }
        }
    }

    protected boolean handlePostSetUserClaimValues(Event event, String userName, UserStoreManager userStoreManager,
                                                   String userStoreDomainName, String tenantDomain,
                                                   Property[] identityProperties, int maximumFailedAttempts,
                                                   String accountLockTime, double unlockTimeRatio,
                                                   boolean adminForcedPasswordResetLockNotificationEnabled,
                                                   boolean adminForcedPasswordResetUnlockNotificationEnabled)
            throws AccountLockException {

        String newAccountState = null;
        String accountLockedReason = null;
        try {
            boolean notificationInternallyManage = true;
            String existingAccountStateClaimValue = getAccountState(userStoreManager, tenantDomain, userName);
            try {
                notificationInternallyManage = Boolean.parseBoolean(AccountUtil.getConnectorConfig(AccountConstants
                        .NOTIFICATION_INTERNALLY_MANAGE, tenantDomain));
            } catch (IdentityEventException e) {
                log.warn("Error while reading Notification internally manage property in account lock handler");
                if (log.isDebugEnabled()) {
                    log.debug("Error while reading Notification internally manage property in account lock handler", e);
                }
            }
            boolean isAdminInitiated = true;
            if (IdentityUtil.threadLocalProperties.get().get(AccountConstants.ADMIN_INITIATED) != null) {
                isAdminInitiated = (boolean) IdentityUtil.threadLocalProperties.get()
                        .get(AccountConstants.ADMIN_INITIATED);
            }

            if (lockedStates.UNLOCKED_MODIFIED.toString().equals(lockedState.get())) {

                if (log.isDebugEnabled()) {
                    log.debug(String.format("User %s is unlocked", userName));
                }
                String emailTemplateTypeAccUnlocked = AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_UNLOCKED;
                if (notificationInternallyManage) {
                    if (isAdminInitiated) {
                        if (AccountUtil
                                .isTemplateExists(AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_UNLOCKED_ADMIN_TRIGGERED,
                                        tenantDomain)) {
                            emailTemplateTypeAccUnlocked =
                                    AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_UNLOCKED_ADMIN_TRIGGERED;
                        }
                    } else {
                        if (AccountUtil.isTemplateExists(AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_UNLOCKED_TIME_BASED,
                                tenantDomain)) {
                            emailTemplateTypeAccUnlocked = AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_UNLOCKED_TIME_BASED;
                        }
                    }
                    if (IdentityMgtConstants.AccountStates.PENDING_ADMIN_FORCED_USER_PASSWORD_RESET
                            .equals(existingAccountStateClaimValue)) {
                        if (adminForcedPasswordResetUnlockNotificationEnabled) {
                            triggerNotification(event, userName, userStoreManager, userStoreDomainName, tenantDomain,
                                    identityProperties,
                                    emailTemplateTypeAccUnlocked);
                        }
                    } else {
                        triggerNotification(event, userName, userStoreManager, userStoreDomainName, tenantDomain,
                                identityProperties,
                                emailTemplateTypeAccUnlocked);
                    }
                }
                newAccountState = buildAccountState(AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_UNLOCKED, tenantDomain,
                        userStoreManager, userName);
                publishPostAccountLockedEvent(IdentityEventConstants.Event.POST_UNLOCK_ACCOUNT,
                        event.getEventProperties(), true);
                // Remove Audit Log
                /*auditAccountLock(AuditConstants.ACCOUNT_UNLOCKED, userName, userStoreDomainName, isAdminInitiated,
                        null, AuditConstants.AUDIT_SUCCESS,true);*/
            } else if (lockedStates.LOCKED_MODIFIED.toString().equals(lockedState.get())) {

                if (log.isDebugEnabled()) {
                    log.debug(String.format("User %s is locked", userName));
                }
                String emailTemplateTypeAccLocked = AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_LOCKED;
                if (isAdminInitiated && StringUtils.isBlank(getClaimValue(userName, userStoreManager,
                        AccountConstants.ACCOUNT_LOCKED_REASON_CLAIM_URI))) {
                    setUserClaim(AccountConstants.ACCOUNT_LOCKED_REASON_CLAIM_URI,
                            IdentityMgtConstants.LockedReason.ADMIN_INITIATED.toString(), userStoreManager, userName);
                }
                if (notificationInternallyManage) {
                    if (isAdminInitiated) {
                        if (AccountUtil
                                .isTemplateExists(AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_LOCKED_ADMIN_TRIGGERED,
                                        tenantDomain)) {
                            emailTemplateTypeAccLocked =
                                    AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_LOCKED_ADMIN_TRIGGERED;
                        }
                    } else {
                        if (AccountUtil
                                .isTemplateExists(AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_LOCKED_FAILED_ATTEMPT,
                                        tenantDomain)) {
                            emailTemplateTypeAccLocked = AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_LOCKED_FAILED_ATTEMPT;
                        }
                    }

                    // Check if the account is in PENDING_AFUPR state.
                    if (IdentityMgtConstants.AccountStates.PENDING_ADMIN_FORCED_USER_PASSWORD_RESET.equals(
                            existingAccountStateClaimValue)) {
                        // Send notification if the unlock notification enabled.
                        if (adminForcedPasswordResetLockNotificationEnabled) {
                            triggerNotification(event, userName, userStoreManager, userStoreDomainName,
                                    tenantDomain, identityProperties, emailTemplateTypeAccLocked);
                        }
                        // Send locked email only if the accountState claim value is neither PENDIG_SR nor PENDING_EV.
                    } else if (!AccountConstants.PENDING_SELF_REGISTRATION.equals(existingAccountStateClaimValue) &&
                            !AccountConstants.PENDING_EMAIL_VERIFICATION.equals(existingAccountStateClaimValue)) {
                        triggerNotification(event, userName, userStoreManager, userStoreDomainName,
                                tenantDomain, identityProperties, emailTemplateTypeAccLocked);
                    }
                }
                // Set new account state only if the accountState claim value is neither PENDING_SR nor PENDING_EV.
                if (!AccountConstants.PENDING_SELF_REGISTRATION.equals(existingAccountStateClaimValue) &&
                        !AccountConstants.PENDING_EMAIL_VERIFICATION.equals(existingAccountStateClaimValue)) {
                    newAccountState = buildAccountState(AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_LOCKED,
                            tenantDomain, userStoreManager, userName);
                }
                publishPostAccountLockedEvent(IdentityEventConstants.Event.POST_LOCK_ACCOUNT,
                        event.getEventProperties(),
                        true);
                // Remove Audit Log
                /*auditAccountLock(AuditConstants.ACCOUNT_LOCKED, userName, userStoreDomainName, isAdminInitiated,
                        null, AuditConstants.AUDIT_SUCCESS,true);*/
            } else if (lockedStates.LOCKED_UNMODIFIED.toString().equals(lockedState.get())) {
                // Remove Audit Log
                /*auditAccountLock(AuditConstants.ACCOUNT_LOCKED, userName, userStoreDomainName, isAdminInitiated,
                        null, AuditConstants.AUDIT_SUCCESS,false);*/
            } else if (lockedStates.UNLOCKED_UNMODIFIED.toString().equals(lockedState.get())) {
                // Remove Audit Log
                /*auditAccountLock(AuditConstants.ACCOUNT_UNLOCKED, userName, userStoreDomainName, isAdminInitiated,
                        null, AuditConstants.AUDIT_SUCCESS,false);*/
            }
        } finally {
            lockedState.remove();
            IdentityUtil.threadLocalProperties.get().remove(AccountConstants.ADMIN_INITIATED);
        }
        if (StringUtils.isNotEmpty(newAccountState)) {
            setUserClaim(AccountConstants.ACCOUNT_STATE_CLAIM_URI, newAccountState,
                    userStoreManager, userName);
        }
        return true;
    }

    private String getAccountState(UserStoreManager userStoreManager, String tenantDomain, String userName)
            throws AccountLockException {

        String accountStateClaimValue = null;
        try {
            boolean isAccountStateClaimExist = AccountUtil.isAccountStateClaimExisting(tenantDomain);
            if (isAccountStateClaimExist) {
                Map<String, String> claimValues = userStoreManager.getUserClaimValues(userName, new String[]{
                        AccountConstants.ACCOUNT_STATE_CLAIM_URI}, UserCoreConstants.DEFAULT_PROFILE);
                accountStateClaimValue = claimValues.get(AccountConstants.ACCOUNT_STATE_CLAIM_URI);
            }
        } catch (UserStoreException e) {
            throw new AccountLockException("Error occurred while retrieving account state claim value", e);
        }
        return accountStateClaimValue;
    }

    private String buildAccountState(String state, String tenantDomain, UserStoreManager userStoreManager,
                                     String userName) throws AccountLockException {

        boolean isAccountStateClaimExist = AccountUtil.isAccountStateClaimExisting(tenantDomain);
        String newAccountstate = null;
        if (isAccountStateClaimExist) {
            if (isAccountDisabled(userStoreManager, userName)) {
                // If accountDisabled claim is true, then set accountState=DISABLED
                newAccountstate = AccountConstants.DISABLED;
            } else if (state.equals(AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_UNLOCKED)) {
                // If accountDisabled claim is false and accountLocked claim is false, then set
                // accountState=UNLOCKED
                newAccountstate = AccountConstants.UNLOCKED;
            } else if (state.equals(AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_LOCKED)) {
                // If accountDisabled claim is false and accountLocked claim is true, then set
                // accountState=LOCKED
                newAccountstate = AccountConstants.LOCKED;
            }
        }
        return newAccountstate;
    }

    private boolean isAccountDisabled(UserStoreManager userStoreManager, String userName) throws AccountLockException {

        boolean accountDisabled = false;
        try {
            Map<String, String> claimValues = userStoreManager.getUserClaimValues(userName, new String[]{
                    AccountConstants.ACCOUNT_DISABLED_CLAIM}, UserCoreConstants.DEFAULT_PROFILE);
            accountDisabled = Boolean.parseBoolean(claimValues.get(AccountConstants
                    .ACCOUNT_DISABLED_CLAIM));
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new AccountLockException("Error occurred while retrieving " + AccountConstants
                    .ACCOUNT_DISABLED_CLAIM + " claim value", e);
        }
        return accountDisabled;
    }

    private void publishPostAccountLockedEvent(String accountLockedEventName, Map<String, Object> map, boolean
            isLockPropertySuccessfullyModified) throws AccountLockException {

        Map<String, Object> eventProperties = AccountUtil.cloneMap(map);
        eventProperties.put(IdentityEventConstants.EventProperty.UPDATED_LOCKED_STATUS,
                isLockPropertySuccessfullyModified);
        AccountUtil.publishEvent(accountLockedEventName, eventProperties);
    }

    private void setUserClaim(String claimName, String claimValue, UserStoreManager userStoreManager,
                              String username) throws AccountLockException {

        HashMap<String, String> userClaims = new HashMap<>();
        userClaims.put(claimName, claimValue);
        try {
            userStoreManager.setUserClaimValues(username, userClaims, null);
        } catch (UserStoreException e) {
            throw new AccountLockException("Error while setting user claim value :" + username, e);
        }
    }

    private String getClaimValue(String username, org.wso2.carbon.user.api.UserStoreManager userStoreManager,
                                 String claimURI) throws AccountLockException {

        try {
            Map<String, String> values = userStoreManager.getUserClaimValues(username, new String[]{claimURI},
                    UserCoreConstants.DEFAULT_PROFILE);
            return values.get(claimURI);

        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new AccountLockException("Error occurred while retrieving claim: " + claimURI, e);
        }
    }

    public String[] getPropertyNames() {
        List<String> properties = new ArrayList<>();
        properties.add(AccountConstants.ACCOUNT_LOCKED_PROPERTY);
        properties.add(AccountConstants.FAILED_LOGIN_ATTEMPTS_PROPERTY);
        properties.add(AccountConstants.ACCOUNT_UNLOCK_TIME_PROPERTY);
        properties.add(AccountConstants.LOGIN_FAIL_TIMEOUT_RATIO_PROPERTY);
        properties.add(AccountConstants.NOTIFICATION_INTERNALLY_MANAGE);

        return properties.toArray(new String[properties.size()]);
    }

    protected void triggerNotification(Event event, String userName, UserStoreManager userStoreManager,
                                       String userStoreDomainName, String tenantDomain,
                                       Property[] identityProperties, String notificationEvent) throws
            AccountLockException {

        String eventName = IdentityEventConstants.Event.TRIGGER_NOTIFICATION;

        HashMap<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, userName);
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, userStoreDomainName);
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, tenantDomain);
        properties.put("TEMPLATE_TYPE", notificationEvent);
        Event identityMgtEvent = new Event(eventName, properties);
        try {
            AccountServiceDataHolder.getInstance().getIdentityEventService().handleEvent(identityMgtEvent);
        } catch (Exception e) {
            String errorMsg = "Error occurred while calling triggerNotification, detail : " + e.getMessage();
            //We are not throwing any exception from here, because this event notification should not break the main
            // flow.
            log.warn(errorMsg);
            if (log.isDebugEnabled()) {
                log.debug(errorMsg, e);
            }
        }
    }
}
