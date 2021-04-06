package org.custom.wso2.identity.handler.account.lock.internal;

import org.wso2.carbon.identity.governance.IdentityGovernanceService;

public class CustomAccountServiceDataHolder {

    private static CustomAccountServiceDataHolder instance = new CustomAccountServiceDataHolder();

    private IdentityGovernanceService identityGovernanceService;

    public static CustomAccountServiceDataHolder getInstance() {

        return instance;
    }

    public IdentityGovernanceService getIdentityGovernanceService() {

        return identityGovernanceService;
    }

    public void setIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        this.identityGovernanceService = identityGovernanceService;
    }

}
