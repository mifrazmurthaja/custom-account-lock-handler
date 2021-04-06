package org.custom.wso2.identity.handler.account.lock.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.custom.wso2.identity.handler.account.lock.CustomAccountLockHandler;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;

/**
 * Service component for the CustomAccountLockHandler.
 */
@Component(
        name = "custom.handler.event.account.lock",
        immediate = true
)
public class CustomAccountServiceComponent {

    private static final Log log = LogFactory.getLog(CustomAccountServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        CustomAccountLockHandler accountLockHandler = new CustomAccountLockHandler();
        context.getBundleContext().registerService(AbstractEventHandler.class.getName(), accountLockHandler, null);
        if (log.isDebugEnabled()) {
            log.debug("AccountLockHandler is registered");
        }

        if (log.isDebugEnabled()) {
            log.debug("Custom Account Lock Handler component is activated.");
        }
    }

    @Reference(
            name = "CustomIdentityGovernanceService",
            service = IdentityGovernanceService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityGovernanceService")
    protected void setIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        CustomAccountServiceDataHolder.getInstance().setIdentityGovernanceService(identityGovernanceService);
    }

    protected void unsetIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        CustomAccountServiceDataHolder.getInstance().setIdentityGovernanceService(null);
    }

}
