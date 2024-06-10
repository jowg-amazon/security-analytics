package org.opensearch.securityanalytics.threatIntel.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.action.SAListTIFSourceConfigsAction;
import org.opensearch.securityanalytics.threatIntel.action.SAListTIFSourceConfigsRequest;
import org.opensearch.securityanalytics.threatIntel.action.SAListTIFSourceConfigsResponse;
import org.opensearch.securityanalytics.threatIntel.service.SATIFSourceConfigManagementService;
import org.opensearch.securityanalytics.transport.SecureTransportAction;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

public class TransportListTIFSourceConfigsAction extends HandledTransportAction<SAListTIFSourceConfigsRequest, SAListTIFSourceConfigsResponse> implements SecureTransportAction {

    private static final Logger log = LogManager.getLogger(TransportListTIFSourceConfigsAction.class);

    private final ClusterService clusterService;

    private final Settings settings;

    private final ThreadPool threadPool;

    private volatile Boolean filterByEnabled;

    private final SATIFSourceConfigManagementService SaTifConfigService;

    @Inject
    public TransportListTIFSourceConfigsAction(TransportService transportService,
                                               ActionFilters actionFilters,
                                               ClusterService clusterService,
                                               final ThreadPool threadPool,
                                               Settings settings,
                                               final SATIFSourceConfigManagementService SaTifConfigService) {
        super(SAListTIFSourceConfigsAction.NAME, transportService, actionFilters, SAListTIFSourceConfigsRequest::new);
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        this.settings = settings;
        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(this.settings);
        this.clusterService.getClusterSettings().addSettingsUpdateConsumer(SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES, this::setFilterByEnabled);
        this.SaTifConfigService = SaTifConfigService;
    }

    @Override
    protected void doExecute(Task task, SAListTIFSourceConfigsRequest request, ActionListener<SAListTIFSourceConfigsResponse> actionListener) {
        // validate user
        User user = readUserFromThreadContext(this.threadPool);
        String validateBackendRoleMessage = validateUserBackendRoles(user, this.filterByEnabled);
        if (!"".equals(validateBackendRoleMessage)) {
            actionListener.onFailure(new OpenSearchStatusException("Do not have permissions to resource", RestStatus.FORBIDDEN));
            return;
        }

        SaTifConfigService.listTIFSourceConfigs(ActionListener.wrap(
                r -> {
                    log.debug("Successfully listed all threat intel source configs");
                    actionListener.onResponse(new SAListTIFSourceConfigsResponse(r));
                }, e -> {
                    log.error("Failed to list all threat intel source configs");
                    actionListener.onFailure(e);
                }
        ));
    }

    private void setFilterByEnabled(boolean filterByEnabled) {
        this.filterByEnabled = filterByEnabled;
    }

}
