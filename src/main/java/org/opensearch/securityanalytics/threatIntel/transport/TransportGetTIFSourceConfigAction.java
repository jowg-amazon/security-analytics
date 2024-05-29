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
import org.opensearch.securityanalytics.threatIntel.action.SAGetTIFSourceConfigAction;
import org.opensearch.securityanalytics.threatIntel.action.SAGetTIFSourceConfigRequest;
import org.opensearch.securityanalytics.threatIntel.action.SAGetTIFSourceConfigResponse;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.threatIntel.service.SATIFSourceConfigService;
import org.opensearch.securityanalytics.transport.SecureTransportAction;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

public class TransportGetTIFSourceConfigAction extends HandledTransportAction<SAGetTIFSourceConfigRequest, SAGetTIFSourceConfigResponse> implements SecureTransportAction {

    private static final Logger log = LogManager.getLogger(TransportGetTIFSourceConfigAction.class);

    private final ClusterService clusterService;

    private final Settings settings;

    private final ThreadPool threadPool;

    private volatile Boolean filterByEnabled;

    private final SATIFSourceConfigService SaTifConfigService;

    @Inject
    public TransportGetTIFSourceConfigAction(TransportService transportService,
                                             ActionFilters actionFilters,
                                             ClusterService clusterService,
                                             final ThreadPool threadPool,
                                             Settings settings,
                                             final SATIFSourceConfigService SaTifConfigService) {
        super(SAGetTIFSourceConfigAction.NAME, transportService, actionFilters, SAGetTIFSourceConfigRequest::new);
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        this.settings = settings;
        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(this.settings);
        this.clusterService.getClusterSettings().addSettingsUpdateConsumer(SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES, this::setFilterByEnabled);
        this.SaTifConfigService = SaTifConfigService;
    }

    @Override
    protected void doExecute(Task task, SAGetTIFSourceConfigRequest request, ActionListener<SAGetTIFSourceConfigResponse> actionListener) {

        User user = readUserFromThreadContext(this.threadPool);

        String validateBackendRoleMessage = validateUserBackendRoles(user, this.filterByEnabled);
        if (!"".equals(validateBackendRoleMessage)) {
            actionListener.onFailure(new OpenSearchStatusException("Do not have permissions to resource", RestStatus.FORBIDDEN));
            return;
        }

        SaTifConfigService.getTIFSourceConfig(request.getId(), request.getVersion(), new ActionListener<>() {
            @Override
            public void onResponse(SATIFSourceConfig SaTifSourceConfig) {
                SATIFSourceConfigDto SaTifSourceConfigDto = new SATIFSourceConfigDto(SaTifSourceConfig);
                actionListener.onResponse(new SAGetTIFSourceConfigResponse(SaTifSourceConfigDto.getId(), SaTifSourceConfigDto.getVersion(), RestStatus.OK, SaTifSourceConfigDto));
            }

            @Override
            public void onFailure(Exception e) {
                actionListener.onFailure(e);
            }
        });
    }

    private void setFilterByEnabled(boolean filterByEnabled) {
        this.filterByEnabled = filterByEnabled;
    }

}
