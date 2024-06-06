package org.opensearch.securityanalytics.threatIntel.resthandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.threatIntel.action.SAListTIFSourceConfigsAction;
import org.opensearch.securityanalytics.threatIntel.action.SAListTIFSourceConfigsRequest;

import java.io.IOException;
import java.util.List;

import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.GET;

public class RestListTIFSourceConfigsAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(RestListTIFSourceConfigsAction.class);

    @Override
    public String getName() {
        return "list_tif_configs_action";
    }

    @Override
    public List<Route> routes() {
        return singletonList(new Route(GET, SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        SAListTIFSourceConfigsRequest req = new SAListTIFSourceConfigsRequest();

        return channel -> client.execute(
                SAListTIFSourceConfigsAction.INSTANCE,
                req,
                new RestToXContentListener<>(channel)
        );
    }
}
