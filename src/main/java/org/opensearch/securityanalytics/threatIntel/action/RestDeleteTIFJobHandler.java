/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

import static org.opensearch.rest.RestRequest.Method.DELETE;

/**
 * Rest handler for threat intel tif job delete request
 */
public class RestDeleteTIFJobHandler extends BaseRestHandler {
    private static final String ACTION_NAME = "threatintel_tifjob_delete";
    private static final String PARAMS_NAME = "name";

    @Override
    public String getName() {
        return ACTION_NAME;
    }

    @Override
    protected RestChannelConsumer prepareRequest(final RestRequest request, final NodeClient client) throws IOException {
        final String name = request.param(PARAMS_NAME);
        final DeleteTIFJobRequest deleteTIFJobRequest = new DeleteTIFJobRequest(name);

        return channel -> client.executeLocally(
            DeleteTIFJobAction.INSTANCE,
            deleteTIFJobRequest,
            new RestToXContentListener<>(channel)
        );
    }

    @Override
    public List<Route> routes() {
        String path = String.join("/", "/_plugins/_security_analytics", String.format(Locale.ROOT, "threatintel/tifjob/{%s}", PARAMS_NAME));
        return List.of(new Route(DELETE, path));
    }
}