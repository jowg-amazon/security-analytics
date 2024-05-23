/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.threatIntel.resthandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.node.NodeClient;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.threatIntel.action.SAIndexTIFSourceConfigAction;
import org.opensearch.securityanalytics.threatIntel.action.SAIndexTIFSourceConfigRequest;
import org.opensearch.securityanalytics.threatIntel.action.SAIndexTIFSourceConfigResponse;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.util.RestHandlerUtils;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Locale;

import static org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto.NO_ID;


public class RestIndexTIFConfigAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestIndexTIFConfigAction.class);
    @Override
    public String getName() {
        return "index_tif_config_action";
    }
    @Override
    public List<Route> routes() {
        return List.of(
                new Route(RestRequest.Method.POST, SecurityAnalyticsPlugin.TIF_CONFIG_URI),
                new Route(RestRequest.Method.PUT, SecurityAnalyticsPlugin.TIF_CONFIG_URI + "/{tifConfigId}")
        );
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        log.debug(String.format(Locale.getDefault(), "%s %s", request.method(), SecurityAnalyticsPlugin.TIF_CONFIG_URI));

        WriteRequest.RefreshPolicy refreshPolicy = WriteRequest.RefreshPolicy.IMMEDIATE;
        if (request.hasParam(RestHandlerUtils.REFRESH)) {
            refreshPolicy = WriteRequest.RefreshPolicy.parse(request.param(RestHandlerUtils.REFRESH));
        }

        String id = request.param("feed_id", null);

        XContentParser xcp = request.contentParser();
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.nextToken(), xcp);

        SATIFSourceConfigDto tifConfig = SATIFSourceConfigDto.parse(xcp, id, null);
        // I can probably set the schedule time here?
        tifConfig.setLastUpdateTime(Instant.now());

        SAIndexTIFSourceConfigRequest indexTIFConfigRequest = new SAIndexTIFSourceConfigRequest(id, refreshPolicy, request.method(), tifConfig);
        return channel -> client.execute(SAIndexTIFSourceConfigAction.INSTANCE, indexTIFConfigRequest, indexTIFConfigResponse(channel, request.method()));
    }

    private RestResponseListener<SAIndexTIFSourceConfigResponse> indexTIFConfigResponse(RestChannel channel, RestRequest.Method restMethod) {
        return new RestResponseListener<>(channel) {
            @Override
            public RestResponse buildResponse(SAIndexTIFSourceConfigResponse response) throws Exception {
                RestStatus returnStatus = RestStatus.CREATED;
                if (restMethod == RestRequest.Method.PUT) {
                    returnStatus = RestStatus.OK;
                }

                BytesRestResponse restResponse = new BytesRestResponse(returnStatus, response.toXContent(channel.newBuilder(), ToXContent.EMPTY_PARAMS));

                if (restMethod == RestRequest.Method.POST) {
                    String location = String.format(Locale.getDefault(), "%s/%s", SecurityAnalyticsPlugin.TIF_CONFIG_URI, response.getTIFConfigId());
                    restResponse.addHeader("Location", location);
                }

                return restResponse;
            }
        };
    }
}