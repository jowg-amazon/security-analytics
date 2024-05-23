/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.securityanalytics.resthandler;

import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Assert;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.commons.alerting.util.IndexUtilsKt;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.jobscheduler.spi.schedule.Schedule;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.TestHelpers;
import org.opensearch.securityanalytics.model.CorrelationRule;
import org.opensearch.securityanalytics.model.CustomLogType;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;
import org.opensearch.securityanalytics.threatIntel.common.FeedType;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.opensearch.securityanalytics.TestHelpers.*;

public class SATIFSourceConfigRestApiIT extends SecurityAnalyticsRestTestCase {
    private static final Logger log = LogManager.getLogger(SATIFSourceConfigRestApiIT.class);

    private String matchAllSearchBody = "{\"size\": 1000, \"query\" : {\"match_all\":{}}}";

    public void testCreateSATIFSourceConfig() throws IOException {
        Schedule schedule = new IntervalSchedule(Instant.now(), 1, ChronoUnit.DAYS);
        SATIFSourceConfigDto satifSourceConfigDto = new SATIFSourceConfigDto(
                null,
                null,
                "feedname",
                "stix",
                FeedType.CUSTOM,
                "joanne", // how to set user needs to be changed
                null,
                null,
                null,
                schedule,
                null,
                null,
                null,
                null,
                true,
                null
        );

        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.TIF_CONFIG_URI, Collections.emptyMap(), toHttpEntity(satifSourceConfigDto));
        Assert.assertEquals(201, response.getStatusLine().getStatusCode());
        Map<String, Object> responseBody = asMap(response);
        log.error("response");
        log.error(responseBody);

        List<SearchHit> hits = executeSearch(".opensearch-sap--job", matchAllSearchBody);
        log.error("hits");
        log.error(hits);
        fail();
    }
}
