/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.securityanalytics.resthandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Assert;
import org.opensearch.client.Response;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.threatIntel.common.FeedType;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.opensearch.securityanalytics.SecurityAnalyticsPlugin.JOB_INDEX_NAME;

public class SATIFSourceConfigRestApiIT extends SecurityAnalyticsRestTestCase {
    private static final Logger log = LogManager.getLogger(SATIFSourceConfigRestApiIT.class);
    public void testCreateSATIFSourceConfig() throws IOException {
        String feedName = "test_feed_name";
        String feedFormat = "STIX";
        FeedType feedType = FeedType.INTERNAL;
        IntervalSchedule schedule = new IntervalSchedule(Instant.now(), 1, ChronoUnit.DAYS);
        List<String> iocTypes = List.of("ip", "dns");

        SATIFSourceConfigDto satifSourceConfigDto = new SATIFSourceConfigDto(
                null,
                null,
                feedName,
                feedFormat,
                feedType,
                null,
                null,
                null,
                null,
                schedule,
                null,
                null,
                null,
                null,
                true,
                null,
                iocTypes
        );

        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.TIF_SOURCE_CONFIG_URI, Collections.emptyMap(), toHttpEntity(satifSourceConfigDto));
        Assert.assertEquals(201, response.getStatusLine().getStatusCode());
        Map<String, Object> responseBody = asMap(response);

        String createdId = responseBody.get("_id").toString();
        Assert.assertNotEquals("response is missing Id", SATIFSourceConfigDto.NO_ID, createdId);

        int createdVersion = Integer.parseInt(responseBody.get("_version").toString());
        Assert.assertTrue("incorrect version", createdVersion > 0);
        Assert.assertEquals("Incorrect Location header", String.format(Locale.getDefault(), "%s/%s", SecurityAnalyticsPlugin.TIF_SOURCE_CONFIG_URI, createdId), response.getHeader("Location"));

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(JOB_INDEX_NAME, request);
        Assert.assertEquals(1, hits.size());
    }

    public void testGetSATIFSourceConfigById() throws IOException {
        String feedName = "test_feed_name";
        String feedFormat = "STIX";
        FeedType feedType = FeedType.INTERNAL;
        IntervalSchedule schedule = new IntervalSchedule(Instant.now(), 1, ChronoUnit.DAYS);
        List<String> iocTypes = List.of("ip", "dns");

        SATIFSourceConfigDto satifSourceConfigDto = new SATIFSourceConfigDto(
                null,
                null,
                feedName,
                feedFormat,
                feedType,
                null,
                null,
                null,
                null,
                schedule,
                null,
                null,
                null,
                null,
                true,
                null,
                iocTypes
        );

        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.TIF_SOURCE_CONFIG_URI, Collections.emptyMap(), toHttpEntity(satifSourceConfigDto));
        Assert.assertEquals(201, response.getStatusLine().getStatusCode());
        Map<String, Object> responseBody = asMap(response);

        String createdId = responseBody.get("_id").toString();
        Assert.assertNotEquals("response is missing Id", SATIFSourceConfigDto.NO_ID, createdId);

        response = makeRequest(client(), "GET", SecurityAnalyticsPlugin.TIF_SOURCE_CONFIG_URI + "/" + createdId, Collections.emptyMap(), null);
        Map<String, Object> getResponse = entityAsMap(response);

        String responseId = responseBody.get("_id").toString();
        Assert.assertEquals("Created Id and returned Id do not match", createdId, responseId);

        int responseVersion = Integer.parseInt(responseBody.get("_version").toString());
        Assert.assertTrue("Incorrect version", responseVersion > 0);

        String returnedFeedName = (String) ((Map<String, Object>)responseBody.get("tif_config")).get("feed_name");
        Assert.assertEquals("Created feed name and returned feed name do not match", feedName, returnedFeedName);

        String returnedFeedFormat = (String) ((Map<String, Object>)responseBody.get("tif_config")).get("feed_format");
        Assert.assertEquals("Created feed format and returned feed format do not match", feedFormat, returnedFeedFormat);

        String returnedFeedType = (String) ((Map<String, Object>)responseBody.get("tif_config")).get("feed_type");
        Assert.assertEquals("Created feed type and returned feed type do not match", feedType, SATIFSourceConfigDto.toFeedType(returnedFeedType));

        List<String> returnedIocTypes = (List<String>) ((Map<String, Object>)responseBody.get("tif_config")).get("ioc_types");
        Assert.assertTrue("Created ioc types and returned ioc types do not match", iocTypes.containsAll(returnedIocTypes) && returnedIocTypes.containsAll(iocTypes));
    }
}
