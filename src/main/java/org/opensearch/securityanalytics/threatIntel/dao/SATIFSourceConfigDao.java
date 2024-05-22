/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.dao;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.ActionRunnable;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.StepListener;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.commons.alerting.action.DeleteMonitorResponse;
import org.opensearch.commons.alerting.action.DeleteWorkflowResponse;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.RestRequest;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.IndexDetectorResponse;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.action.SAIndexTIFSourceConfigRequest;
import org.opensearch.securityanalytics.threatIntel.action.SAIndexTIFSourceConfigResponse;
import org.opensearch.securityanalytics.threatIntel.action.ThreatIntelIndicesResponse;
import org.opensearch.securityanalytics.threatIntel.common.StashedThreadContext;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
import org.opensearch.securityanalytics.threatIntel.sacommons.IndexTIFSourceConfigResponse;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.threadpool.ThreadPool;

import javax.swing.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

/**
 * CRUD for threat intel feeds config object
 */
public class SATIFSourceConfigDao {
    private static final Logger log = LogManager.getLogger(SATIFSourceConfigDao.class);
    private final Client client;
    private final ClusterService clusterService;
    private final ClusterSettings clusterSettings;
    private final ThreadPool threadPool;


    public SATIFSourceConfigDao(final Client client, final ClusterService clusterService, ThreadPool threadPool) {
        this.client = client;
        this.clusterService = clusterService;
        this.clusterSettings = clusterService.getClusterSettings();
        this.threadPool = threadPool;
    }

    public void indexTIFSourceConfig(SATIFSourceConfig satifSourceConfig, TimeValue indexTimeout, final ActionListener<SATIFSourceConfig> actionListener) throws Exception {
        IndexRequest indexRequest = new IndexRequest(SecurityAnalyticsPlugin.JOB_INDEX_NAME)
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .source(satifSourceConfig.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                .timeout(indexTimeout);
        log.debug("Indexing tif source config");
        client.index(indexRequest, new ActionListener<>() {
            @Override
            public void onResponse(IndexResponse response) {
                log.debug("TIF source config indexed success.");
                satifSourceConfig.setId(response.getId());
                actionListener.onResponse(satifSourceConfig);
            }
            @Override
            public void onFailure(Exception e) {
                throw new SecurityAnalyticsException("Exception saving the tif source config in index", RestStatus.INTERNAL_SERVER_ERROR, e);
            }
        });
    }

    public ThreadPool getThreadPool() {
        return threadPool;
    }




    // Initialize the tif source config index if it doesn't exist
    public void initTIFSourceConfigIndex(ActionListener<CreateIndexResponse> actionListener) {
        if (!tifJobSchedulerIndexExists()) {
            Settings indexSettings = Settings.builder()
                    .put("index.hidden", true)
                    .build();
            CreateIndexRequest indexRequest = new CreateIndexRequest(SecurityAnalyticsPlugin.JOB_INDEX_NAME)
                    .mapping(getIndexMapping())
                    .settings(indexSettings);
            client.admin().indices().create(indexRequest, actionListener);
        }
    }

    public boolean tifJobSchedulerIndexExists() {
        ClusterState clusterState = clusterService.state();
        return clusterState.getRoutingTable().hasIndex(SecurityAnalyticsPlugin.JOB_INDEX_NAME);
    }



    // Get the job config index mapping
    private String getIndexMapping() {
        try {
            try (InputStream is = SATIFSourceConfigDao.class.getResourceAsStream("/mappings/threat_intel_feed_mapping.json")) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                    return reader.lines().map(String::trim).collect(Collectors.joining());
                }
            }
        } catch (IOException e) {
            log.error("Runtime exception when getting the threat intel index mapping", e);
            throw new SecurityAnalyticsException("Runtime exception when getting the threat intel index mapping", RestStatus.INTERNAL_SERVER_ERROR, e);
        }
    }



    // Create Threat intel config index
    /**
     * Index name: .opensearch-sap--job
     * Mapping: /mappings/threat_intel_job_mapping.json
     *
     * @param stepListener setup listener
     */
    public void createJobIndexIfNotExists(final StepListener<Void> stepListener) {
        // check if job index exists
        if (clusterService.state().metadata().hasIndex(SecurityAnalyticsPlugin.JOB_INDEX_NAME) == true) {
            stepListener.onResponse(null);
            return;
        }
        final CreateIndexRequest createIndexRequest = new CreateIndexRequest(SecurityAnalyticsPlugin.JOB_INDEX_NAME).mapping(getIndexMapping())
                .settings(SecurityAnalyticsPlugin.TIF_JOB_INDEX_SETTING);
        StashedThreadContext.run(client, () -> client.admin().indices().create(createIndexRequest, new ActionListener<>() {
            @Override
            public void onResponse(final CreateIndexResponse createIndexResponse) {
                stepListener.onResponse(null);
            }

            @Override
            public void onFailure(final Exception e) {
                if (e instanceof ResourceAlreadyExistsException) {
                    log.info("index[{}] already exist", SecurityAnalyticsPlugin.JOB_INDEX_NAME);
                    stepListener.onResponse(null);
                    return;
                }
                log.error("Failed to create security analytics threat intel job index", e);
                stepListener.onFailure(e);
            }
        }));
    }


















    // Put threat intel config data into index
    /**
     * Put threat intel feed config in an index {@code TIFJobExtension.JOB_INDEX_NAME}
     *
     * @param satifConfig the satifConfig
     * @param listener        the listener
     */
    public void saveTIFConfig(final SATIFSourceConfig satifConfig, final ActionListener<IndexResponse> listener) {
        satifConfig.setLastUpdateTime(Instant.now());
        StashedThreadContext.run(client, () -> {
            try {
                client.prepareIndex(SecurityAnalyticsPlugin.JOB_INDEX_NAME)
                        .setId(satifConfig.getId())
                        .setOpType(DocWriteRequest.OpType.CREATE)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                        .setSource(satifConfig.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS));

            } catch (IOException e) { // listener.onfailure
                throw new SecurityAnalyticsException("Exception saving the threat intel feed job parameter in index", RestStatus.INTERNAL_SERVER_ERROR, e);
            }
        });
    }




























    // Common utils interface class
    IndexTIFSourceConfigResponse indexTIFConfig(SAIndexTIFSourceConfigRequest request, ActionListener <SAIndexTIFSourceConfigRequest> listener) {
        return null;
    }




//
//    // Read threat intel config
//    /**
//     * Get threat intel feed config from an index {@code TIFJobExtension.JOB_INDEX_NAME}
//     *
//     * @param id the id of a tif job
//     */
//    public void getTIFConfig(final String id, ActionListener<SATIFSourceConfig> listener) {
//        GetRequest request = new GetRequest(SecurityAnalyticsPlugin.JOB_INDEX_NAME, id);
//        StashedThreadContext.run(client, () -> client.get(request, ActionListener.wrap(
//                response -> {
//                    if (response.isExists() == false) {
//                        log.error("TIF config[{}] does not exist in an index[{}]", id, SecurityAnalyticsPlugin.JOB_INDEX_NAME);
//                        listener.onFailure(new ResourceNotFoundException("id"));
//                    }
//                    XContentParser xcp = XContentHelper.createParser(
//                            NamedXContentRegistry.EMPTY,
//                            LoggingDeprecationHandler.INSTANCE,
//                            response.getSourceAsBytesRef()
//                    );
//                    listener.onResponse(SATIFSourceConfig.parse(xcp, null, null));
//                }, e -> {
//                    log.error("Failed to fetch tif job document " + id, e);
//                    listener.onFailure(e);
//                })));
//    }
//
//
//    // Update Threat Intel Config in an Index
//    public IndexResponse updateTIFConfig(final SATIFSourceConfig satifConfig) {
//        satifConfig.setLastUpdateTime(Instant.now());
//        return StashedThreadContext.run(client, () -> {
//            try {
//                return client.prepareIndex(SecurityAnalyticsPlugin.JOB_INDEX_NAME)
//                        .setId(satifConfig.getId())
//                        .setOpType(DocWriteRequest.OpType.INDEX)
//                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
//                        .setSource(satifConfig.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
//                        .execute()
//                        .actionGet(clusterSettings.get(SecurityAnalyticsSettings.THREAT_INTEL_TIMEOUT));
//            } catch (IOException e) {
//                throw new SecurityAnalyticsException("Exception updating the threat intel feed job parameter in index", RestStatus.INTERNAL_SERVER_ERROR, e);
//            }
//        });
//    }
//
//








    // Update threat intel config
    /**
     * Update threat intel feed config in an index {@code TIFJobExtension.JOB_INDEX_NAME}
     *
     * @param satifConfig the satifConfig
     */
    public void updateJobSchedulerParameter(final SATIFSourceConfig satifConfig, final ActionListener<ThreatIntelIndicesResponse> listener) {
        satifConfig.setLastUpdateTime(Instant.now());
        StashedThreadContext.run(client, () -> {
            try {
                client.prepareIndex(SecurityAnalyticsPlugin.JOB_INDEX_NAME)
                        .setId(satifConfig.getId())
                        .setOpType(DocWriteRequest.OpType.INDEX)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                        .setSource(satifConfig.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                        .execute(new ActionListener<>() {
                            @Override
                            public void onResponse(IndexResponse indexResponse) {
                                if (indexResponse.status().getStatus() >= 200 && indexResponse.status().getStatus() < 300) {

                                    // TODO: String list of indices that needs to be updated
                                    List<String> iocListStore = satifConfig.getIocMapStore()
                                            .values()
                                            .stream()
                                            .map(Object::toString)
                                            .collect(Collectors.toList());

                                    listener.onResponse(new ThreatIntelIndicesResponse(true, iocListStore));
                                } else {
                                    listener.onFailure(new OpenSearchStatusException("update of job scheduler parameter failed", RestStatus.INTERNAL_SERVER_ERROR));
                                }
                            }

                            @Override
                            public void onFailure(Exception e) {
                                listener.onFailure(e);
                            }
                        });
            } catch (IOException e) {
                log.error("failed to update job scheduler param for tif job", e);
                listener.onFailure(e);
            }
        });
    }

    // Delete threat intel config
    /**
     * Delete the threat intel feed config in an index
     */
    public void deleteTIFConfig(final SATIFSourceConfig satifConfig) {
        DeleteResponse response = client.prepareDelete()
                .setIndex(SecurityAnalyticsPlugin.JOB_INDEX_NAME)
                .setId(satifConfig.getId())
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .execute()
                .actionGet(clusterSettings.get(SecurityAnalyticsSettings.THREAT_INTEL_TIMEOUT));

        if (response.status().equals(RestStatus.OK)) {
            log.info("deleted threat intel config[{}] successfully", satifConfig.getName());
        } else if (response.status().equals(RestStatus.NOT_FOUND)) {
            throw new ResourceNotFoundException("datasource[{}] does not exist", satifConfig.getName());
        } else {
            throw new OpenSearchException("failed to delete threat intel config[{}] with status[{}]", satifConfig.getName(), response.status());
        }
    }


}
