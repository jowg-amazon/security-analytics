package org.opensearch.securityanalytics.threatIntel.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.action.StepListener;
import org.opensearch.action.admin.cluster.state.ClusterStateResponse;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.routing.Preference;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.jobscheduler.spi.LockModel;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.services.STIX2IOCFetchService;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.common.TIFLockService;
import org.opensearch.securityanalytics.threatIntel.model.DefaultIocStoreConfig;
import org.opensearch.securityanalytics.threatIntel.model.IocStoreConfig;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.util.IndexUtils;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;


/**
 * Service class for threat intel feed source config object
 */
public class SATIFSourceConfigManagementService {
    private static final Logger log = LogManager.getLogger(SATIFSourceConfigManagementService.class);
    private final SATIFSourceConfigService saTifSourceConfigService;
    private final TIFLockService lockService; //TODO: change to js impl lock
    private final STIX2IOCFetchService stix2IOCFetchService;
    private final NamedXContentRegistry xContentRegistry;
    private final IndexNameExpressionResolver indexNameExpressionResolver;
    private final ClusterService clusterService;

    /**
     * Default constructor
     *
     * @param saTifSourceConfigService the tif source config dao
     * @param lockService              the lock service
     * @param stix2IOCFetchService     the service to download, and store IOCs
     */
    @Inject
    public SATIFSourceConfigManagementService(
            final SATIFSourceConfigService saTifSourceConfigService,
            final TIFLockService lockService,
            final STIX2IOCFetchService stix2IOCFetchService,
            final NamedXContentRegistry xContentRegistry,
            final IndexNameExpressionResolver indexNameExpressionResolver,
            final ClusterService clusterService
    ) {
        this.saTifSourceConfigService = saTifSourceConfigService;
        this.lockService = lockService;
        this.stix2IOCFetchService = stix2IOCFetchService;
        this.xContentRegistry = xContentRegistry;
        this.indexNameExpressionResolver = indexNameExpressionResolver;
        this.clusterService = clusterService;
    }

    public void createOrUpdateTifSourceConfig(
            final SATIFSourceConfigDto saTifSourceConfigDto,
            final LockModel lock,
            final RestRequest.Method restMethod,
            final User createdByUser,
            final ActionListener<SATIFSourceConfigDto> listener
    ) {
        if (restMethod == RestRequest.Method.POST) {
            createIocAndTIFSourceConfig(saTifSourceConfigDto, lock, createdByUser, listener);
        } else if (restMethod == RestRequest.Method.PUT) {
            updateIocAndTIFSourceConfig(saTifSourceConfigDto, lock, listener);
        }
    }

    /**
     * Creates the job index if it doesn't exist and indexes the tif source config object
     *
     * @param saTifSourceConfigDto the tif source config dto
     * @param lock                 the lock object
     * @param listener             listener that accepts a tif source config if successful
     */
    public void createIocAndTIFSourceConfig(
            final SATIFSourceConfigDto saTifSourceConfigDto,
            final LockModel lock,
            final User createdByUser,
            final ActionListener<SATIFSourceConfigDto> listener
    ) {
        try {
            SATIFSourceConfig saTifSourceConfig = convertToSATIFConfig(saTifSourceConfigDto, null, TIFJobState.CREATING, createdByUser);

            // Index threat intel source config as creating
            saTifSourceConfigService.indexTIFSourceConfig(
                    saTifSourceConfig,
                    lock,
                    ActionListener.wrap(
                            indexSaTifSourceConfigResponse -> {
                                log.debug("Indexed threat intel source config as CREATING for [{}]", indexSaTifSourceConfigResponse.getId());
                                // Call to download and save IOCS's, update state as AVAILABLE on success
                                indexSaTifSourceConfigResponse.setLastRefreshedTime(Instant.now());
                                downloadAndSaveIOCs(indexSaTifSourceConfigResponse, ActionListener.wrap(
                                        r -> {
                                            // TODO: Update the IOC map to store list of indices, sync up with @hurneyt
                                            // TODO: Only return list of ioc indices if no errors occur (no partial iocs)
                                            markSourceConfigAsAction(
                                                    indexSaTifSourceConfigResponse,
                                                    TIFJobState.AVAILABLE,
                                                    ActionListener.wrap(
                                                            updateSaTifSourceConfigResponse -> {
                                                                log.debug("Updated threat intel source config as AVAILABLE for [{}]", indexSaTifSourceConfigResponse.getId());
                                                                SATIFSourceConfigDto returnedSaTifSourceConfigDto = new SATIFSourceConfigDto(updateSaTifSourceConfigResponse);
                                                                listener.onResponse(returnedSaTifSourceConfigDto);
                                                            }, e -> {
                                                                log.error("Failed to index threat intel source config with id [{}]", indexSaTifSourceConfigResponse.getId());
                                                                listener.onFailure(e);
                                                            }
                                                    ));
                                        },
                                        e -> {
                                            log.error("Failed to download and save IOCs for source config [{}]", indexSaTifSourceConfigResponse.getId());
                                            saTifSourceConfigService.deleteTIFSourceConfig(indexSaTifSourceConfigResponse, ActionListener.wrap(
                                                    deleteResponse -> {
                                                        log.debug("Successfully deleted threat intel source config [{}]", indexSaTifSourceConfigResponse.getId());
                                                        listener.onFailure(new OpenSearchException("Successfully deleted threat intel source config [{}]", indexSaTifSourceConfigResponse.getId()));
                                                    }, ex -> {
                                                        log.error("Failed to delete threat intel source config [{}]", indexSaTifSourceConfigResponse.getId());
                                                        listener.onFailure(ex);
                                                    }
                                            ));
                                            listener.onFailure(e);
                                        })
                                );
                            }, e -> {
                                log.error("Failed to index threat intel source config with id [{}]", saTifSourceConfig.getId());
                                listener.onFailure(e);
                            }));
        } catch (Exception e) {
            log.error("Failed to create IOCs and threat intel source config");
            listener.onFailure(e);
        }
    }

    // Temp function to download and save IOCs (i.e. refresh)
    public void downloadAndSaveIOCs(SATIFSourceConfig saTifSourceConfig, ActionListener<STIX2IOCFetchService.STIX2IOCFetchResponse> actionListener) {
        stix2IOCFetchService.downloadAndIndexIOCs(saTifSourceConfig, actionListener);
    }

    public void getTIFSourceConfig(
            final String saTifSourceConfigId,
            final ActionListener<SATIFSourceConfigDto> listener
    ) {
        saTifSourceConfigService.getTIFSourceConfig(saTifSourceConfigId, ActionListener.wrap(
                saTifSourceConfigResponse -> {
                    SATIFSourceConfigDto returnedSaTifSourceConfigDto = new SATIFSourceConfigDto(saTifSourceConfigResponse);
                    listener.onResponse(returnedSaTifSourceConfigDto);
                }, e -> {
                    log.error("Failed to get threat intel source config for [{}]", saTifSourceConfigId);
                    listener.onFailure(e);
                }
        ));
    }

    public void searchTIFSourceConfigs(
            final SearchSourceBuilder searchSourceBuilder,
            final ActionListener<SearchResponse> listener
    ) {
        try {
            SearchRequest searchRequest = getSearchRequest(searchSourceBuilder);

            // convert search response to threat intel source config dtos
            saTifSourceConfigService.searchTIFSourceConfigs(searchRequest, ActionListener.wrap(
                    searchResponse -> {
                        for (SearchHit hit: searchResponse.getHits()) {
                            XContentParser xcp = XContentType.JSON.xContent().createParser(
                                    xContentRegistry,
                                    LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString()
                            );
                            SATIFSourceConfigDto satifSourceConfigDto = SATIFSourceConfigDto.docParse(xcp, hit.getId(), hit.getVersion());
                            XContentBuilder xcb = satifSourceConfigDto.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS);
                            hit.sourceRef(BytesReference.bytes(xcb));
                        }
                        listener.onResponse(searchResponse);
                    }, e -> {
                        log.error("Failed to fetch all threat intel source configs for search request [{}]", searchSourceBuilder, e);
                        listener.onFailure(e);
                    }
            ));
        } catch (Exception e) {
            log.error("Failed to search and parse all threat intel source configs");
            listener.onFailure(e);
        }
    }

    private static SearchRequest getSearchRequest(SearchSourceBuilder searchSourceBuilder) {

        // update search source builder
        searchSourceBuilder.seqNoAndPrimaryTerm(true);
        searchSourceBuilder.version(true);

        // construct search request
        SearchRequest searchRequest = new SearchRequest().source(searchSourceBuilder);
        searchRequest.indices(SecurityAnalyticsPlugin.JOB_INDEX_NAME);
        searchRequest.preference(Preference.PRIMARY_FIRST.type());

        BoolQueryBuilder boolQueryBuilder;

        if (searchRequest.source().query() == null) {
            boolQueryBuilder = new BoolQueryBuilder();
        } else {
            boolQueryBuilder = QueryBuilders.boolQuery().must(searchRequest.source().query());
        }

        BoolQueryBuilder bqb = new BoolQueryBuilder();
        bqb.should().add(new BoolQueryBuilder().must(QueryBuilders.existsQuery("source_config")));

        boolQueryBuilder.filter(bqb);
        searchRequest.source().query(boolQueryBuilder);
        return searchRequest;
    }

    public void updateIocAndTIFSourceConfig(
            final SATIFSourceConfigDto saTifSourceConfigDto,
            final LockModel lock,
            final ActionListener<SATIFSourceConfigDto> listener
    ) {
        try {
            saTifSourceConfigService.getTIFSourceConfig(saTifSourceConfigDto.getId(), ActionListener.wrap(
                    retrievedSaTifSourceConfig -> {
                        if (TIFJobState.AVAILABLE.equals(retrievedSaTifSourceConfig.getState()) == false) {
                            log.error("Invalid TIF job state. Expecting {} but received {}", TIFJobState.AVAILABLE, retrievedSaTifSourceConfig.getState());
                            listener.onFailure(new OpenSearchException("Invalid TIF job state. Expecting {} but received {}", TIFJobState.AVAILABLE, retrievedSaTifSourceConfig.getState()));
                            return;
                        }

                        SATIFSourceConfig updatedSaTifSourceConfig = updateSaTifSourceConfig(saTifSourceConfigDto, retrievedSaTifSourceConfig);

                        // Call to download and save IOCS's based on new threat intel source config
                        retrievedSaTifSourceConfig.setState(TIFJobState.REFRESHING);
                        retrievedSaTifSourceConfig.setLastRefreshedTime(Instant.now());
                        downloadAndSaveIOCs(updatedSaTifSourceConfig, ActionListener.wrap(
                                r -> {
                                    updatedSaTifSourceConfig.setState(TIFJobState.AVAILABLE);
                                    updatedSaTifSourceConfig.setLastUpdateTime(Instant.now());
                                    saTifSourceConfigService.updateTIFSourceConfig(
                                            updatedSaTifSourceConfig,
                                            ActionListener.wrap(
                                                    saTifSourceConfigResponse -> {
                                                        SATIFSourceConfigDto returnedSaTifSourceConfigDto = new SATIFSourceConfigDto(saTifSourceConfigResponse);
                                                        listener.onResponse(returnedSaTifSourceConfigDto);
                                                    }, e -> {
                                                        log.error("Failed to index threat intel source config with id [{}]", updatedSaTifSourceConfig.getId());
                                                        listener.onFailure(e);
                                                    }
                                            ));
                                },
                                e -> {
                                    log.error("Failed to download and save IOCs for source config [{}]", updatedSaTifSourceConfig.getId());
                                    markSourceConfigAsAction(updatedSaTifSourceConfig, TIFJobState.REFRESH_FAILED, ActionListener.wrap(
                                            r -> {
                                                log.info("Set threat intel source config as REFRESH_FAILED for [{}]", updatedSaTifSourceConfig.getId());
                                                listener.onFailure(new OpenSearchException("Set threat intel source config as REFRESH_FAILED for [{}]", saTifSourceConfigDto.getId()));
                                            }, ex -> {
                                                log.error("Failed to set threat intel source config as REFRESH_FAILED for [{}]", updatedSaTifSourceConfig.getId());
                                                listener.onFailure(ex);
                                            }
                                    ));
                                    listener.onFailure(e);
                                })
                        );
                    }, e -> {
                        log.error("Failed to get threat intel source config for [{}]", saTifSourceConfigDto.getId());
                        listener.onFailure(e);
                    }
            ));
        } catch (Exception e) {
            log.error("Failed to update IOCs and threat intel source config for [{}]", saTifSourceConfigDto.getId());
            listener.onFailure(e);
        }
    }

    public void internalUpdateTIFSourceConfig(
            final SATIFSourceConfig saTifSourceConfig,
            final ActionListener<SATIFSourceConfig> listener
    ) {
        try {
            saTifSourceConfig.setLastUpdateTime(Instant.now());
            saTifSourceConfigService.updateTIFSourceConfig(saTifSourceConfig, listener);
        } catch (Exception e) {
            log.error("Failed to update threat intel source config [{}]", saTifSourceConfig.getId());
            listener.onFailure(e);
        }
    }

    public void refreshTIFSourceConfig(
            final String saTifSourceConfigId,
            final User user,
            final ActionListener<SATIFSourceConfigDto> listener
    ) {
        saTifSourceConfigService.getTIFSourceConfig(saTifSourceConfigId, ActionListener.wrap(
                saTifSourceConfig -> {
                    if (TIFJobState.AVAILABLE.equals(saTifSourceConfig.getState()) == false && TIFJobState.REFRESH_FAILED.equals(saTifSourceConfig.getState()) == false) {
                        log.error("Invalid TIF job state. Expecting {} or {} but received {}", TIFJobState.AVAILABLE, TIFJobState.REFRESH_FAILED, saTifSourceConfig.getState());
                        listener.onFailure(new OpenSearchException("Invalid TIF job state. Expecting {} or {} but received {}", TIFJobState.AVAILABLE, TIFJobState.REFRESH_FAILED, saTifSourceConfig.getState()));
                        return;
                    }

                    // set the last refreshed user
                    if (user != null) {
                        saTifSourceConfig.setLastRefreshedUser(user);
                    }

                    // REFRESH FLOW
                    log.info("Refreshing IOCs and updating threat intel source config"); // place holder

                    markSourceConfigAsAction(saTifSourceConfig, TIFJobState.REFRESHING, ActionListener.wrap(
                            updatedSourceConfig -> {
                                // TODO: download and save iocs listener should return the source config, sync up with @hurneyt
                                downloadAndSaveIOCs(updatedSourceConfig, ActionListener.wrap(
                                        // 1. call refresh IOC method (download and save IOCs)
                                        // 1a. set state to refreshing
                                        // 1b. delete old indices
                                        // 1c. update or create iocs
                                        response -> {
                                            // 2. update source config as succeeded
                                            markSourceConfigAsAction(updatedSourceConfig, TIFJobState.AVAILABLE, ActionListener.wrap(
                                                    r -> {
                                                        log.debug("Set threat intel source config as AVAILABLE for [{}]", updatedSourceConfig.getId());
                                                        SATIFSourceConfigDto returnedSaTifSourceConfigDto = new SATIFSourceConfigDto(updatedSourceConfig);
                                                        listener.onResponse(returnedSaTifSourceConfigDto);
                                                    }, ex -> {
                                                        log.error("Failed to set threat intel source config as AVAILABLE for [{}]", updatedSourceConfig.getId());
                                                        listener.onFailure(ex);
                                                    }
                                            ));
                                        }, e -> {
                                            // 3. update source config as failed
                                            log.error("Failed to download and save IOCs for threat intel source config [{}]", updatedSourceConfig.getId());
                                            markSourceConfigAsAction(updatedSourceConfig, TIFJobState.REFRESH_FAILED, ActionListener.wrap(
                                                    r -> {
                                                        log.debug("Set threat intel source config as REFRESH_FAILED for [{}]", updatedSourceConfig.getId());
                                                        listener.onFailure(new OpenSearchException("Set threat intel source config as REFRESH_FAILED for [{}]", updatedSourceConfig.getId()));
                                                    }, ex -> {
                                                        log.error("Failed to set threat intel source config as REFRESH_FAILED for [{}]", updatedSourceConfig.getId());
                                                        listener.onFailure(ex);
                                                    }
                                            ));
                                            listener.onFailure(e);
                                        }));
                                }, ex -> {
                                log.error("Failed to set threat intel source config as REFRESHING for [{}]", saTifSourceConfig.getId());
                                listener.onFailure(ex);
                            }
                    ));
                }, e -> {
                    log.error("Failed to get threat intel source config [{}]", saTifSourceConfigId);
                    listener.onFailure(e);
                }
        ));
    }

    /**
     * @param saTifSourceConfigId
     * @param listener
     */
    public void deleteTIFSourceConfig(
            final String saTifSourceConfigId,
            final ActionListener<DeleteResponse> listener
    ) {
        saTifSourceConfigService.getTIFSourceConfig(saTifSourceConfigId, ActionListener.wrap(
                saTifSourceConfig -> {
                    // Check if all threat intel monitors are deleted
                    saTifSourceConfigService.checkAndEnsureThreatIntelMonitorsDeleted(ActionListener.wrap(
                            isDeleted -> {
                                onDeleteThreatIntelMonitors(saTifSourceConfigId, listener, saTifSourceConfig, isDeleted);
                            }, e -> {
                                log.error("Failed to check if all threat intel monitors are deleted or if multiple threat intel source configs exist");
                                listener.onFailure(e);
                            }
                    ));
                }, e -> {
                    log.error("Failed to get threat intel source config for [{}]", saTifSourceConfigId);
                    if (e instanceof IndexNotFoundException) {
                        listener.onFailure(new OpenSearchException("Threat intel source config [{}] not found", saTifSourceConfigId));
                    } else {
                        listener.onFailure(e);
                    }
                }
        ));
    }

    public IocStoreConfig deleteOldIocIndices (
            final SATIFSourceConfig saTifSourceConfig,
            ActionListener<Void> listener
    ) {
        Map<String, List<String>> iocToAliasMap = ((DefaultIocStoreConfig) saTifSourceConfig.getIocStoreConfig()).getIocMapStore();
        List<String> iocTypes = saTifSourceConfig.getIocTypes();
        String type = iocTypes.get(0); // just grabbing the first ioc type we see since all the indices are stored

        List<String> iocIndicesDeleted = new ArrayList<>();
        String alias = "dummyAlias"; // TODO: dummy alias for now, will replace after rollover is set
        StepListener<List<String>> deleteIocIndicesByAgeListener = new StepListener<>();
        checkAndDeleteOldIocIndicesByAge(iocToAliasMap.get(type), deleteIocIndicesByAgeListener, alias);
        deleteIocIndicesByAgeListener.whenComplete(
                iocIndicesDeletedByAge-> {
                    // removing the indices deleted by age from the ioc map
                    for (String indexName: iocIndicesDeletedByAge) {
                        iocToAliasMap.get(type).remove(indexName);
                    }

                    // add the indices delete by age to indices deleted by type
                    iocIndicesDeleted.addAll(iocIndicesDeletedByAge);

                    // next delete the ioc indices by size
                    checkAndDeleteOldIocIndicesBySize(iocToAliasMap.get(type), alias, ActionListener.wrap(
                            iocIndicesDeletedBySize -> {
                                for (String indexName: iocIndicesDeletedBySize) {
                                    iocToAliasMap.get(type).remove(indexName);
                                }
                                iocIndicesDeleted.addAll(iocIndicesDeletedBySize);
                                listener.onResponse(null);
                            }, e -> {
                                // add error log
                                listener.onFailure(e);
                            }
                    ));
                }, e -> {
                    // add error log
                    listener.onFailure(e);
                });

        // delete the iocs that were deleted from the store config for the other ioc types
        saTifSourceConfig.getIocTypes().forEach(iocType -> {
            if (iocType.equals(type) == false) {
                for (String indexName: iocIndicesDeleted) {
                    iocToAliasMap.get(iocType).remove(indexName);
                }
            }
        });
        return new DefaultIocStoreConfig(iocToAliasMap);
    }

    // Method checks if index is greater than retention period
    private void checkAndDeleteOldIocIndicesByAge(
            List<String> indices,
            StepListener<List<String>> stepListener,
            String alias
    ) {
        log.info("Delete old IOC indices by age");
        saTifSourceConfigService.getClusterState( // get the cluster state to check the age of the indices
                indices,
                ActionListener.wrap(
                        clusterStateResponse -> {
                            List<String> indicesToDelete = new ArrayList<>();
                            if (!clusterStateResponse.getState().metadata().getIndices().isEmpty()) {
                                log.info("Checking if we should delete indices: [" + indicesToDelete + "]");
                                indicesToDelete = getIocIndicesToDeleteByAge(clusterStateResponse, alias);
                                saTifSourceConfigService.deleteAllOldIocHistoryIndices(indicesToDelete);
                            } else {
                                log.info("No old IOC indices to delete");
                            }
                            stepListener.onResponse(indicesToDelete);
                        }, e -> {
                            log.error("Failed to get the cluster metadata");
                            stepListener.onFailure(e);
                        }
                )
        );
    }

    // check if index is greater than retention period
    private void checkAndDeleteOldIocIndicesBySize(
            List<String> indices,
            String alias,
            ActionListener<List<String>> listener
    ) {
        log.info("Delete old IOC indices by size");
        // get new cluster state after deleting indices past retention period
        saTifSourceConfigService.getClusterState(
                indices,
                ActionListener.wrap(
                        clusterStateResponse -> {
                            List<String> indicesToDelete = new ArrayList<>();
                            if (!clusterStateResponse.getState().metadata().getIndices().isEmpty()) {
                                List<String> concreteIndices = getConcreteIndices(alias); // storing both alias and concrete index
                                Integer numIndicesToDelete = numOfIndicesToDelete(concreteIndices);
                                if (numIndicesToDelete > 0) {
                                    indicesToDelete = getIocIndicesToDeleteBySize(clusterStateResponse, numIndicesToDelete, concreteIndices, alias);
                                    log.info("Checking if we should delete indices: [" + indicesToDelete + "]");
                                    if (indicesToDelete.size() != numIndicesToDelete) {
                                        log.error("Number of indices to delete and retrieved index names not equivalent"); // TODO check this
                                    }
                                    saTifSourceConfigService.deleteAllOldIocHistoryIndices(indicesToDelete);
                                    listener.onResponse(indicesToDelete);
                                } else {
                                    log.info("No old IOC indices to delete");
                                    listener.onResponse(indicesToDelete);
                                }
                            } else {
                                log.info("No old IOC indices to delete");
                                listener.onResponse(indicesToDelete);
                            }
                        }, e -> {
                            log.error("Failed to get the cluster metadata");
                            listener.onFailure(e);
                        }
                )
        );
    }

    public List<String> getIocIndicesToDeleteByAge(
            ClusterStateResponse clusterStateResponse,
            String alias
    ) {
        List<String> indicesToDelete = new ArrayList<>();
        String writeIndex = IndexUtils.getWriteIndex(alias, clusterStateResponse.getState());
        Long maxRetentionPeriod = clusterService.getClusterSettings().get(SecurityAnalyticsSettings.IOC_INDEX_RETENTION_PERIOD).millis();

        // for every index metadata, check if the age is greater than the retention period
        for (IndexMetadata indexMetadata : clusterStateResponse.getState().metadata().indices().values()) {
            Long creationTime = indexMetadata.getCreationDate();
            if ((Instant.now().toEpochMilli() - creationTime) > maxRetentionPeriod) {
                // check that the index is not the current write index
                String indexToDelete = indexMetadata.getIndex().getName();
                if (indexToDelete.equals(writeIndex) == false) {
                    indicesToDelete.add(indexToDelete);
                }
            }
        }
        return indicesToDelete;
    }

    public List<String> getIocIndicesToDeleteBySize(
            ClusterStateResponse clusterStateResponse,
            Integer numOfIndices,
            List<String> concreteIndices,
            String alias
    ) {
        List<String> indicesToDelete = new ArrayList<>();
        String writeIndex = IndexUtils.getWriteIndex(alias, clusterStateResponse.getState());

        for (int i = 0; i < numOfIndices; i++) {
            String indexToDelete = getOldestIndexByCreationDate(concreteIndices, clusterStateResponse.getState(), indicesToDelete);
            if (indexToDelete.equals(writeIndex) == false ) { // theoretically this should never be true (never be the write index)
                indicesToDelete.add(indexToDelete);
            }
        }
        return indicesToDelete;
    }

    private static String getOldestIndexByCreationDate(
            List<String> concreteIndices,
            ClusterState clusterState,
            List<String> indicesToDelete
    ) {
        final SortedMap<String, IndexAbstraction> lookup = clusterState.getMetadata().getIndicesLookup();
        long minCreationDate = Long.MAX_VALUE;
        String oldestIndex = null;
        for (String indexName : concreteIndices) {
            IndexAbstraction index = lookup.get(indexName);
            IndexMetadata indexMetadata = clusterState.getMetadata().index(indexName);
            if(index != null && index.getType() == IndexAbstraction.Type.CONCRETE_INDEX) {
                if (indexMetadata.getCreationDate() < minCreationDate && indicesToDelete.contains(indexName) == false) {
                    minCreationDate = indexMetadata.getCreationDate();
                    oldestIndex = indexName;
                }
            }
        }
        return oldestIndex;
    }

    private List<String> getConcreteIndices(String alias) {
        ClusterState state = this.clusterService.state();
        String[] concreteIndices = indexNameExpressionResolver.concreteIndexNames(
                state,
                IndicesOptions.lenientExpand(),
                false,
                alias
        );
        return new ArrayList<>(List.of(concreteIndices));
    }

    private Integer numOfIndicesToDelete(List<String> concreteIndices) {
        Integer maxIndicesPerAlias = clusterService.getClusterSettings().get(SecurityAnalyticsSettings.IOC_INDICES_PER_ALIAS);
        if (concreteIndices.size() > maxIndicesPerAlias ) {
            return concreteIndices.size() - maxIndicesPerAlias;
        }
        return 0;
    }


    private void onDeleteThreatIntelMonitors(String saTifSourceConfigId, ActionListener<DeleteResponse> listener, SATIFSourceConfig saTifSourceConfig, Boolean isDeleted) {
        if (isDeleted == false) {
            listener.onFailure(new IllegalArgumentException("All threat intel monitors need to be deleted before deleting last threat intel source config"));
        } else {
            log.debug("All threat intel monitors are deleted or multiple threat intel source configs exist, can delete threat intel source config [{}]", saTifSourceConfigId);
            markSourceConfigAsAction(
                    saTifSourceConfig,
                    TIFJobState.DELETING,
                    ActionListener.wrap(
                            updateSaTifSourceConfigResponse -> {
                                // TODO: Delete all IOCs associated with source config then delete source config, sync up with @hurneyt
                                saTifSourceConfigService.deleteTIFSourceConfig(saTifSourceConfig, ActionListener.wrap(
                                        deleteResponse -> {
                                            log.debug("Successfully deleted threat intel source config [{}]", saTifSourceConfig.getId());
                                            listener.onResponse(deleteResponse);
                                        }, e -> {
                                            log.error("Failed to delete threat intel source config [{}]", saTifSourceConfigId);
                                            listener.onFailure(e);
                                        }
                                ));
                            }, e -> {
                                log.error("Failed to update threat intel source config with state as {}", TIFJobState.DELETING);
                                listener.onFailure(e);
                            }
                    ));

        }
    }

    public void markSourceConfigAsAction(final SATIFSourceConfig saTifSourceConfig, TIFJobState state, ActionListener<SATIFSourceConfig> actionListener) {
        saTifSourceConfig.setState(state);
        try {
            internalUpdateTIFSourceConfig(saTifSourceConfig, actionListener);
        } catch (Exception e) {
            log.error("Failed to mark threat intel source config as {} for [{}]", state, saTifSourceConfig.getId(), e);
            actionListener.onFailure(e);
        }
    }

    /**
     * Converts the DTO to entity when creating the source config
     *
     * @param saTifSourceConfigDto
     * @return saTifSourceConfig
     */
    public SATIFSourceConfig convertToSATIFConfig(SATIFSourceConfigDto saTifSourceConfigDto, IocStoreConfig iocStoreConfig, TIFJobState state, User createdByUser) {
        return new SATIFSourceConfig(
                saTifSourceConfigDto.getId(),
                saTifSourceConfigDto.getVersion(),
                saTifSourceConfigDto.getName(),
                saTifSourceConfigDto.getFormat(),
                saTifSourceConfigDto.getType(),
                saTifSourceConfigDto.getDescription(),
                createdByUser,
                saTifSourceConfigDto.getCreatedAt(),
                saTifSourceConfigDto.getSource(),
                saTifSourceConfigDto.getEnabledTime(),
                saTifSourceConfigDto.getLastUpdateTime(),
                saTifSourceConfigDto.getSchedule(),
                state,
                saTifSourceConfigDto.getRefreshType(),
                saTifSourceConfigDto.getLastRefreshedTime(),
                saTifSourceConfigDto.getLastRefreshedUser(),
                saTifSourceConfigDto.isEnabled(),
                iocStoreConfig,
                saTifSourceConfigDto.getIocTypes()
        );
    }

    private SATIFSourceConfig updateSaTifSourceConfig(SATIFSourceConfigDto saTifSourceConfigDto, SATIFSourceConfig saTifSourceConfig) {
        return new SATIFSourceConfig(
                saTifSourceConfig.getId(),
                saTifSourceConfig.getVersion(),
                saTifSourceConfigDto.getName(),
                saTifSourceConfigDto.getFormat(),
                saTifSourceConfigDto.getType(),
                saTifSourceConfigDto.getDescription(),
                saTifSourceConfig.getCreatedByUser(),
                saTifSourceConfig.getCreatedAt(),
                saTifSourceConfigDto.getSource(),
                saTifSourceConfig.getEnabledTime(),
                saTifSourceConfig.getLastUpdateTime(),
                saTifSourceConfigDto.getSchedule(),
                saTifSourceConfig.getState(),
                saTifSourceConfigDto.getRefreshType(),
                saTifSourceConfig.getLastRefreshedTime(),
                saTifSourceConfig.getLastRefreshedUser(),
                saTifSourceConfigDto.isEnabled(),
                saTifSourceConfig.getIocStoreConfig(),
                saTifSourceConfigDto.getIocTypes()
        );
    }

}
