/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.action.SAIndexTIFSourceConfigRequest;
import org.opensearch.securityanalytics.threatIntel.action.SAIndexTIFSourceConfigResponse;
import org.opensearch.securityanalytics.threatIntel.action.ThreatIntelIndicesResponse;
import org.opensearch.securityanalytics.threatIntel.common.TIFLockService;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.threatIntel.service.SATIFSourceConfigService;
import org.opensearch.securityanalytics.transport.SecureTransportAction;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.util.ConcurrentModificationException;

import static org.opensearch.securityanalytics.threatIntel.common.TIFLockService.LOCK_DURATION_IN_SECONDS;
import static org.opensearch.securityanalytics.threatIntel.sacommons.IndexTIFSourceConfigAction.INDEX_TIF_SOURCE_CONFIG_ACTION_NAME;

/**
 * Transport action to create job to fetch threat intel feed data and save IoCs
 */
public class TransportIndexTIFSourceConfigAction extends HandledTransportAction<SAIndexTIFSourceConfigRequest, SAIndexTIFSourceConfigResponse> implements SecureTransportAction {
    private static final Logger log = LogManager.getLogger(TransportIndexTIFSourceConfigAction.class);
    private final SATIFSourceConfigService satifConfigService;
    private final TIFLockService lockService;
    private final ThreadPool threadPool;
    private final Settings settings;
    private volatile Boolean filterByEnabled;
    private final TimeValue indexTimeout;


    /**
     * Default constructor
     * @param transportService the transport service
     * @param actionFilters the action filters
     * @param threadPool the thread pool
     * @param lockService the lock service
     */
    @Inject
    public TransportIndexTIFSourceConfigAction(
            final TransportService transportService,
            final ActionFilters actionFilters,
            final ThreadPool threadPool,
            final SATIFSourceConfigService satifConfigService,
            final TIFLockService lockService,
            final Settings settings
    ) {
        super(INDEX_TIF_SOURCE_CONFIG_ACTION_NAME, transportService, actionFilters, SAIndexTIFSourceConfigRequest::new);
        this.threadPool = threadPool;
        this.satifConfigService = satifConfigService;
        this.lockService = lockService;
        this.settings = settings;
        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(this.settings);
        this.indexTimeout = SecurityAnalyticsSettings.INDEX_TIMEOUT.get(this.settings);
    }


    @Override
    protected void doExecute(final Task task, final SAIndexTIFSourceConfigRequest request, final ActionListener<SAIndexTIFSourceConfigResponse> listener) {
        // validate user
        User user = readUserFromThreadContext(this.threadPool);
        String validateBackendRoleMessage = validateUserBackendRoles(user, this.filterByEnabled);

        if (!"".equals(validateBackendRoleMessage)) {
            listener.onFailure(SecurityAnalyticsException.wrap(new OpenSearchStatusException(validateBackendRoleMessage, RestStatus.FORBIDDEN)));
            return;
        }

        retrieveLockAndCreateTIFConfig(request, listener);
    }

    private void retrieveLockAndCreateTIFConfig(SAIndexTIFSourceConfigRequest request, ActionListener<SAIndexTIFSourceConfigResponse> listener) {
        try {
            lockService.acquireLock(request.getTIFConfigDto().getFeed_id(), LOCK_DURATION_IN_SECONDS, ActionListener.wrap(lock -> {
                if (lock == null) {
                    listener.onFailure(
                            new ConcurrentModificationException("another processor is holding a lock on the resource. Try again later")
                    );
                    log.error("another processor is a lock, BAD_REQUEST error", RestStatus.BAD_REQUEST);
                    return;
                }
                try {
                    log.info("hhh retrieve lock and create tif config");
                    SATIFSourceConfigDto satifConfigDto = request.getTIFConfigDto();
//                    satifConfigDto.setCreatedByUser(readUserFromThreadContext(threadPool).getName()); // thread pool is null

                    try {
                        satifConfigService.createIndexAndSaveTIFConfig(satifConfigDto, lock, indexTimeout, new ActionListener<>() {
                            @Override
                            public void onResponse(SATIFSourceConfig satifSourceConfig) {
                                SATIFSourceConfigDto satifSourceConfigDto = new SATIFSourceConfigDto(satifSourceConfig);
                                log.info("hhh the feed id", satifSourceConfigDto.getFeed_id() );
                                listener.onResponse(new SAIndexTIFSourceConfigResponse(satifSourceConfigDto.getFeed_id(), satifSourceConfigDto.getVersion(), RestStatus.OK, satifSourceConfigDto));
                            }
                            @Override
                            public void onFailure(Exception e) {
                                listener.onFailure(e);
                            }
                        });

                    } catch (Exception e) {
                        lockService.releaseLock(lock);
                        listener.onFailure(e);
                        log.error("listener failed when executing", e);
                    }

                } catch (Exception e) {
                    lockService.releaseLock(lock);
                    listener.onFailure(e);
                    log.error("listener failed when executing", e);
                }
            }, exception -> {
                listener.onFailure(exception);
                log.error("execution failed", exception);
            }));
        } catch (Exception e) {
            log.error("Failed to acquire lock for job", e);
            listener.onFailure(e);
        }
    }





//    /**
//     * This method takes lock as a parameter and is responsible for releasing lock
//     * unless exception is thrown
//     */
//    protected void internalDoExecute(
//            final SAIndexTIFConfigRequest request,
//            final LockModel lock,
//            final ActionListener<AcknowledgedResponse> listener
//    ) {
//        StepListener<Void> createIndexStepListener = new StepListener<>();
//        createIndexStepListener.whenComplete(v -> {
//            try {
//                SATIFConfig satifConfig = SATIFConfigService.convertToSATIFConfig(satifConfigDto);
//                satifConfigDao.saveTIFConfig(satifConfig, postIndexingTifJobParameter(satifConfigDto, lock, listener));
//            } catch (Exception e) {
//                listener.onFailure(e);
//            }
//        }, exception -> {
//            lockService.releaseLock(lock);
//            log.error("failed to release lock", exception);
//            listener.onFailure(exception);
//        });
//        // 1st step - create job index if it doesn't exist (.opensearch-sap--job)
//        satifConfigDao.createJobIndexIfNotExists(createIndexStepListener);
//    }


    /**
     * This method takes lock as a parameter and is responsible for releasing lock
     * unless exception is thrown
     */
//    protected ActionListener<IndexResponse> postIndexingTifJobParameter(
//            final SATIFSourceConfigDto satifConfigDto,
//            final LockModel lock,
//            final ActionListener<AcknowledgedResponse> listener
//    ) {
//        return ActionListener.wrap(
//                indexResponse -> {
//                    AtomicReference<LockModel> lockReference = new AtomicReference<>(lock);
//                    createThreatIntelFeedData(satifConfigDto, lockService.getRenewLockRunnable(lockReference), ActionListener.wrap(
//                            threatIntelIndicesResponse -> {
//                                if (threatIntelIndicesResponse.isAcknowledged()) {
//                                    lockService.releaseLock(lockReference.get());
//                                    listener.onResponse(new AcknowledgedResponse(true));
//                                } else {
//                                    listener.onFailure(new OpenSearchStatusException("creation of threat intel feed data failed", RestStatus.INTERNAL_SERVER_ERROR));
//                                }
//                            }, listener::onFailure
//                    ));
//                }, e -> {
//                    lockService.releaseLock(lock);
//                    if (e instanceof VersionConflictEngineException) {
//                        log.error("satifConfigDto already exists");
//                        listener.onFailure(new ResourceAlreadyExistsException("satifConfigDto [{}] already exists", satifConfigDto.getName()));
//                    } else {
//                        log.error("Internal server error");
//                        listener.onFailure(e);
//                    }
//                }
//        );
//    }

    // create empty index -


    protected void createThreatIntelFeedData(final SATIFSourceConfigDto satifConfig, final Runnable renewLock, final ActionListener<ThreatIntelIndicesResponse> listener) {
//        if (TIFJobState.CREATING.equals(tifJobParameter.getState()) == false) {
//            log.error("Invalid tifJobParameter state. Expecting {} but received {}", TIFJobState.CREATING, tifJobParameter.getState());
//            markTIFJobAsCreateFailed(tifJobParameter, listener);
//            return;
//        }
//
//        try {
//            tifJobUpdateService.createThreatIntelFeedData(tifJobParameter, renewLock, listener);
//        } catch (Exception e) {
//            log.error("Failed to create tifJobParameter for {}", tifJobParameter.getName(), e);
//            markTIFJobAsCreateFailed(tifJobParameter, listener);
//        }
    }


//    private void markTIFJobAsCreateFailed(final TIFJobParameter tifJobParameter, final ActionListener<ThreatIntelIndicesResponse> listener) {
//        tifJobParameter.getUpdateStats().setLastFailedAt(Instant.now());
//        tifJobParameter.setState(TIFJobState.CREATE_FAILED);
//        try {
//            tifJobParameterService.updateJobSchedulerParameter(tifJobParameter, listener);
//        } catch (Exception e) {
//            log.error("Failed to mark tifJobParameter state as CREATE_FAILED for {}", tifJobParameter.getName(), e);
//        }
//    }
}

