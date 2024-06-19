/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.jobscheduler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.action.ActionListener;
import org.opensearch.extensions.AcknowledgedResponse;
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
import org.opensearch.jobscheduler.spi.ScheduledJobRunner;
import org.opensearch.jobscheduler.spi.utils.LockService;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.common.TIFLockService;
import org.opensearch.securityanalytics.threatIntel.service.SATIFSourceConfigService;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
import org.opensearch.securityanalytics.threatIntel.service.SATIFSourceConfigManagementService;
import org.opensearch.threadpool.ThreadPool;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

/**
 * This is a background task which is responsible for updating threat intel feed iocs and the source config
 */
public class TIFSourceConfigRunner implements ScheduledJobRunner {
    private static final Logger log = LogManager.getLogger(TIFSourceConfigRunner.class);
    private static TIFSourceConfigRunner INSTANCE;
    public static TIFSourceConfigRunner getJobRunnerInstance() {
        if (INSTANCE != null) {
            return INSTANCE;
        }
        synchronized (TIFSourceConfigRunner.class) {
            if (INSTANCE != null) {
                return INSTANCE;
            }
            INSTANCE = new TIFSourceConfigRunner();
            return INSTANCE;
        }
    }

    private ClusterService clusterService;
    private TIFLockService lockService;
    private boolean initialized;
    private ThreadPool threadPool;
    private SATIFSourceConfigManagementService saTifSourceConfigManagementService;
    private SATIFSourceConfigService saTifSourceConfigService;

    private TIFSourceConfigRunner() {
        // Singleton class, use getJobRunner method instead of constructor
    }

    public void initialize(
            final ClusterService clusterService,
            final TIFLockService threatIntelLockService,
            final ThreadPool threadPool,
            final SATIFSourceConfigManagementService saTifSourceConfigManagementService,
            final SATIFSourceConfigService saTifSourceConfigService
    ) {
        this.clusterService = clusterService;
        this.lockService = threatIntelLockService;
        this.threadPool = threadPool;
        this.initialized = true;
        this.saTifSourceConfigManagementService = saTifSourceConfigManagementService;
        this.saTifSourceConfigService = saTifSourceConfigService;
    }

    @Override
    public void runJob(final ScheduledJobParameter jobParameter, final JobExecutionContext context) {
        if (initialized == false) {
            throw new AssertionError("This instance is not initialized");
        }

        if (jobParameter instanceof SATIFSourceConfig == false) {
            log.error("Illegal state exception: job parameter is not instance of TIF Source Config");
            throw new IllegalStateException(
                    "job parameter is not instance of TIF Source Config, type: " + jobParameter.getClass().getCanonicalName()
            );
        }

        if (this.clusterService == null) {
            throw new IllegalStateException("ClusterService is not initialized.");
        }

        if (this.threadPool == null) {
            throw new IllegalStateException("ThreadPool is not initialized.");
        }
        final LockService lockService = context.getLockService(); // todo
        threadPool.generic().submit(retrieveLockAndUpdateConfig((SATIFSourceConfig)jobParameter));
    }

    /**
     * Update threat intel feed config and data
     *
     * Lock is used so that only one of nodes run this task.
     *
     * @param saTifSourceConfig the TIF source config that is scheduled onto the job scheduler
     */
    protected Runnable retrieveLockAndUpdateConfig(final SATIFSourceConfig saTifSourceConfig) {
        log.info("Update job started for a TIF Source Config [{}]", saTifSourceConfig.getId());

        return () -> lockService.acquireLock(
                saTifSourceConfig.getId(),
                TIFLockService.LOCK_DURATION_IN_SECONDS,
                ActionListener.wrap(lock -> {
                    updateSourceConfigAndIOCs(saTifSourceConfig, lockService.getRenewLockRunnable(new AtomicReference<>(lock)),
                            ActionListener.wrap(
                                    r -> lockService.releaseLock(lock),
                                    e -> {
                                        log.error("Failed to update threat intel source config " + saTifSourceConfig.getName(), e);
                                        lockService.releaseLock(lock);
                                    }
                            ));
                }, e -> {
                    log.error("Failed to update. Another processor is holding a lock for job parameter[{}]", saTifSourceConfig.getName());
                })
        );
    }

    protected void updateSourceConfigAndIOCs(final SATIFSourceConfig saTifSourceConfig, final Runnable renewLock, ActionListener<AcknowledgedResponse> listener) {
        // TODO: refactor logic to method in service class that refresh API also calls
        saTifSourceConfigService.getTIFSourceConfig(saTifSourceConfig.getId(), ActionListener.wrap(
                saTifSourceConfigResponse -> {
                    if (saTifSourceConfigResponse == null) {
                        log.info("Threat intel source config [{}] does not exist", saTifSourceConfig.getId());
                        //TODO: listener.onFailure()
                        return;
                    }

                    if (TIFJobState.AVAILABLE.equals(saTifSourceConfigResponse.getState()) == false) {
                        log.error("Invalid TIF job state. Expecting {} but received {}", TIFJobState.AVAILABLE, saTifSourceConfigResponse.getState());
                        //TODO: listener.onFailure()
                        return;
                    }

                    // REFRESH FLOW
                    log.info("Refreshing IOCs and updating threat intel source config"); // place holder
                    saTifSourceConfig.setState(TIFJobState.REFRESHING);
                    saTifSourceConfig.setLastRefreshedTime(Instant.now());
                    saTifSourceConfigManagementService.downloadAndSaveIOCs(saTifSourceConfigResponse, ActionListener.wrap(
                            // 1. call refresh IOC method (download and save IOCs)
                            // 1a. set state to refreshing
                            // 1b. delete old indices
                            // 1c. update or create iocs
                            r -> {
                                // 2. update source config as succeeded
                                saTifSourceConfigResponse.setState(TIFJobState.AVAILABLE);
                                saTifSourceConfigService.updateTIFSourceConfig(saTifSourceConfigResponse, ActionListener.wrap(
                                        updatedSaTifSourceConfig -> {
                                            listener.onResponse(new AcknowledgedResponse(true));
                                        }, e-> {
                                            log.error("Failed to update threat intel source config [{}]", saTifSourceConfigResponse.getId());
                                            listener.onFailure(e);
                                        }
                                ));
                            }, e -> {
                                // 3. update source config as failed
                                log.error("Failed to update and save IOCs for threat intel source config [{}]", saTifSourceConfigResponse.getId());
                                saTifSourceConfigManagementService.markSourceConfigAsAction(saTifSourceConfigResponse, TIFJobState.REFRESH_FAILED, ActionListener.wrap(
                                        r -> {
                                            log.info("Set threat intel source config as REFRESH_FAILED for [{}]", saTifSourceConfigResponse.getId());
                                        }, ex -> {
                                            log.error("Failed to set threat intel source config as REFRESH_FAILED for [{}]", saTifSourceConfigResponse.getId());
                                            listener.onFailure(ex);
                                        }
                                ));
                                listener.onFailure(e);
                            }
                    ));
                }, e -> {
                    log.error("Failed to get threat intel source config [{}]", saTifSourceConfig.getId());
                    listener.onFailure(e);
                }
        ));
    }
}