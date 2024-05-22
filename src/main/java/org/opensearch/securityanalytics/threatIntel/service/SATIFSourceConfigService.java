package org.opensearch.securityanalytics.threatIntel.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.StepListener;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.action.ActionListener;
import org.opensearch.jobscheduler.spi.LockModel;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.common.TIFLockService;
import org.opensearch.securityanalytics.threatIntel.dao.SATIFSourceConfigDao;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.threadpool.ThreadPool;

/**
 * Service class for threat intel feed config
 * Performs the business logic for the
 * Returns the entity(satifconfig) then converting to DTO is done at the transport layer
 */
public class SATIFSourceConfigService {
    private static final Logger log = LogManager.getLogger(SATIFSourceConfigService.class);
    private final SATIFSourceConfigDao satifConfigDao;
    private final TIFLockService lockService;

    /**
     * Default constructor
     * @param lockService the lock service
     */
    @Inject
    public SATIFSourceConfigService(
            final SATIFSourceConfigDao satifConfigDao,
            final TIFLockService lockService
    ) {
        this.satifConfigDao = satifConfigDao;
        this.lockService = lockService;
    }

    // converts the DTO to entity

    /**
     * This method takes lock as a parameter and is responsible for releasing lock
     * unless exception is thrown
     */
    public void createIndexAndSaveTIFConfig(
            final SATIFSourceConfigDto satifConfigDto,
            final LockModel lock,
            final TimeValue indexTimeout,
            final ActionListener<SATIFSourceConfig> listener
    ) {
        StepListener<Void> createIndexStepListener = new StepListener<>();
        createIndexStepListener.whenComplete(v -> {
            try {
                SATIFSourceConfig satifConfig = convertToSATIFConfig(satifConfigDto);
                satifConfigDao.indexTIFSourceConfig(satifConfig, indexTimeout, new ActionListener<>() {
                    @Override
                    public void onResponse(SATIFSourceConfig satifSourceConfig) {
                        satifConfig.setId(satifSourceConfig.getId());
                        satifConfig.setVersion(satifSourceConfig.getVersion());
                        listener.onResponse(satifConfig);
                    }
                    @Override
                    public void onFailure(Exception e) {
                        listener.onFailure(e);
                    }
                });
            } catch (Exception e) {
                listener.onFailure(e);
            }
        }, exception -> {
            lockService.releaseLock(lock);
            log.error("failed to release lock", exception);
            listener.onFailure(exception);
        });
        // 1st step - create job index if it doesn't exist (.opensearch-sap--job)
        satifConfigDao.createJobIndexIfNotExists(createIndexStepListener);
    }


    public SATIFSourceConfig convertToSATIFConfig(SATIFSourceConfigDto satifConfigDto) {
        // might need to do additional configuration
        SATIFSourceConfig satifConfig = new SATIFSourceConfig(
                satifConfigDto.getId(), // set in DTO
                satifConfigDto.getVersion(), // set in DTO
                satifConfigDto.getName(), // comes from request
                satifConfigDto.getFeedFormat(), // comes from request
                satifConfigDto.getFeedType(), // comes from request
                satifConfigDto.getCreatedByUser(),
                satifConfigDto.getCreatedAt(), // set in DTO
                satifConfigDto.getEnabledTime(), // set in DTO
                satifConfigDto.getLastUpdateTime(), // set in DTO
                satifConfigDto.getSchedule(), // comes from request
                satifConfigDto.getState(), // set in DTO
                satifConfigDto.getRefreshType(), // null
                satifConfigDto.getLastRefreshedTime(), // null
                satifConfigDto.getLastRefreshedUser(), //null
                satifConfigDto.isEnabled(), // comes from request
                satifConfigDto.getIocMapStore()
        );
        return satifConfig;
    }

}
