package org.opensearch.securityanalytics.threatIntel.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.StepListener;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.action.ActionListener;
import org.opensearch.jobscheduler.spi.LockModel;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.common.TIFLockService;
import org.opensearch.securityanalytics.threatIntel.dao.SATIFSourceConfigDao;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;

/**
 * Service class for threat intel feed config
 * Performs the business logic for the
 * Returns the entity(satifconfig) then converting to DTO is done at the transport layer
 */
public class SATIFSourceConfigService {
    private static final Logger log = LogManager.getLogger(SATIFSourceConfigService.class);
    private final SATIFSourceConfigDao satifSourceConfigDao;
    private final TIFLockService lockService;

    /**
     * Default constructor
     * @param satifSourceConfigDao the tif source config dao
     * @param lockService the lock service
     */
    @Inject
    public SATIFSourceConfigService(
            final SATIFSourceConfigDao satifSourceConfigDao,
            final TIFLockService lockService
    ) {
        this.satifSourceConfigDao = satifSourceConfigDao;
        this.lockService = lockService;
    }


    /**
     * This method takes lock as a parameter and is responsible for releasing lock
     * unless exception is thrown
     */
    public void createIndexAndSaveTIFConfig(
            final SATIFSourceConfigDto satifConfigDto,
            final LockModel lock,
            final TimeValue indexTimeout,
            WriteRequest.RefreshPolicy refreshPolicy,
            final ActionListener<SATIFSourceConfig> listener
    ) {
        StepListener<Void> createIndexStepListener = new StepListener<>();
        createIndexStepListener.whenComplete(v -> {
            try {
                SATIFSourceConfig satifSourceConfig = convertToSATIFConfig(satifConfigDto);
                satifSourceConfig.setState(TIFJobState.AVAILABLE);
                satifSourceConfigDao.indexTIFSourceConfig(satifSourceConfig,
                        indexTimeout,
                        refreshPolicy,
                        new ActionListener<>() {
                    @Override
                    public void onResponse(SATIFSourceConfig response) {
                        satifSourceConfig.setFeed_id(response.getFeed_id());
                        satifSourceConfig.setVersion(response.getVersion());
                        listener.onResponse(satifSourceConfig);
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
        satifSourceConfigDao.createJobIndexIfNotExists(createIndexStepListener);
    }

    /**
     * Converts the DTO to entity
     * @param satifSourceConfigDto
     * @return satifSourceConfig
     */
    public SATIFSourceConfig convertToSATIFConfig(SATIFSourceConfigDto satifSourceConfigDto) {
        return new SATIFSourceConfig(
                satifSourceConfigDto.getFeed_id(),
                satifSourceConfigDto.getVersion(),
                satifSourceConfigDto.getName(),
                satifSourceConfigDto.getFeedFormat(),
                satifSourceConfigDto.getFeedType(),
                satifSourceConfigDto.getCreatedByUser(),
                satifSourceConfigDto.getCreatedAt(),
                satifSourceConfigDto.getEnabledTime(),
                satifSourceConfigDto.getLastUpdateTime(),
                satifSourceConfigDto.getSchedule(),
                satifSourceConfigDto.getState(),
                satifSourceConfigDto.getRefreshType(),
                satifSourceConfigDto.getLastRefreshedTime(),
                satifSourceConfigDto.getLastRefreshedUser(),
                satifSourceConfigDto.isEnabled(),
                satifSourceConfigDto.getIocMapStore(),
                satifSourceConfigDto.getIocTypes()
        );
    }

}
