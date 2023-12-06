/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.cluster.routing.Preference;
import org.opensearch.core.action.ActionListener;
import org.opensearch.action.ActionRequest;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.lifecycle.LifecycleComponent;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.IndexScopedSettings;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.settings.SettingsFilter;
import org.opensearch.commons.alerting.action.AlertingActions;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.index.IndexSettings;
import org.opensearch.index.codec.CodecServiceFactory;
import org.opensearch.index.engine.EngineFactory;
import org.opensearch.index.mapper.Mapper;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.ClusterPlugin;
import org.opensearch.plugins.EnginePlugin;
import org.opensearch.plugins.MapperPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.plugins.SearchPlugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestHandler;
import org.opensearch.script.ScriptService;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.action.*;
import org.opensearch.securityanalytics.correlation.index.codec.CorrelationCodecService;
import org.opensearch.securityanalytics.correlation.index.mapper.CorrelationVectorFieldMapper;
import org.opensearch.securityanalytics.correlation.index.query.CorrelationQueryBuilder;
import org.opensearch.securityanalytics.indexmanagment.DetectorIndexManagementService;
import org.opensearch.securityanalytics.logtype.BuiltinLogTypeLoader;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.mapper.IndexTemplateManager;
import org.opensearch.securityanalytics.mapper.MapperService;
import org.opensearch.securityanalytics.model.CustomLogType;
import org.opensearch.securityanalytics.resthandler.*;
import org.opensearch.securityanalytics.transport.*;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.util.CorrelationIndices;
import org.opensearch.securityanalytics.util.CorrelationRuleIndices;
import org.opensearch.securityanalytics.util.CustomLogTypeIndices;
import org.opensearch.securityanalytics.util.DetectorIndices;
import org.opensearch.securityanalytics.util.RuleIndices;
import org.opensearch.securityanalytics.util.RuleTopicIndices;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.watcher.ResourceWatcherService;

public class SecurityAnalyticsPlugin extends Plugin implements ActionPlugin, MapperPlugin, SearchPlugin, EnginePlugin, ClusterPlugin {

    private static final Logger log = LogManager.getLogger(SecurityAnalyticsPlugin.class);

    public static final String PLUGINS_BASE_URI = "/_plugins/_security_analytics";
    public static final String MAPPER_BASE_URI = PLUGINS_BASE_URI + "/mappings";
    public static final String MAPPINGS_VIEW_BASE_URI = MAPPER_BASE_URI + "/view";
    public static final String FINDINGS_BASE_URI = PLUGINS_BASE_URI + "/findings";
    public static final String ALERTS_BASE_URI = PLUGINS_BASE_URI + "/alerts";
    public static final String DETECTOR_BASE_URI = PLUGINS_BASE_URI + "/detectors";
    public static final String RULE_BASE_URI = PLUGINS_BASE_URI + "/rules";
    public static final String FINDINGS_CORRELATE_URI = FINDINGS_BASE_URI + "/correlate";
    public static final String LIST_CORRELATIONS_URI = PLUGINS_BASE_URI + "/correlations";
    public static final String CORRELATION_RULES_BASE_URI = PLUGINS_BASE_URI + "/correlation/rules";

    public static final String CUSTOM_LOG_TYPE_URI = PLUGINS_BASE_URI + "/logtype";

    private CorrelationRuleIndices correlationRuleIndices;

    private DetectorIndices detectorIndices;

    private RuleTopicIndices ruleTopicIndices;

    private CorrelationIndices correlationIndices;

    private CustomLogTypeIndices customLogTypeIndices;

    private MapperService mapperService;

    private RuleIndices ruleIndices;

    private DetectorIndexManagementService detectorIndexManagementService;

    private IndexTemplateManager indexTemplateManager;

    private BuiltinLogTypeLoader builtinLogTypeLoader;

    private LogTypeService logTypeService;

    private Client client;

    @Override
    public Collection<Object> createComponents(Client client,
                                               ClusterService clusterService,
                                               ThreadPool threadPool,
                                               ResourceWatcherService resourceWatcherService,
                                               ScriptService scriptService,
                                               NamedXContentRegistry xContentRegistry,
                                               Environment environment,
                                               NodeEnvironment nodeEnvironment,
                                               NamedWriteableRegistry namedWriteableRegistry,
                                               IndexNameExpressionResolver indexNameExpressionResolver,
                                               Supplier<RepositoriesService> repositoriesServiceSupplier) {
        builtinLogTypeLoader = new BuiltinLogTypeLoader();
        logTypeService = new LogTypeService(client, clusterService, xContentRegistry, builtinLogTypeLoader);
        detectorIndices = new DetectorIndices(client.admin(), clusterService, threadPool);
        ruleTopicIndices = new RuleTopicIndices(client, clusterService, logTypeService);
        correlationIndices = new CorrelationIndices(client, clusterService);
        customLogTypeIndices = new CustomLogTypeIndices(client.admin(), clusterService);
        indexTemplateManager = new IndexTemplateManager(client, clusterService, indexNameExpressionResolver, xContentRegistry);
        mapperService = new MapperService(client, clusterService, indexNameExpressionResolver, indexTemplateManager, logTypeService);
        ruleIndices = new RuleIndices(logTypeService, client, clusterService, threadPool);
        correlationRuleIndices = new CorrelationRuleIndices(client, clusterService);
        this.client = client;

        return List.of(
                detectorIndices, correlationIndices, correlationRuleIndices, ruleTopicIndices, customLogTypeIndices, ruleIndices,
                mapperService, indexTemplateManager, builtinLogTypeLoader
        );
    }

    @Override
    public Collection<Class<? extends LifecycleComponent>> getGuiceServiceClasses() {
        return List.of(DetectorIndexManagementService.class, BuiltinLogTypeLoader.class);
    }

    @Override
    public List<RestHandler> getRestHandlers(Settings settings,
                                             RestController restController,
                                             ClusterSettings clusterSettings,
                                             IndexScopedSettings indexScopedSettings,
                                             SettingsFilter settingsFilter,
                                             IndexNameExpressionResolver indexNameExpressionResolver,
                                             Supplier<DiscoveryNodes> nodesInCluster) {
        return List.of(
                new RestAcknowledgeAlertsAction(),
                new RestUpdateIndexMappingsAction(),
                new RestCreateIndexMappingsAction(),
                new RestGetIndexMappingsAction(),
                new RestIndexDetectorAction(),
                new RestGetDetectorAction(),
                new RestSearchDetectorAction(),
                new RestDeleteDetectorAction(),
                new RestGetFindingsAction(),
                new RestGetMappingsViewAction(),
                new RestGetAlertsAction(),
                new RestIndexRuleAction(),
                new RestSearchRuleAction(),
                new RestDeleteRuleAction(),
                new RestValidateRulesAction(),
                new RestGetAllRuleCategoriesAction(),
                new RestSearchCorrelationAction(),
                new RestIndexCorrelationRuleAction(),
                new RestDeleteCorrelationRuleAction(),
                new RestListCorrelationAction(),
                new RestSearchCorrelationRuleAction(),
                new RestIndexCustomLogTypeAction(),
                new RestSearchCustomLogTypeAction(),
                new RestDeleteCustomLogTypeAction()
        );
    }

    @Override
    public List<NamedXContentRegistry.Entry> getNamedXContent() {
        return List.of(
                Detector.XCONTENT_REGISTRY,
                DetectorInput.XCONTENT_REGISTRY,
                Rule.XCONTENT_REGISTRY,
                CustomLogType.XCONTENT_REGISTRY
        );
    }

    @Override
    public Map<String, Mapper.TypeParser> getMappers() {
        return Collections.singletonMap(
                CorrelationVectorFieldMapper.CONTENT_TYPE,
                new CorrelationVectorFieldMapper.TypeParser()
        );
    }

    @Override
    public Optional<EngineFactory> getEngineFactory(IndexSettings indexSettings) {
        return Optional.empty();
    }

    @Override
    public Optional<CodecServiceFactory> getCustomCodecServiceFactory(IndexSettings indexSettings) {
        if (indexSettings.getValue(SecurityAnalyticsSettings.IS_CORRELATION_INDEX_SETTING)) {
            return Optional.of(config -> new CorrelationCodecService(config, indexSettings));
        }
        return Optional.empty();
    }

    @Override
    public List<QuerySpec<?>> getQueries() {
        return Collections.singletonList(new QuerySpec<>(CorrelationQueryBuilder.NAME, CorrelationQueryBuilder::new, CorrelationQueryBuilder::fromXContent));
    }

    @Override
    public List<Setting<?>> getSettings() {
        return List.of(
                SecurityAnalyticsSettings.INDEX_TIMEOUT,
                SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES,
                SecurityAnalyticsSettings.ALERT_HISTORY_ENABLED,
                SecurityAnalyticsSettings.ALERT_HISTORY_ROLLOVER_PERIOD,
                SecurityAnalyticsSettings.ALERT_HISTORY_INDEX_MAX_AGE,
                SecurityAnalyticsSettings.ALERT_HISTORY_MAX_DOCS,
                SecurityAnalyticsSettings.ALERT_HISTORY_RETENTION_PERIOD,
                SecurityAnalyticsSettings.REQUEST_TIMEOUT,
                SecurityAnalyticsSettings.MAX_ACTION_THROTTLE_VALUE,
                SecurityAnalyticsSettings.FINDING_HISTORY_ENABLED,
                SecurityAnalyticsSettings.FINDING_HISTORY_MAX_DOCS,
                SecurityAnalyticsSettings.FINDING_HISTORY_INDEX_MAX_AGE,
                SecurityAnalyticsSettings.FINDING_HISTORY_ROLLOVER_PERIOD,
                SecurityAnalyticsSettings.FINDING_HISTORY_RETENTION_PERIOD,
                SecurityAnalyticsSettings.CORRELATION_HISTORY_MAX_DOCS,
                SecurityAnalyticsSettings.CORRELATION_HISTORY_INDEX_MAX_AGE,
                SecurityAnalyticsSettings.CORRELATION_HISTORY_ROLLOVER_PERIOD,
                SecurityAnalyticsSettings.CORRELATION_HISTORY_RETENTION_PERIOD,
                SecurityAnalyticsSettings.IS_CORRELATION_INDEX_SETTING,
                SecurityAnalyticsSettings.CORRELATION_TIME_WINDOW,
                SecurityAnalyticsSettings.ENABLE_AUTO_CORRELATIONS,
                SecurityAnalyticsSettings.DEFAULT_MAPPING_SCHEMA,
                SecurityAnalyticsSettings.ENABLE_WORKFLOW_USAGE
        );
    }

    @Override
    public List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> getActions() {
        return List.of(
                new ActionPlugin.ActionHandler<>(AckAlertsAction.INSTANCE, TransportAcknowledgeAlertsAction.class),
                new ActionPlugin.ActionHandler<>(UpdateIndexMappingsAction.INSTANCE, TransportUpdateIndexMappingsAction.class),
                new ActionPlugin.ActionHandler<>(CreateIndexMappingsAction.INSTANCE, TransportCreateIndexMappingsAction.class),
                new ActionPlugin.ActionHandler<>(GetIndexMappingsAction.INSTANCE, TransportGetIndexMappingsAction.class),
                new ActionPlugin.ActionHandler<>(IndexDetectorAction.INSTANCE, TransportIndexDetectorAction.class),
                new ActionPlugin.ActionHandler<>(DeleteDetectorAction.INSTANCE, TransportDeleteDetectorAction.class),
                new ActionPlugin.ActionHandler<>(GetMappingsViewAction.INSTANCE, TransportGetMappingsViewAction.class),
                new ActionPlugin.ActionHandler<>(GetDetectorAction.INSTANCE, TransportGetDetectorAction.class),
                new ActionPlugin.ActionHandler<>(SearchDetectorAction.INSTANCE, TransportSearchDetectorAction.class),
                new ActionPlugin.ActionHandler<>(GetFindingsAction.INSTANCE, TransportGetFindingsAction.class),
                new ActionPlugin.ActionHandler<>(GetAlertsAction.INSTANCE, TransportGetAlertsAction.class),
                new ActionPlugin.ActionHandler<>(IndexRuleAction.INSTANCE, TransportIndexRuleAction.class),
                new ActionPlugin.ActionHandler<>(SearchRuleAction.INSTANCE, TransportSearchRuleAction.class),
                new ActionPlugin.ActionHandler<>(DeleteRuleAction.INSTANCE, TransportDeleteRuleAction.class),
                new ActionPlugin.ActionHandler<>(ValidateRulesAction.INSTANCE, TransportValidateRulesAction.class),
                new ActionPlugin.ActionHandler<>(GetAllRuleCategoriesAction.INSTANCE, TransportGetAllRuleCategoriesAction.class),
                new ActionPlugin.ActionHandler<>(CorrelatedFindingAction.INSTANCE, TransportSearchCorrelationAction.class),
                new ActionPlugin.ActionHandler<>(IndexCorrelationRuleAction.INSTANCE, TransportIndexCorrelationRuleAction.class),
                new ActionPlugin.ActionHandler<>(DeleteCorrelationRuleAction.INSTANCE, TransportDeleteCorrelationRuleAction.class),
                new ActionPlugin.ActionHandler<>(AlertingActions.SUBSCRIBE_FINDINGS_ACTION_TYPE, TransportCorrelateFindingAction.class),
                new ActionPlugin.ActionHandler<>(ListCorrelationsAction.INSTANCE, TransportListCorrelationAction.class),
                new ActionPlugin.ActionHandler<>(SearchCorrelationRuleAction.INSTANCE, TransportSearchCorrelationRuleAction.class),
                new ActionHandler<>(IndexCustomLogTypeAction.INSTANCE, TransportIndexCustomLogTypeAction.class),
                new ActionHandler<>(SearchCustomLogTypeAction.INSTANCE, TransportSearchCustomLogTypeAction.class),
                new ActionHandler<>(DeleteCustomLogTypeAction.INSTANCE, TransportDeleteCustomLogTypeAction.class)
        );
    }

    @Override
    public void onNodeStarted(DiscoveryNode localNode) {
//      Trigger initialization of log types
        logTypeService.ensureConfigIndexIsInitialized(new ActionListener<>() {
            @Override
            public void onResponse(Void unused) {
                log.info("LogType config index successfully created and builtin log types loaded");
            }

            @Override
            public void onFailure(Exception e) {
                log.warn("Failed to initialize LogType config index and builtin log types");
            }
        });
      }
}