package org.opensearch.securityanalytics.threatIntel.sacommons.monitor;

public class ThreatIntelMonitorActions {
    public static final String INDEX_THREAT_INTEL_MONITOR_ACTION_NAME = "cluster:admin/opensearch/securityanalytics/threatIntel/monitors/write";
    public static final String SEARCH_THREAT_INTEL_MONITOR_ACTION_NAME = "cluster:admin/opensearch/securityanalytics/threatIntel/monitors/search";
    public static final String DELETE_THREAT_INTEL_MONITOR_ACTION_NAME = "cluster:admin/opensearch/securityanalytics/threatIntel/monitors/delete";
    public static final String GET_THREAT_INTEL_ALERTS_ACTION_NAME = "cluster:admin/opensearch/securityanalytics/threatIntel/alerts/get";
    public static final String UPDATE_THREAT_INTEL_ALERT_STATUS_ACTION_NAME = "cluster:admin/opensearch/securityanalytics/threatIntel/alerts/status/update";
}
