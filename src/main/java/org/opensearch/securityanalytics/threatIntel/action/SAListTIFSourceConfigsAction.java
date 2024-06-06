/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.action.ActionType;

import static org.opensearch.securityanalytics.threatIntel.sacommons.IndexTIFSourceConfigAction.LIST_TIF_SOURCE_CONFIGS_ACTION_NAME;

/**
 * List TIF Source Configs Action
 */
public class SAListTIFSourceConfigsAction extends ActionType<SAListTIFSourceConfigsResponse> {

    public static final SAListTIFSourceConfigsAction INSTANCE = new SAListTIFSourceConfigsAction();
    public static final String NAME = LIST_TIF_SOURCE_CONFIGS_ACTION_NAME;
    private SAListTIFSourceConfigsAction() {
        super(NAME, SAListTIFSourceConfigsResponse::new);
    }
}
