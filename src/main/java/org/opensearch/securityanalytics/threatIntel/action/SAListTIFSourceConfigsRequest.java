/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;
import java.util.Locale;

import static org.opensearch.action.ValidateActions.addValidationError;

/**
 * List threat intel feed source config request
 */
public class SAListTIFSourceConfigsRequest extends ActionRequest {
    public static final String TIF_SOURCE_CONFIG_ID = "tif_source_config_id";

    public SAListTIFSourceConfigsRequest() {
        super();
    }

    public SAListTIFSourceConfigsRequest(StreamInput sin) throws IOException {
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

}
