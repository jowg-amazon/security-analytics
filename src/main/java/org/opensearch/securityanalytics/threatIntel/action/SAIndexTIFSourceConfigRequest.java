/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.rest.RestRequest;
import org.opensearch.securityanalytics.threatIntel.common.ParameterValidator;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.threatIntel.sacommons.IndexTIFSourceConfigRequest;

import java.io.IOException;
import java.util.List;

/**
 * Threat intel feed config creation request
 */
public class SAIndexTIFSourceConfigRequest extends ActionRequest implements IndexTIFSourceConfigRequest {
    private static final ParameterValidator VALIDATOR = new ParameterValidator();
    private String tifSourceConfigId;
    private WriteRequest.RefreshPolicy refreshPolicy;
    private RestRequest.Method method;
    private SATIFSourceConfigDto satifSourceConfigDto;

    public SAIndexTIFSourceConfigRequest(String tifSourceConfigId,
                                         WriteRequest.RefreshPolicy refreshPolicy,
                                         RestRequest.Method method,
                                         SATIFSourceConfigDto satifSourceConfigDto) {
        super();
        this.tifSourceConfigId = tifSourceConfigId;
        this.refreshPolicy = refreshPolicy;
        this.method = method;
        this.satifSourceConfigDto = satifSourceConfigDto;
    }

    public SAIndexTIFSourceConfigRequest(StreamInput sin) throws IOException {
        this(
                sin.readString(), // tif config id
                WriteRequest.RefreshPolicy.readFrom(sin), // refresh policy
                sin.readEnum(RestRequest.Method.class), // method
                SATIFSourceConfigDto.readFrom(sin) // SA tif config dto
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(tifSourceConfigId);
        refreshPolicy.writeTo(out);
        out.writeEnum(method);
        satifSourceConfigDto.writeTo(out);
    }

    @Override
    public String getTIFConfigId() {
        return tifSourceConfigId;
    }

    public void setTIFConfigId(String tifConfigId) {
        this.tifSourceConfigId = tifConfigId;
    }

    @Override
    public SATIFSourceConfigDto getTIFConfigDto() {
        return satifSourceConfigDto;
    }

    public void setTIFConfigDto(SATIFSourceConfigDto saTifConfigDto) {
        this.satifSourceConfigDto = saTifConfigDto;
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException errors = new ActionRequestValidationException();
        List<String> errorMsgs = VALIDATOR.validateTIFJobName(satifSourceConfigDto.getName());
        if (errorMsgs.isEmpty() == false) {
            errorMsgs.forEach(errors::addValidationError);
        }
        return errors.validationErrors().isEmpty() ? null : errors;
    }

}
