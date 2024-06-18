/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.threatIntel.sacommons.IndexTIFSourceConfigResponse;
import org.opensearch.securityanalytics.threatIntel.sacommons.TIFSourceConfigDto;

import java.io.IOException;

import static org.opensearch.securityanalytics.util.RestHandlerUtils._ID;
import static org.opensearch.securityanalytics.util.RestHandlerUtils._VERSION;

public class SAIndexTIFSourceConfigResponse extends ActionResponse implements ToXContentObject, IndexTIFSourceConfigResponse {
    private final String id;
    private final Long version;
    private final RestStatus status;
    private final SATIFSourceConfigDto saTifSourceConfigDto;

    public SAIndexTIFSourceConfigResponse(String id, Long version, RestStatus status, SATIFSourceConfigDto saTifSourceConfigDto) {
        super();
        this.id = id;
        this.version = version;
        this.status = status;
        this.saTifSourceConfigDto = saTifSourceConfigDto;
    }

    public SAIndexTIFSourceConfigResponse(StreamInput sin) throws IOException {
        this(
                sin.readString(), // tif config id
                sin.readLong(), // version
                sin.readEnum(RestStatus.class), // status
                SATIFSourceConfigDto.readFrom(sin) // SA tif config dto
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeLong(version);
        out.writeEnum(status);
        saTifSourceConfigDto.writeTo(out);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field(_ID, id)
                .field(_VERSION, version);

        builder.startObject("tif_config")
                .field(SATIFSourceConfigDto.FORMAT_FIELD, saTifSourceConfigDto.getFormat())
                .field(SATIFSourceConfigDto.NAME_FIELD, saTifSourceConfigDto.getName())
                .field(SATIFSourceConfigDto.TYPE_FIELD, saTifSourceConfigDto.getType())
                .field(SATIFSourceConfigDto.DESCRIPTION_FIELD, saTifSourceConfigDto.getDescription())
                .field(SATIFSourceConfigDto.STATE_FIELD, saTifSourceConfigDto.getState())
                .field(SATIFSourceConfigDto.ENABLED_TIME_FIELD, saTifSourceConfigDto.getEnabledTime())
                .field(SATIFSourceConfigDto.ENABLED_FIELD, saTifSourceConfigDto.isEnabled())
                .field(SATIFSourceConfigDto.LAST_REFRESHED_TIME_FIELD, saTifSourceConfigDto.getLastRefreshedTime())
                .field(SATIFSourceConfigDto.SCHEDULE_FIELD, saTifSourceConfigDto.getSchedule())
                .field(SATIFSourceConfigDto.SOURCE_FIELD, saTifSourceConfigDto.getSource())
                .field(SATIFSourceConfigDto.CREATED_BY_USER_FIELD, saTifSourceConfigDto.getCreatedByUser())
                .field(SATIFSourceConfigDto.IOC_TYPES_FIELD, saTifSourceConfigDto.getIocTypes())
                .endObject();

        return builder.endObject();
    }
    @Override
    public String getTIFConfigId() {
        return id;
    }
    @Override
    public Long getVersion() {
        return version;
    }
    @Override
    public TIFSourceConfigDto getTIFConfigDto() {
        return saTifSourceConfigDto;
    }
    public RestStatus getStatus() {
        return status;
    }

}