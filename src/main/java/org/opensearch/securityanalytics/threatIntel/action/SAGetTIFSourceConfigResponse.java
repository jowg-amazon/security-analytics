/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.threatIntel.sacommons.IndexTIFSourceConfigResponse;
import org.opensearch.securityanalytics.threatIntel.sacommons.TIFSourceConfigDto;

import java.io.IOException;

import static org.opensearch.securityanalytics.util.RestHandlerUtils._ID;
import static org.opensearch.securityanalytics.util.RestHandlerUtils._VERSION;

public class SAGetTIFSourceConfigResponse extends ActionResponse implements ToXContentObject {
    private final String id;

    private final Long version;

    private final RestStatus status;

    private final SATIFSourceConfigDto satifSourceConfigDto;


    public SAGetTIFSourceConfigResponse(String id, Long version, RestStatus status, SATIFSourceConfigDto satifSourceConfigDto) {
        super();
        this.id = id;
        this.version = version;
        this.status = status;
        this.satifSourceConfigDto = satifSourceConfigDto;
    }

    public SAGetTIFSourceConfigResponse(StreamInput sin) throws IOException {
        this(
                sin.readString(), // id
                sin.readLong(), // version
                sin.readEnum(RestStatus.class), // status
                sin.readBoolean()? SATIFSourceConfigDto.readFrom(sin) : null // SA tif config dto
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeLong(version);
        out.writeEnum(status);
        if (satifSourceConfigDto != null) {
            out.writeBoolean((true));
            satifSourceConfigDto.writeTo(out);
        } else {
            out.writeBoolean(false);
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field(_ID, id)
                .field(_VERSION, version);
        builder.startObject("tif_config")
                .field(SATIFSourceConfigDto.FEED_NAME_FIELD, satifSourceConfigDto.getName())
                .field(SATIFSourceConfigDto.FEED_FORMAT_FIELD, satifSourceConfigDto.getFeedFormat())
                .field(SATIFSourceConfigDto.FEED_TYPE_FIELD, satifSourceConfigDto.getFeedType())
                .field(SATIFSourceConfigDto.STATE_FIELD, satifSourceConfigDto.getState())
                .field(SATIFSourceConfigDto.ENABLED_TIME_FIELD, satifSourceConfigDto.getEnabledTime())
                .field(SATIFSourceConfigDto.ENABLED_FIELD, satifSourceConfigDto.isEnabled())
                .field(SATIFSourceConfigDto.LAST_REFRESHED_TIME_FIELD, satifSourceConfigDto.getLastRefreshedTime())
                .field(SATIFSourceConfigDto.SCHEDULE_FIELD, satifSourceConfigDto.getSchedule())
                // source
                .field(SATIFSourceConfigDto.CREATED_BY_USER_FIELD, satifSourceConfigDto.getCreatedByUser())
                .field(SATIFSourceConfigDto.IOC_TYPES_FIELD, satifSourceConfigDto.getIocTypes())
                .endObject();
        return builder.endObject();
    }

    public String getId() {
        return id;
    }

    public Long getVersion() {
        return version;
    }

    public RestStatus getStatus() {
        return status;
    }

    public SATIFSourceConfigDto getDetector() {
        return satifSourceConfigDto;
    }
}