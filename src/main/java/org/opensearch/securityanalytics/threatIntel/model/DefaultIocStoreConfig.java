package org.opensearch.securityanalytics.threatIntel.model;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Model used for the default IOC store configuration
 * Stores the IOC mapping in a map of string to list of strings
 */
public class DefaultIocStoreConfig extends IocStoreConfig implements Writeable, ToXContent {
    private static final Logger log = LogManager.getLogger(DefaultIocStoreConfig.class);
    public static final String DEFAULT_FIELD = "default";
    public static final String IOC_WRITE_INDICES_MAP_FIELD = "ioc_write_indices_map";
    public static final String IOC_ALIASES_MAP_FIELD = "ioc_aliases_map";

    // Maps the IOC types to the list of index/alias names
    private final Map<String, List<String>> iocToWriteIndices; // stores the write indices
    private final Map<String, List<String>> iocToAliases; // stores the aliases


    public DefaultIocStoreConfig(Map<String, List<String>> iocToWriteIndices, Map<String, List<String>> iocToAliases) {
        this.iocToWriteIndices = iocToWriteIndices;
        this.iocToAliases = iocToAliases;
    }

    public DefaultIocStoreConfig(StreamInput sin) throws IOException {
        this.iocToWriteIndices = sin.readMapOfLists(StreamInput::readString, StreamInput::readString);
        this.iocToAliases = sin.readMapOfLists(StreamInput::readString, StreamInput::readString);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeMapOfLists(iocToWriteIndices, StreamOutput::writeString, StreamOutput::writeString);
        out.writeMapOfLists(iocToAliases, StreamOutput::writeString, StreamOutput::writeString);
    }

    public XContentBuilder toXContent(XContentBuilder builder, ToXContent.Params params) throws IOException {
        builder.startObject()
                .field(DEFAULT_FIELD);
        builder.startObject()
                .field(IOC_WRITE_INDICES_MAP_FIELD, iocToWriteIndices)
                .field(IOC_ALIASES_MAP_FIELD, iocToAliases);
        builder.endObject();
        builder.endObject();
        return builder;
    }

    public static DefaultIocStoreConfig parse(XContentParser xcp) throws IOException {
        Map<String, List<String>> iocToWriteIndices = null;
        Map<String, List<String>> iocToAliases = null;

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case DEFAULT_FIELD:
                    break;
                case IOC_WRITE_INDICES_MAP_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        iocToWriteIndices = null;
                    } else {
                        iocToWriteIndices = xcp.map(HashMap::new, p -> {
                            List<String> indices = new ArrayList<>();
                            XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                            while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                                indices.add(xcp.text());
                            }
                            return indices;
                        });
                    }
                    break;
                case IOC_ALIASES_MAP_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        iocToAliases = null;
                    } else {
                        iocToAliases = xcp.map(HashMap::new, p -> {
                            List<String> indices = new ArrayList<>();
                            XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                            while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                                indices.add(xcp.text());
                            }
                            return indices;
                        });
                    }
                    break;
                default:
                    xcp.skipChildren();
            }
        }
        return new DefaultIocStoreConfig(iocToWriteIndices, iocToAliases);
    }

    @Override
    public String name() {
        return DEFAULT_FIELD;
    }

    public Map<String, List<String>> getIocToWriteIndices() {
        return iocToWriteIndices;
    }

    public Map<String, List<String>> getIocToAliases() {
        return iocToAliases;
    }

}
