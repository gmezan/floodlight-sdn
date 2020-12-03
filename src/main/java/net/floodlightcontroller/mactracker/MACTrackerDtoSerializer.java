package net.floodlightcontroller.mactracker;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

import java.io.IOException;

public class MACTrackerDtoSerializer extends JsonSerializer<MACTrackerDto> {

    @Override
    public void serialize(MACTrackerDto value, JsonGenerator jGen, SerializerProvider provider) throws IOException, JsonProcessingException {
        jGen.writeStartObject();
        jGen.writeStringField("MacAddress", value.getMacAddress());
        jGen.writeStringField("AttachmentPoint", value.getAttachmentPoint());
        jGen.writeEndObject();
    }

}
