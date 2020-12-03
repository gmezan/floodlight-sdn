package net.floodlightcontroller.mactracker;

import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;

import java.util.ArrayList;
import java.util.List;

public class MACTrackerResource extends ServerResource {
    @Get("json")
    public List<MACTrackerDto> retrieve() {
        IMACTrackerService imts = (IMACTrackerService)getContext().getAttributes().get(IMACTrackerService.class.getCanonicalName());
        List<MACTrackerDto> l = new ArrayList<MACTrackerDto>();
        return imts.getMACTrackerDto();
    }
}
