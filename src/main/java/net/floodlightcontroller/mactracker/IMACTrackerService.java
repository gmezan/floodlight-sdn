package net.floodlightcontroller.mactracker;

import net.floodlightcontroller.core.module.IFloodlightService;
import java.util.List;

public interface IMACTrackerService extends IFloodlightService{
    List<MACTrackerDto> getMACTrackerDto();
}
