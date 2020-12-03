package net.floodlightcontroller.mactracker;

import net.floodlightcontroller.restserver.RestletRoutable;
import org.restlet.Context;
import org.restlet.Restlet;
import org.restlet.routing.Router;

public class MACTrackerWebRoutable implements RestletRoutable {
    @Override
    public Restlet getRestlet(Context context) {
        Router router = new Router(context);
        router.attach("/macTracker/json", MACTrackerResource.class);
        return router;
    }

    @Override
    public String basePath() {
        return "/wm/macTracker";
    }
}
