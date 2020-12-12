package net.floodlightcontroller.internalsecurity;

import java.util.ArrayList;
import java.util.List;

public class AttackScanner {

    protected enum AttackType{
        NONE,
        IP_SPOOFING,
        PORT_SCANNING,
        MALICIOUS_REQUEST
    }

    protected List<AttackType> attackTypeList;

    public AttackScanner() {
      attackTypeList = new ArrayList<>();
    }


}
