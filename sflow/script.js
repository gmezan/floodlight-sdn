var floodlight = '172.31.64.45';
var controls = {};

//console.log("loggg");

logInfo("loggg");

setFlow('udp_reflection',
 {keys:'ipdestination,udpsourceport',value:'frames'});
setThreshold('udp_reflection_attack',
 {metric:'udp_reflection',value:100,byFlow:true,timeout:2});

setEventHandler(function(evt) {
    logInfo("Event Handler..");
       // don't consider inter-switch links
    var link = topologyInterfaceToLink(evt.agent,evt.dataSource);
    logInfo("link: " + link);
    if(link) return;

    // get port information
    var port = topologyInterfaceToPort(evt.agent,evt.dataSource);
    logInfo("port: " + port);
    if(!port) return;

    // need OpenFlow info to create Ryu filtering rule
    logInfo("port.dpid: " + port.dpid +"\nport.ofport: "+ port.ofport+"\n" + parseInt(port.dpid,16));
    if(!port.dpid || !port.ofport) return;

    // we already have a control for this flow
    logInfo(controls[evt.flowKey]);
    if(controls[evt.flowKey]) return;

    var [ipdestination,udpsourceport] = evt.flowKey.split(',');

    var flow = {
       switch: port.dpid,
       name: "flow_for_mitigate",
       priority: "40000",
       in_port: port.ofport,
       eth_type:"0x800",
       ipv4_dst: ipdestination+"/32",
       ip_proto : "17",
       active : true
    };
    //var msg = {
    // priority:40000,
    // dpid:parseInt(port.dpid,16),
    // match: {
    //  in_port:port.ofport,
     // dl_type:0x800,
     // nw_dst:ipdestination+'/32',
     // nw_proto:17,
    //  tp_src:udpsourceport
    //  }
    //};
    logInfo(flow.switch);
    var resp = http2({
    //url:'http://'+floodlight+':8080/stats/flowentry/add',
     url:'http://'+floodlight+':8080/wm/staticflowpusher/json',
     headers:{'Content-Type':'application/json','Accept':'application/json'},
     operation:'post',
     body: JSON.stringify(flow)
     //body: JSON.stringify(msg)
    });

    controls[evt.flowKey] = {
     time:Date.now(),
     threshold:evt.thresholdID,
     agent:evt.agent,
     metric:evt.dataSource+'.'+evt.metric,
     flow:flow
     //msg:msg
    };

    logInfo("blocking " + evt.flowKey);
},['udp_reflection_attack']);

setIntervalHandler(function() {
 logInfo("Interval Handler ..");
	var now = Date.now();
 for(var key in controls) {
  let rec = controls[key];

  // keep control for at least 10 seconds
  if(now - rec.time < 10000) continue;
  // keep control if threshold still triggered
  if(thresholdTriggered(rec.threshold,rec.agent,rec.metric,key)) continue;

  var resp = http2({
   //url:'http://'+floodlight+':8080/stats/flowentry/delete',
   url:'http://'+floodlight+':8080/wm/staticflowpusher/json',
   headers:{'Content-Type':'application/json','Accept':'application/json'},
   operation:'delete',
   //body: JSON.stringify(rec.msg)
   body: JSON.stringify(rec.flow)
  });

  delete controls[key];

  logInfo("unblocking " + key);
 }
});
