
var getProcesses = require('./lib/processes');
var Process = require('./lib/process');

getProcesses(function(e, processList) {

  var p;

  for(var i = 0; i < processList.length; i++) {
    if(~processList[i].COMMAND.indexOf("hello")) {
      p = processList[i];
      break;
    }
  }

  if(!p) {
    // process has probably died
    throw new Error("invalid process");
  }

  var process = new Process(p);

  process.inject(function(err) {

    if(err) {
      console.error("Error injecting process:", err);
      return process.exit(1);
    }

    process.fetchExports(function() {

      console.log("Process has loaded %d modules.", Object.keys(process.externalModules).length);

      process.on('call', function(call) {

        var module = process.externalModules[call.module];

        var n;

        for(var i = 0; i < module.exports.length; i++) {
          if(module.exports[i].name == call.name) {
            n = module.exports[i];
          }
        }

        if(!n) {
          console.error("Unknown call:", call);
          return;
        }

        console.log("Process called: %s:%s %s", module.name, n.name, "0x" + n.address.toString(16));

      });

      process.trackCalls("hello");

    });

  });   

});