
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

    process.on('call', function(one, two) {
      console.log("*******", one, two);
    });

    process.trackCalls();

  });   

});