
import { EventEmitter } from "events";

import fs from "fs";

import path from "path";

import frida from "frida";

import async from "async";

const clientJS = fs.readFileSync(path.resolve(__dirname, "../js/client.js")).toString();

class Process extends EventEmitter {

  constructor(data) {

    super();

    for(var k in data) {
      this[k] = data[k];
    }

    this.externalModules = {};
    this.externalCalls = {};

  }

  inject(callback = () => {}) {

    var err = (e) => callback(e);

    frida.attach(parseInt(this.PID)).then(session => {

      this.session = session;

      this.session.createScript(clientJS).then(script => {

        this.script = script;

        this.script.events.listen('message', (res) => {
          let { name, data } = res.payload || {};
          // console.log("GOT DATA YO:", name);
          this.emit(name, data);
        });

        this.script.load().then(function() {

          return callback(null, session);

        }).catch(err);

      }).catch(err);

    }).catch(err);

  }

  fetchExports(callback) {

    this.session.enumerateModules().then(modules => {

      async.each(modules, (module, done) => {

        let { name } = module;

        this.session.enumerateExports(name).then(e => {

          module.exports = e;

          this.externalModules[name] = module;

          return done();

        }).catch(e => {

          console.log(e);

        });
        
      }, () => {

        return callback(null, this.externalModules);

      });

    });

  }

  trackCalls(moduleName, callback = () => {}) {

    let module = this.externalModules[moduleName];

    let { name, exports } = module;

    async.eachSeries(exports, (ex, done) => {

      this.script.postMessage({
        type: "logFunctionExport",
        payload: {
          module: name,
          name:   ex.name
        }
      });

      setTimeout(done, 20);

    }, function() {

      callback();

    });

    this.on('onEnterExport', function(module, name) {

      this.emit('call', module, name);

      if(!this.externalCalls[module]) {
        this.externalCalls[module] = [];
      }

      if(!~this.externalCalls[module].indexOf(name)) {
        this.externalCalls[module].push(name);
      }

    });

  }

}

export default Process;
