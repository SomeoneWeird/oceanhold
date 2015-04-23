
import { EventEmitter } from "events";

import { readFileSync } from "fs";

import { resolve } from "path";

import frida from "frida";

import async from "async";

const clientJS = readFileSync(resolve(__dirname, "../js/client.js")).toString();

class Process extends EventEmitter {

  constructor(data) {

    super();

    for(var k in data) {
      if(k === "PID") data[k] = parseInt(data[k]);
      this[k] = data[k];
    }

    this.externalModules = {};
    this.externalCalls = {};

  }

  inject(callback = () => {}) {

    frida.attach(this.PID).then(session => {

      this.session = session;

      this.session.createScript(clientJS).then(script => {

        this.script = script;

        this.script.events.listen('message', this.emit.bind(this));

      });

      return callback(session);

    }).catch(function(err) {

      return callback(err);

    });

  }

  fetchExportFunctions(callback) {

    this.on("getModules", modules => {

      async.each(modules, (module, done) => {

        this.externalModules[module] = [];

        this.on(`getExports-${module}`, exports => {

          this.externalModules[module] = exports;

          done();

        });

      }, () => {

        callback(null, this.externalModules);

      });

    });

    this.script.postMessage({
      name: "getModules"
    });

  }

  trackCalls() {

    this.fetchExportFunctions((err, modules) => {

      for(let k in modules) {
        let module = modules[k];
        for(let i = 0; i < module.length; i++) {
          let name = module[i];
          this.script.postMessage({
            name: "logFunctionExport",
            module: module,
            _name: name
          });
        }
      }

    });

    this.on('onEnterExport', function(module, name) {

      let emitted = ~(this.externalCalls[module] || []).indexOf(name);

      if(emitted)
        return;

      if(!this.externalCalls[module]) {
        this.externalCalls[module] = [];
      }

      this.externalCalls[module].push(name);

      this.emit('call', module, name);
    

    });

  }

}

export default Process;
