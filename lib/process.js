
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

      console.log(session);

      this.session.createScript(clientJS).then(script => {

        this.script = script;

        this.script.events.listen('message', (res) => {
          let { name, data } = res.payload || {};
          // console.log("GOT DATA YO:", name);
          this.emit(name, data);
        });

        this.script.load().then(function() {

          return callback(null, session);

        }).catch(function(err) {

          return callback(err);

        });

      }).catch(function(err) {

        return callback(err);

      });

    }).catch(function(err) {

      return callback(err);

    });

  }

  fetchExportFunctions(callback) {

    this.on("getModules", modules => {

      for(var i = 0; i < modules.length; i++) {

        var module = modules[i];
        var name = module.name;

        this.once("getExports-" + name, function(data) {

          console.log(module.name);

          data.forEach(function(d) {
            console.log(" - " + d.name);
          });

        });

        this.script.postMessage({
          type: "getExports",
          payload: {
            name: name
          }
        });

      }


      // console.log(modules[1]);

      // modules.splice(1, 1);

      // modules.reverse();

      // // async.each(modules, (module, done) => {

      // //   this.externalModules[module.name] = module;

      // //   this.once(`getExports-${module.name}`, data => {

      // //     this.externalModules[module.name].exports = data;

      // //     console.log(`${module.name}`);

      // //     data.forEach(function(d) {
      // //       console.log(`- ${d.name} (${d.address})`);
      // //     });

      // //     done();

      // //   });

      // //   this.script.postMessage({
      // //     type: "getExports",
      // //     payload: {
      // //       name: module.name
      // //     }
      // //   });

      // // }, function() {

      // //   console.log("done");
      // //   callback(null, this.externalModules);

      // // });

    });

    this.script.postMessage({
      type: "getModules",
      payload: {}
    });

  }

  trackCalls() {

    this.fetchExportFunctions((err, modules) => {

      console.log("got function exports:", modules);

      // for(let k in modules) {
      //   let module = modules[k];
      //   for(let i = 0; i < module.length; i++) {
      //     let name = module[i];
      //     this.script.postMessage({
      //       type: "logFunctionExport",
      //       payload: {
      //         module: module,
      //         name:   name
      //       }
      //     });
      //   }
      // }

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
