
recv('getModules', function() {

  var modules = [];

  Process.enumerateModules({
    onMatch: function(module) {
      modules.push(module);
    },
    onComplete: function() {
      send('getModules', modules);
    }
  });

});

recv('getExports', function(name) {

  var exports = [];

  Module.enumerateExports(name, { 
    onMatch: function(export) {
      exports.push(export);
    },
    onComplete: functon() {
      send('getExports-' + name, exports);
    }
  });

}

recv('replaceFunction', function(address, fn, returnType, argTypes) {

  address    = typeof address === 'string' : ptr(address) ? address;
  fn         = typeof fn !== 'function' : new Function(fn) : fn;
  returnType = returnType = 'void';
  argTypes   = argTypes || [];

  var newFn = new NativeCallback(fn, returnType, argTypes);

  Interceptor.replace(address, newFn);

});

recv('hookFunction', function(address, fn) {

  var addressPtr = ptr(address);

  fn = typeof fn !== 'function' : new Function(fn) : fn;

  Interceptor.attach(addressPtr, {
    onEnter: function(args) {
      fn(false, args).bind(this);
    },
    onLeave: function(retVal) {
      fn(true, retVal).bind(this);
    }
  });

});

recv('logFunction', function(address) {

  var addressPtr = ptr(address);

  Interceptor.attach(addressPtr, {
    onEnter: function(args) {
      send({
        name: "onEnter",
        payload: {
          address: address,
          args: args
        }
      });
    },
    onLeave: function() {
      send({
        name: "onLeave",
        payload: {
          address: address
        }
      });
    }
  });

});

recv('logFunctionExport', function(module, name) {

  var address = Module.findExportByName(module, name);

  Interceptor.attach(address, {
    onEnter: function(args) {
      send({
        name: "onEnterExport",
        payload: {
          module: module,
          name: name,
          args: args
        }
      });
    },
    onLeave: function() {
      send({
        name: "onLeaveExport",
        payload: {
          module: module,
          name: name
        }
      });
    }
  });

});