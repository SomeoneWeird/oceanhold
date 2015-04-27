
recv('replaceFunction', function(address, fn, returnType, argTypes) {

  address    = typeof address === 'string' ? ptr(address) : address;
  fn         = typeof fn !== 'function' ? new Function(fn) : fn;
  returnType = returnType = 'void';
  argTypes   = argTypes || [];

  var newFn = new NativeCallback(fn, returnType, argTypes);

  Interceptor.replace(address, newFn);

});

recv('hookFunction', function(address, fn) {

  var addressPtr = ptr(address);

  fn = typeof fn !== 'function' ? new Function(fn) : fn;

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

function logFunctionExport() {

  recv('logFunctionExport', function(data) {

    logFunctionExport();

    var module = data.payload.module;
    var name   = data.payload.name;

    var address = Module.findExportByName(module, name);

    // console.log('attaching to', module, name);

    Interceptor.attach(ptr(address), {
      onEnter: function(args) {
        send({
          name: "onEnterExport",
          data: {
            module: module,
            name: name,
            args: args
          }
        });
      },
      onLeave: function() {
        send({
          name: "onLeaveExport",
          data: {
            module: module,
            name: name
          }
        });
      }
    });

  });

}

logFunctionExport();