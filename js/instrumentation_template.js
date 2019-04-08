// Based on https://github.com/paulirish/break-on-access.
(function() {
  if (window.exfiltrationInstrumentation === undefined) {
    let trustedScriptIds = {};
    let disableBreak = false;

    let breakOn = function(obj, propertyName, breakFunc) {
      function getPropertyDescriptor(obj, name) {
        let property = Object.getOwnPropertyDescriptor(obj, name);
        let proto = Object.getPrototypeOf(obj);
        while (property === undefined && proto !== null) {
          property = Object.getOwnPropertyDescriptor(proto, name);
          proto = Object.getPrototypeOf(proto);
        }
        return property;
      }

      function blackboxedBreak() {
        if (disableBreak) {
          return;
        }

        if (!console.stackTrace) {
          breakFunc();
          return;
        }

        let stackIsTrusted = true;
        let stackScriptIds = console.stackTrace();
        for (let i = 0; i < stackScriptIds.length; ++i) {
          stackIsTrusted = trustedScriptIds[stackScriptIds[i]];
          if (!stackIsTrusted) {
            break;
          }
        }

        if (!stackIsTrusted) {
          breakFunc();
        };
      };


      let originalProperty = getPropertyDescriptor(obj, propertyName);
      let newProperty = { enumerable: originalProperty.enumerable };

      // write
      if (originalProperty.set) {
        // accessor property
        newProperty.set = function(val) {
          blackboxedBreak();

          originalProperty.set.call(this, val);
        }
      } else if (originalProperty.writable) {
        // value property
        newProperty.set = function(val) {
          blackboxedBreak();

          originalProperty.value = val;
        }
      }

      // read
      newProperty.get = function(val) {
        blackboxedBreak();

        return originalProperty.get ? originalProperty.get.call(this, val) : originalProperty.value;
      }

      Object.defineProperty(obj, propertyName, newProperty);
    };

    {{range .}}
    let shim_{{.Name}} = function() { debugger };
    breakOn({{.Object}}, "{{.Property}}", shim_{{.Name}});
    {{end}}

    window.exfiltrationInstrumentation = true;
    console.log("Exfiltration instrumentation installed")
  }
})();
