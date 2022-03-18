const comps = function(selector, data) {

  const CONFIG = {
    endpoint: "https://comps2.idmod.org/",
    localize: true,
    context: {
      ApplicationName: "COMPS",
      ClientVersion: 11
    }
  };

  const cookies = {
    /**
     * setItem create or overwrite a cookie of the same key.
     * @external {Boolean|String} CONFIG.localize (from the outer scope) determines scope of cookie storage.
     *
     * @public (to outer scope)
     * @param {String} key is the name of the cookie.
     * @param {String} val is the value of the cookie.
     * @param {varies} end (optional) is time till expiry, null defaults to session, or seconds (31536e3 for a year), Infinity, GMTString, Date object.
     * @param {String} path (optional) is where the cookie will be exclusively readable (e/g "/dashboard").
     * @param {String} location (optional) is where the cookie will be exclusively readable (e/g "comps.idmod.org").
     * @param {Boolean} secure (false by default) determines if cookie will be transmitted only over secure protocol as https.
     * @return {Boolean} true when a cookie has been stored, false when key is null or an illegal term (no cookie written).
     */
    setItem: function (key, val, end, path, location, secure) {

      var domain = null;

      if (!key || /^(?:expires|max\-age|path|domain|secure|true|false)$/i.test(key)) {
        return false;
      }

      if (!!CONFIG.localize && key in cookieItems) {
        domain = typeof location !== "undefined" ?  location : enforceOpenDomain();
      }

      var expires = "";
      if (end) {
        switch (end.constructor) {
          case Number:
            expires = end === Infinity ? "; expires=Fri, 31 Dec 9999 23:59:59 GMT" : "; max-age=" + end;
            break;
          case String:
            expires = "; expires=" + end;
            break;
          case Date:
            expires = "; expires=" + end.toUTCString();
            break;
        }
      }

      document.cookie = encodeURIComponent(key) + "=" + encodeURIComponent(val)
          + expires
          + (!!path ? "; path=" + path : "")
          + (!!secure ? "; secure" : "")
          + (!!domain ? "; domain=" + domain : "");

      return true;
    },

    /**
     * getItem gets a cookie's value.
     *
     * @public (to outer scope)
     * @param {String} key is the name of the cookie.
     * @param {varies} defVal is the default value when cookie is not found.
     * @return {varies} either the cookie value (String) or default.
     */
    getItem: function (key, defVal) {
      if (!key || !this.hasItem(key)) {
        return defVal || null;
      } else {
        return decodeURIComponent(document.cookie.replace(new RegExp("(?:(?:^|.*;)\\s*" + encodeURIComponent(key).replace(/[\-\.\+\*]/g, "\\$&") + "\\s*\\=\\s*([^;]*).*$)|^.*$"), "$1"));
      }
    },

    /**
     * hasItem checks the existence of a cookie of a given key.
     *
     * @public (to outer scope)
     * @param {String} key is the name of the cookie.
     * @return {Boolean} true when the cookie exists.
     */
    hasItem: function (key) {
      if (!key) {
        return false;
      } else {
        return (new RegExp("(?:^|;\\s*)" + encodeURIComponent(key).replace(/[\-\.\+\*]/g, "\\$&") + "\\s*\\=")).test(document.cookie);
      }
    },

    /**
     * removeItem expires a cookie of a given key, path, and domain.
     *
     * @public (to outer scope)
     * @param {String} key is the name of the cookie.
     * @param {String} path (optional) is where the cookie will be exclusively readable (e/g "/dashboard").
     * @param {String} domain (optional) is where the cookie will be exclusively readable (e/g "comps.idmod.org").
     * @return {null}
     */
    removeItem: function (key, path, domain) {
      if (typeof domain === "undefined" && key in cookieItems) {
        /* var domain = enforceOpenDomain(); // Will not work in IE or Edge, so don't. */
      }
      if (this.hasItem(key)) {
        document.cookie = encodeURIComponent(key)
            + "=; expires=Thu, 01 Jan 1970 00:00:00 GMT"
            + (domain ? "; domain=" + domain : "")
            + (path ? "; path=" + path : "");
      }
      return null;
    },

    /**
     * getKeys gets all cookie names available to the document.
     *
     * @public (to outer scope)
     * @return {Array} the document's cookie names.
     */
    getKeys: function () {
      let keys = document.cookie.replace(/((?:^|\s*;)[^\=]+)(?=;|$)|^\s*|\s*(?:\=[^;]*)?(?:\1|$)/g, "").split(/\s*(?:\=[^;]*)?;\s*/);

      for (let length = keys.length, index = 0; index < length; index++) {
        keys[index] = decodeURIComponent(keys[index]);
      }
      return keys;
    }
  };

  /**
   * submitCredentials is the fundamental Request to API for a token.
   * NOTE: No validation here. Supplied credentials are expected to be vetted and well-formed.
   * NOTE: By default, a successful transaction will store Token locally as a cookie.
   *
   * @public by proxy
   * @param {Object} info are { UserName:"value", Password:"value" } required for authentication.
   * @callback {Function} successHandler (optional). The Response's JSON.parse(responseText) and Request XHR are passed to this handler.
   * @callback {Function} failureHandler (optional). The Response's statusText and Request XHR are passed to this handler.
   * @callback {Function} finallyHandler (optional). Fires after all processes, regardless of success or failure.
   */
  const submitCredentials = function (info, successHandler, failureHandler, finallyHandler) {

    let response = {},
        request = new XMLHttpRequest(),
        url = CONFIG.endpoint + "tokens?format=json";

    /**
     * onFailure is a general-purpose facilitator for informing the user of error-like situations.
     * @private
     * @param {Boolean} isHandled is true whenever a callback is expected to resolve the user experience.
     * @param {String} uxMessage (optional) is any message prescribed with contextual relevance.
     */
    const onFailure = function (isHandled, uxMessage) {
      let message = "Sorry, but there was a problem with IDM authentication (see:console).";
      if (!!uxMessage) {
        message = uxMessage;
      } else if ("ResponseMessage" in response && !!response.ResponseMessage) {
        message = response.ResponseMessage;
      }
      // always message the console...
      console.error("idmorg-auth:submitCredentials:", message);
      if (!!failureHandler && failureHandler instanceof Function) {
        failureHandler({ Request: request, Response: message });
      }
    };

    // apply application configurations to credentials object
    for (let property in CONFIG.context) {
      if (CONFIG.context.hasOwnProperty(property)) {
        info[property] = CONFIG.context[property];
      }
    }

    try {

      request.open("POST", url, true);
      request.onreadystatechange = function () {
        if (request.readyState === 4) {
          if (!request.responseText) {
            onFailure(!!failureHandler, null);
            return;
          }

          response = JSON.parse(request.responseText);
          if (request.status === 200) {
            if ("Token" in response && tokenIsViable(response.Token)) {
              if (cookies.setItem(cookieItems.Token, response.Token, Infinity)) {
                console.log("signin!", response);
              } else {
                onFailure(false, "Access requires the browser to accept cookies.");
              }
            } else {
              onFailure(!!successHandler, "Authentication cannot be verified at this time.");
            }
            if (!!successHandler && successHandler instanceof Function) {
              successHandler({ Request: request, Response: response });
            }
          } else {
            if (!!failureHandler && failureHandler instanceof Function) {
              failureHandler({ Request: request, Response: response });
            } else {
              switch (request.status) {
                case 401:
                  onFailure(false, "The supplied credentials do not match a registered account.");
                  break;
                default:
                  onFailure(false, "Authentication cannot be verified at this time.");
              }
            }
          }
        }
        if (!!finallyHandler && finallyHandler instanceof Function) {
          finallyHandler();
        }
      };
      request.setRequestHeader("Content-Type", "application/json");
      request.send(JSON.stringify(info));
    } catch (err) {
      console.error("idmorg-auth:submitCredentials:", err);
      throw err;
    }
  };

  let instance = null
  const execute = function() {

    let key,value,handler,element;

    if (!!selector && !!data && "test" in data) {
      switch(data.test) {
        case "cookies":
          key = cookies.getKeys()[0];
          value = !!key ? cookies.getItem(key) : "no cookies!";
          document.querySelector(selector).textContent = `${data.test}! ${key}: ${value}`;
          break;
        case "signin":
          element = document.querySelector(selector);
          handler = function(info) {
            value = info.Response || "No response";
            element.textContent = `${data.test}! ${value}`;
          };
          submitCredentials(data,handler,handler);
          break;
        case "window":
          if (!!instance) {
            instance.focus();
          } else {
            instance = window.open("https://comps.idmod.org", "_blank");
            setTimeout(function(){
              value = instance.postMessage({
                method:"comps.notifier.notify",
                args:["Hello from Jupyter!",{level:"success",pause:5000}],
                observer:window.location.href,
                callback:"demo"
              }, "https://comps.idmod.org");
              document.querySelector(selector).textContent = `${data.test}! COMPS is launched!`;
            },1000);
          }
          break;
      }

    } else {
      console.error("Expected parameters were not found!");
    }

  }();
};
