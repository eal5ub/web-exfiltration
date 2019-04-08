window.onload = function() {
  var script = document.createElement("script");
  script.innerHTML = " \
    console.log(document.cookie); \
    var r = new XMLHttpRequest(); \
    r.open('GET', 'https://httpbin.org/get'); \
    r.send(); \
  ";
  document.body.appendChild(script);
};
