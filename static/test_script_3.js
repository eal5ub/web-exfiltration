window.onload = function() {
  console.log(document.cookie);
  var r = new XMLHttpRequest();
  r.open("GET", "https://httpbin.org/get");
  r.send();
}
