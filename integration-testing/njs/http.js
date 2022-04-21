function echo(r) {
  r.status = 200;
  var h;
  for (h in r.headersIn) {
    // Echo the request headers
    r.headersOut[h] = r.headersIn[h];
  }
  r.sendHeader();

  r.finish();
}

export default { echo };
