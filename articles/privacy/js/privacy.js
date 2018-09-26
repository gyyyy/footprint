function privacy() {
  let p = {};
  let search = window.location.search;
  if (search.indexOf('?') === 0) {
    param = search.substr(1).split('&');
    for (let i = 0; i < param.length; i++) {
      let kv = param[i].split('=');
      p[kv[0]] = unescape(kv[1]);
    }
  }
  console.log(p);
  document.getElementById('privacy-content').style.display = 'block';
}