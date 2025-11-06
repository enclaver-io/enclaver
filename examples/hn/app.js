const express = require('express');
const axios = require('axios');
const https_proxy_agent = require("https-proxy-agent");

const app = express();
const port = 8000;

app.get('/', (req, resOuter) => {
  console.log('Request received!');
  const agent = new https_proxy_agent.HttpsProxyAgent(process.env.HTTPS_PROXY);

  axios.get('https://news.ycombinator.com', {
    proxy: false,
    httpsAgent: agent,
  })
    .then((resInner) => {
      const status = resInner.status;
      const contentType = resInner.headers['content-type'];
      const data = resInner.data;

      resOuter.status(status);
      resOuter.set('content-type', contentType);
      resOuter.send(data);
    });
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
