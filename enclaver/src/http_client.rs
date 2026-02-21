use hyper::Uri;
use hyper::body::Body;
use hyper_proxy2::{Intercept, Proxy, ProxyConnector};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

pub type HttpProxyClient<B> = Client<ProxyConnector<HttpConnector>, B>;

/// Creates an HTTPS client that uses a proxy
pub fn new_http_proxy_client<B>(proxy_uri: Uri) -> HttpProxyClient<B>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let proxy = Proxy::new(Intercept::All, proxy_uri);
    let connector = HttpConnector::new();
    let proxy_connector = ProxyConnector::from_proxy(connector, proxy).unwrap();

    Client::builder(TokioExecutor::new()).build(proxy_connector)
}
