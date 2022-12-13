use std::sync::{atomic::AtomicUsize, Arc};

use jsonrpc_core::{serde::de::DeserializeOwned, Call, Output, Request};
use log;
use reqwest::Client;
use serde_json::Value;
use url::Url;
use web3::{
    error::{Error, Result, TransportError},
    futures::future::BoxFuture,
    helpers, RequestId, Transport,
};

#[derive(Debug, Clone)]
pub struct CPCHttp {
    client: Client,
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    url: Url,
    id: AtomicUsize,
}

impl CPCHttp {
    /// Create new CPCHttp transport connecting to given URL.
    ///
    /// Note that the http [Client] automatically enables some features like setting the basic auth
    /// header or enabling a proxy from the environment. You can customize it with
    /// [Http::with_client].
    pub fn new(url: &str) -> Result<Self> {
        #[allow(unused_mut)]
        let mut builder = Client::builder();
        #[cfg(not(feature = "wasm"))]
        {
            builder = builder.user_agent(headers::HeaderValue::from_static("web3.rs"));
        }
        let client = builder.build().map_err(|err| {
            Error::Transport(TransportError::Message(format!(
                "failed to build client: {}",
                err
            )))
        })?;
        Ok(Self::with_client(client, url.parse()?))
    }

    /// Like `new` but with a user provided client instance.
    pub fn with_client(client: Client, url: Url) -> Self {
        Self {
            client,
            inner: Arc::new(Inner {
                url,
                id: AtomicUsize::new(0),
            }),
        }
    }

    fn next_id(&self) -> RequestId {
        self.inner
            .id
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
    }

    fn new_request(&self) -> (Client, Url) {
        (self.client.clone(), self.inner.url.clone())
    }
}

impl Transport for CPCHttp {
    type Out = BoxFuture<'static, Result<Value>>;

    fn prepare(&self, method: &str, params: Vec<Value>) -> (RequestId, Call) {
        let id = self.next_id();
        let request = helpers::build_request(id, method, params);
        (id, request)
    }

    fn send(&self, id: RequestId, call: Call) -> Self::Out {
        let (client, url) = self.new_request();
        Box::pin(async move {
            let output: Output = execute_rpc(&client, url, &Request::Single(call), id).await?;
            helpers::to_result_from_output(output)
        })
    }

    fn execute(&self, method: &str, params: Vec<jsonrpc_core::Value>) -> Self::Out {
        let (id, request) = self.prepare(method, params);
        self.send(id, request)
    }
}

async fn execute_rpc<T: DeserializeOwned>(
    client: &Client,
    url: Url,
    request: &Request,
    id: RequestId,
) -> Result<T> {
    log::debug!(
        "[id:{}] sending request: {:?}",
        id,
        serde_json::to_string(&request)?
    );
    let url_1 = serde_json::to_string(&request)?;
    let response = client.post(url).json(request).send().await.map_err(|err| {
        Error::Transport(TransportError::Message(format!(
            "failed to send request: {}",
            err
        )))
    })?;
    let status = response.status();
    let response = response.bytes().await.map_err(|err| {
        Error::Transport(TransportError::Message(format!(
            "failed to read response bytes: {}",
            err
        )))
    })?;
    let mut response = response.to_vec();
    if url_1.contains("eth_getBlock") {
        if response.len() > 2 && response.to_vec()[response.len() - 3] == b'}' {
            response.pop();
            response.pop();
            response.pop();
            // Insert sha3Uncles to compatible ethereum
            let sha3_uncles = b",\"sha3Uncles\":\"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347\"";
            response.append(&mut sha3_uncles.to_vec());
            // Insert difficulty to compatible ethereum
            let difficulty = b",\"difficulty\": \"0x0\"";
            response.append(&mut difficulty.to_vec());
            // Insert uncles to compatible ethereum
            let uncles = b",\"uncles\": []}}";
            response.append(&mut uncles.to_vec());
        }
    }
    log::debug!(
        "[id:{}] received response: {:?}",
        id,
        String::from_utf8_lossy(&response)
    );
    if !status.is_success() {
        return Err(Error::Transport(TransportError::Code(status.as_u16())));
    }
    helpers::arbitrary_precision_deserialize_workaround(&response).map_err(|err| {
        Error::Transport(TransportError::Message(format!(
            "failed to deserialize response: {}",
            err
        )))
    })
}
