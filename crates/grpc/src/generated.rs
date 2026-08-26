// This checked-in module is generated from proto/foundation.proto. It intentionally
// avoids a build-time protoc dependency.
#![allow(
    clippy::default_trait_access,
    clippy::let_unit_value,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::needless_lifetimes,
    clippy::too_many_lines,
    dead_code,
    missing_docs,
    unused_variables
)]

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct ExecuteRequest {
    #[prost(bytes = "bytes", tag = "1")]
    pub payload: ::prost::bytes::Bytes,
}

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct ExecuteResponse {
    #[prost(bytes = "bytes", tag = "1")]
    pub payload: ::prost::bytes::Bytes,
}

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct StreamRequest {
    #[prost(bytes = "bytes", tag = "1")]
    pub payload: ::prost::bytes::Bytes,
}

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct StreamResponse {
    #[prost(bytes = "bytes", tag = "1")]
    pub payload: ::prost::bytes::Bytes,
}

pub mod foundation_client {
    use tonic::codegen::http::Uri;
    use tonic::codegen::{Body, Bytes, CompressionEncoding, GrpcMethod, StdError, http};

    #[derive(Debug, Clone)]
    pub struct FoundationClient<T> {
        inner: tonic::client::Grpc<T>,
    }

    impl<T> FoundationClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::Body>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            Self {
                inner: tonic::client::Grpc::new(inner),
            }
        }

        pub fn with_origin(inner: T, origin: Uri) -> Self {
            Self {
                inner: tonic::client::Grpc::with_origin(inner, origin),
            }
        }

        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.send_compressed(encoding);
            self
        }

        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.accept_compressed(encoding);
            self
        }

        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_decoding_message_size(limit);
            self
        }

        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_encoding_message_size(limit);
            self
        }

        pub async fn execute(
            &mut self,
            request: impl tonic::IntoRequest<super::ExecuteRequest>,
        ) -> Result<tonic::Response<super::ExecuteResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|_| tonic::Status::unavailable("gRPC service unavailable"))?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/rsk.grpc.v1.Foundation/Execute");
            let mut request = request.into_request();
            request
                .extensions_mut()
                .insert(GrpcMethod::new("rsk.grpc.v1.Foundation", "Execute"));
            self.inner.unary(request, path, codec).await
        }

        pub async fn stream(
            &mut self,
            request: impl tonic::IntoRequest<super::StreamRequest>,
        ) -> Result<tonic::Response<tonic::codec::Streaming<super::StreamResponse>>, tonic::Status>
        {
            self.inner
                .ready()
                .await
                .map_err(|_| tonic::Status::unavailable("gRPC service unavailable"))?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/rsk.grpc.v1.Foundation/Stream");
            let mut request = request.into_request();
            request
                .extensions_mut()
                .insert(GrpcMethod::new("rsk.grpc.v1.Foundation", "Stream"));
            self.inner.server_streaming(request, path, codec).await
        }
    }
}

pub mod foundation_server {
    use tonic::codegen::{
        Arc, Body, BoxFuture, CompressionEncoding, Context, EnabledCompressionEncodings,
        InterceptedService, Poll, StdError, async_trait, http,
    };

    #[async_trait]
    pub trait Foundation: Send + Sync + 'static {
        async fn execute(
            &self,
            request: tonic::Request<super::ExecuteRequest>,
        ) -> Result<tonic::Response<super::ExecuteResponse>, tonic::Status>;

        type StreamStream: tonic::codegen::tokio_stream::Stream<
                Item = Result<super::StreamResponse, tonic::Status>,
            > + Send
            + 'static;

        async fn stream(
            &self,
            request: tonic::Request<super::StreamRequest>,
        ) -> Result<tonic::Response<Self::StreamStream>, tonic::Status>;
    }

    #[derive(Debug)]
    pub struct FoundationServer<T> {
        inner: Arc<T>,
        accept_compression_encodings: EnabledCompressionEncodings,
        send_compression_encodings: EnabledCompressionEncodings,
        max_decoding_message_size: Option<usize>,
        max_encoding_message_size: Option<usize>,
    }

    impl<T> FoundationServer<T> {
        pub fn new(inner: T) -> Self {
            Self::from_arc(Arc::new(inner))
        }

        pub fn from_arc(inner: Arc<T>) -> Self {
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
                max_decoding_message_size: None,
                max_encoding_message_size: None,
            }
        }

        pub fn with_interceptor<F>(inner: T, interceptor: F) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }

        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.accept_compression_encodings.enable(encoding);
            self
        }

        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.send_compression_encodings.enable(encoding);
            self
        }

        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.max_decoding_message_size = Some(limit);
            self
        }

        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.max_encoding_message_size = Some(limit);
            self
        }
    }

    impl<T, B> tonic::codegen::Service<http::Request<B>> for FoundationServer<T>
    where
        T: Foundation,
        B: Body + Send + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::Body>;
        type Error = std::convert::Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;

        fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: http::Request<B>) -> Self::Future {
            match request.uri().path() {
                "/rsk.grpc.v1.Foundation/Execute" => {
                    struct ExecuteSvc<T: Foundation>(Arc<T>);

                    impl<T: Foundation> tonic::server::UnaryService<super::ExecuteRequest> for ExecuteSvc<T> {
                        type Response = super::ExecuteResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;

                        fn call(
                            &mut self,
                            request: tonic::Request<super::ExecuteRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            Box::pin(
                                async move { <T as Foundation>::execute(&inner, request).await },
                            )
                        }
                    }

                    let accept = self.accept_compression_encodings;
                    let send = self.send_compression_encodings;
                    let max_decode = self.max_decoding_message_size;
                    let max_encode = self.max_encoding_message_size;
                    let inner = Arc::clone(&self.inner);
                    Box::pin(async move {
                        let codec = tonic_prost::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(accept, send)
                            .apply_max_message_size_config(max_decode, max_encode);
                        Ok(grpc.unary(ExecuteSvc(inner), request).await)
                    })
                }
                "/rsk.grpc.v1.Foundation/Stream" => {
                    struct StreamSvc<T: Foundation>(Arc<T>);

                    impl<T: Foundation> tonic::server::ServerStreamingService<super::StreamRequest> for StreamSvc<T> {
                        type Response = super::StreamResponse;
                        type ResponseStream = T::StreamStream;
                        type Future =
                            BoxFuture<tonic::Response<Self::ResponseStream>, tonic::Status>;

                        fn call(
                            &mut self,
                            request: tonic::Request<super::StreamRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            Box::pin(
                                async move { <T as Foundation>::stream(&inner, request).await },
                            )
                        }
                    }

                    let accept = self.accept_compression_encodings;
                    let send = self.send_compression_encodings;
                    let max_decode = self.max_decoding_message_size;
                    let max_encode = self.max_encoding_message_size;
                    let inner = Arc::clone(&self.inner);
                    Box::pin(async move {
                        let codec = tonic_prost::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(accept, send)
                            .apply_max_message_size_config(max_decode, max_encode);
                        Ok(grpc.server_streaming(StreamSvc(inner), request).await)
                    })
                }
                _ => Box::pin(async move {
                    let mut response = http::Response::new(tonic::body::Body::default());
                    response.headers_mut().insert(
                        tonic::Status::GRPC_STATUS,
                        (tonic::Code::Unimplemented as i32).into(),
                    );
                    response.headers_mut().insert(
                        http::header::CONTENT_TYPE,
                        tonic::metadata::GRPC_CONTENT_TYPE,
                    );
                    Ok(response)
                }),
            }
        }
    }

    impl<T> Clone for FoundationServer<T> {
        fn clone(&self) -> Self {
            Self {
                inner: Arc::clone(&self.inner),
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
                max_decoding_message_size: self.max_decoding_message_size,
                max_encoding_message_size: self.max_encoding_message_size,
            }
        }
    }

    pub const SERVICE_NAME: &str = "rsk.grpc.v1.Foundation";

    impl<T> tonic::server::NamedService for FoundationServer<T> {
        const NAME: &'static str = SERVICE_NAME;
    }
}
