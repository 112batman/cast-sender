use std::sync::Arc;

use smol::lock::Mutex;

use crate::namespace::media::*;
use crate::{App, Error, Payload, Receiver, Response};

#[derive(Clone, Debug)]
pub struct MediaController {
    app: App,
    receiver: Receiver,

    media_session_id: Arc<Mutex<i32>>,
}

impl MediaController {
    pub fn new(app: App, receiver: Receiver) -> Result<Self, Error> {
        if !app
            .namespaces
            .contains(&crate::namespace::NamespaceUrn::Media)
        {
            return Err(Error::UnsupportedNamespace);
        }

        Ok(Self {
            app,
            receiver,
            media_session_id: Arc::default(),
        })
    }

    pub async fn load<P: Into<LoadRequestData>>(&self, load_request: P) -> Result<(), Error> {
        let response = self
            .receiver
            .send_request(&self.app, Media::Load(load_request.into()))
            .await?;

        Self::handle_error(&response)?;

        if let Payload::Media(Media::MediaStatus(response_data)) = response.payload {
            *self.media_session_id.lock().await = response_data.first().media_session_id;
            Ok(())
        } else {
            Err(Error::NoResponse)
        }
    }

    pub async fn start(&self) -> Result<(), Error> {
        let response = self
            .receiver
            .send_request(
                &self.app,
                Media::Play(RequestData {
                    media_session_id: Some(*self.media_session_id.lock().await),
                }),
            )
            .await?;

        Self::handle_error(&response)?;
        Ok(())
    }

    pub async fn stop(&self) -> Result<(), Error> {
        let response = self
            .receiver
            .send_request(
                &self.app,
                Media::Stop(RequestData {
                    media_session_id: Some(*self.media_session_id.lock().await),
                }),
            )
            .await?;

        Self::handle_error(&response)?;
        Ok(())
    }

    pub async fn pause(&self) -> Result<(), Error> {
        let response = self
            .receiver
            .send_request(
                &self.app,
                Media::Pause(RequestData {
                    media_session_id: Some(*self.media_session_id.lock().await),
                }),
            )
            .await?;

        Self::handle_error(&response)?;
        Ok(())
    }

    fn handle_error(response: &Response) -> Result<(), Error> {
        if let Payload::Media(Media::InvalidRequest(err)) = &response.payload {
            return Err(Error::MediaError(crate::error::MediaError::InvalidRequest(
                err.reason.clone(),
            )));
        }

        if let Payload::Media(Media::InvalidPlayerState) = response.payload {
            return Err(Error::MediaError(
                crate::error::MediaError::InvalidPlayerState,
            ));
        }

        if let Payload::Media(Media::LoadFailed) = response.payload {
            return Err(Error::MediaError(crate::error::MediaError::LoadFailed));
        }

        if let Payload::Media(Media::LoadCancelled) = response.payload {
            return Err(Error::MediaError(crate::error::MediaError::LoadCancelled));
        }

        Ok(())
    }
}
