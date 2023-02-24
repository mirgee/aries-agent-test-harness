use crate::controllers::Request;
use crate::error::{HarnessError, HarnessErrorType, HarnessResult};
use crate::HarnessAgent;
use actix_web::{post, web, Either, Responder};
use aries_vcx_agent::aries_vcx::common::ledger::transactions::ed25519_public_key_to_did_key;
use aries_vcx_agent::aries_vcx::handlers::out_of_band::receiver::OutOfBandReceiver;
use aries_vcx_agent::aries_vcx::handlers::out_of_band::sender::OutOfBandSender;
use aries_vcx_agent::aries_vcx::messages::a2a::A2AMessage;
use aries_vcx_agent::aries_vcx::messages::diddoc::aries::service::AriesService;
use aries_vcx_agent::aries_vcx::messages::protocols::connection::invite::Invitation;
use aries_vcx_agent::aries_vcx::messages::protocols::issuance::credential_offer::CredentialOffer;
use aries_vcx_agent::aries_vcx::messages::protocols::out_of_band::service_oob::ServiceOob;
use aries_vcx_agent::aries_vcx::messages::protocols::out_of_band::{GoalCode, HandshakeProtocol};
use std::sync::RwLock;

use super::presentation::ProofRequestData;

#[derive(Deserialize)]
pub struct A2AMessageWrapper(A2AMessage);

impl Default for A2AMessageWrapper {
    fn default() -> Self {
        A2AMessageWrapper(A2AMessage::Generic(serde_json::Value::default()))
    }
}

#[derive(Deserialize, Default)]
pub struct CredentialDataWrapper {
    attachments: Vec<CredentialOffer>,
}

#[allow(dead_code)]
#[derive(Deserialize, Default)]
pub struct ProofRequestDataWrapper {
    attachments: Vec<ProofRequestData>,
}

impl HarnessAgent {
    pub async fn create_oob_invitation_with_cred_data(
        &self,
        cred_data: &CredentialDataWrapper,
    ) -> HarnessResult<String> {
        let recipient_keys = vec![ed25519_public_key_to_did_key(
            &self
                .aries_agent
                .profile()
                .inject_wallet()
                .key_for_local_did(&self.aries_agent.issuer_did())
                .await
                .unwrap(),
        )?];
        let service = ServiceOob::AriesService(
            AriesService::create()
                .set_service_endpoint(self.aries_agent.agent_config().service_endpoint)
                .set_recipient_keys(recipient_keys)
                .set_routing_keys(vec![]),
        );
        let cred_offer = cred_data.attachments.last().unwrap().clone();
        let oob_msg = OutOfBandSender::create()
            .set_label("test-label")
            .set_goal_code(&GoalCode::IssueVC)
            .set_goal("To issue credential")
            .append_service(&service)
            .append_handshake_protocol(&HandshakeProtocol::ConnectionV1)
            .unwrap();
        let oob_msg = oob_msg
            .clone()
            .append_a2a_message(
                cred_offer
                    .set_parent_thread_id(&oob_msg.get_id())
                    .to_a2a_message(),
            )
            .unwrap()
            .to_a2a_message();
        Ok(json!({ "state": "invitation-sent", "invitation": oob_msg }).to_string())
    }

    pub async fn create_oob_invitation_with_proof_req(
        &self,
        _proof_req: &ProofRequestDataWrapper,
    ) -> HarnessResult<String> {
        todo!()
    }

    pub async fn receive_oob_invitation(
        &self,
        invitation: &A2AMessageWrapper,
    ) -> HarnessResult<String> {
        let oob_receiver = OutOfBandReceiver::create_from_a2a_msg(&invitation.0).unwrap();
        let connection_id = self
            .aries_agent
            .connections()
            .receive_invitation(Invitation::OutOfBand(oob_receiver.oob.clone()))
            .await?;
        self.aries_agent
            .connections()
            .send_request(&connection_id)
            .await?;
        match oob_receiver.extract_a2a_message()? {
            Some(A2AMessage::CredentialOffer(offer)) => {
                self.aries_agent
                    .holder()
                    .create_from_offer(&connection_id, offer.clone())?;
                Ok(
                    json!({ "state": "invitation-received", "connection_id": connection_id })
                        .to_string(),
                )
            }
            Some(A2AMessage::PresentationRequest(_request)) => {
                unimplemented!()
            }
            _ => Err(HarnessError::from_msg(
                HarnessErrorType::InvalidState,
                "Unexpected message type",
            )),
        }
    }
}

#[post("/send-invitation-message")]
pub async fn create_oob_invitation(
    req: Either<
        web::Json<Request<CredentialDataWrapper>>,
        web::Json<Request<ProofRequestDataWrapper>>,
    >,
    agent: web::Data<RwLock<HarnessAgent>>,
) -> impl Responder {
    match req {
        Either::Left(req) => {
            agent
                .read()
                .unwrap()
                .create_oob_invitation_with_cred_data(&req.data)
                .await
        }
        Either::Right(req) => {
            agent
                .read()
                .unwrap()
                .create_oob_invitation_with_proof_req(&req.data)
                .await
        }
    }
}

#[post("/receive-invitation")]
async fn receive_oob_invitation(
    req: web::Json<Request<A2AMessageWrapper>>,
    agent: web::Data<RwLock<HarnessAgent>>,
) -> impl Responder {
    agent
        .read()
        .unwrap()
        .receive_oob_invitation(&req.data)
        .await
}

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/command/out-of-band")
            .service(create_oob_invitation)
            .service(receive_oob_invitation),
    );
}
