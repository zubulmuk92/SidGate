//! Remontée des retours RTCP du client jusqu'à l'application.
//!
//! La pile WebRTC traite elle-même ce qu'elle sait traiter — une demande de
//! retransmission est servie depuis son tampon d'émission — puis s'arrête là :
//! par défaut, aucun paquet RTCP reçu n'est remis à l'application. Deux retours
//! ne peuvent pourtant être honorés que par elle :
//!
//! - la demande d'image clé (PLI, FIR), puisque c'est l'application qui tient
//!   l'encodeur ;
//! - le rapport de réception, d'où se lit la part de paquets perdus qui pilote
//!   le débit.
//!
//! Cet intercepteur les recopie donc vers la sortie de lecture de la chaîne, et
//! ceux-là seulement. Chaque paquet retenu est remis seul : la pile route un
//! message RTCP d'après son premier paquet, et un retour qui nous concerne ne
//! doit pas dépendre de ce que le navigateur a choisi de placer devant lui.

use std::collections::VecDeque;

use rtc::interceptor::{interceptor, Interceptor, Packet, StreamInfo, TaggedPacket};
use rtc::rtcp::payload_feedbacks::full_intra_request::FullIntraRequest;
use rtc::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtc::rtcp::receiver_report::ReceiverReport;
use rtc::sansio;
use rtc::shared::error::Error;

/// Retours gardés en attente de lecture.
///
/// La boucle de la connexion les lit à mesure ; la borne n'existe que pour
/// qu'un client qui inonderait l'agent de demandes ne fasse pas grossir une
/// file sans fin. Au-delà, les plus anciens sont écartés : un retour périmé ne
/// vaut plus rien.
const MAX_PENDING: usize = 64;

/// Le paquet est-il de ceux que l'application doit voir ?
fn is_application_feedback(packet: &dyn rtc::rtcp::Packet) -> bool {
    let any = packet.as_any();
    any.is::<PictureLossIndication>() || any.is::<FullIntraRequest>() || any.is::<ReceiverReport>()
}

/// Intercepteur recopiant vers l'application les retours RTCP qui la regardent.
#[derive(Interceptor)]
pub struct RtcpForwarder<P> {
    #[next]
    next: P,
    pending: VecDeque<TaggedPacket>,
}

impl<P> RtcpForwarder<P> {
    /// Constructeur à passer à `Registry::with`.
    pub fn builder() -> impl FnOnce(P) -> Self {
        |next| Self {
            next,
            pending: VecDeque::new(),
        }
    }
}

#[interceptor]
impl<P: Interceptor> RtcpForwarder<P> {
    #[overrides]
    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Packet::Rtcp(packets) = &msg.message {
            for packet in packets {
                if !is_application_feedback(packet.as_ref()) {
                    continue;
                }
                if self.pending.len() >= MAX_PENDING {
                    self.pending.pop_front();
                }
                self.pending.push_back(TaggedPacket {
                    now: msg.now,
                    transport: msg.transport,
                    message: Packet::Rtcp(vec![packet.cloned()]),
                });
            }
        }
        // Le message d'origine poursuit sa route : la retransmission et les
        // statistiques de la pile en dépendent.
        self.next.handle_read(msg)
    }

    #[overrides]
    fn poll_read(&mut self) -> Option<Self::Rout> {
        if let Some(packet) = self.pending.pop_front() {
            return Some(packet);
        }
        self.next.poll_read()
    }

    #[overrides]
    fn close(&mut self) -> Result<(), Self::Error> {
        self.pending.clear();
        self.next.close()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtc::interceptor::{NoopInterceptor, Registry};
    use rtc::rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack;
    use rtc::sansio::Protocol;
    use std::time::Instant;

    fn rtcp(packets: Vec<Box<dyn rtc::rtcp::Packet>>) -> TaggedPacket {
        TaggedPacket {
            now: Instant::now(),
            transport: Default::default(),
            message: Packet::Rtcp(packets),
        }
    }

    fn chain() -> impl Interceptor {
        Registry::new().with(RtcpForwarder::builder()).build()
    }

    /// Vide la sortie de lecture et rend les paquets RTCP, un message par entrée.
    fn drain(chain: &mut impl Interceptor) -> Vec<Vec<Box<dyn rtc::rtcp::Packet>>> {
        let mut out = Vec::new();
        while let Some(message) = chain.poll_read() {
            if let Packet::Rtcp(packets) = message.message {
                out.push(packets);
            }
        }
        out
    }

    fn pli() -> Box<dyn rtc::rtcp::Packet> {
        Box::new(PictureLossIndication {
            sender_ssrc: 1,
            media_ssrc: 7,
        })
    }

    #[test]
    fn the_default_chain_alone_delivers_no_rtcp() {
        // Le constat qui justifie ce module : sans lui, tout retour s'arrête
        // dans la pile.
        let mut bare = NoopInterceptor::new();
        bare.handle_read(rtcp(vec![pli()])).unwrap();
        assert!(bare.poll_read().is_none());
    }

    #[test]
    fn keyframe_requests_and_reports_reach_the_application() {
        let mut chain = chain();
        chain.handle_read(rtcp(vec![pli()])).unwrap();
        chain
            .handle_read(rtcp(vec![Box::new(FullIntraRequest::default())]))
            .unwrap();
        chain
            .handle_read(rtcp(vec![Box::new(ReceiverReport::default())]))
            .unwrap();

        let delivered = drain(&mut chain);
        assert_eq!(delivered.len(), 3);
        assert!(delivered[0][0].as_any().is::<PictureLossIndication>());
        assert!(delivered[1][0].as_any().is::<FullIntraRequest>());
        assert!(delivered[2][0].as_any().is::<ReceiverReport>());
    }

    #[test]
    fn each_feedback_is_delivered_on_its_own() {
        // Un message composé : rapport, retransmission, demande d'image clé.
        // La demande ne doit pas rester cachée derrière ce qui la précède.
        let mut chain = chain();
        chain
            .handle_read(rtcp(vec![
                Box::new(ReceiverReport::default()),
                Box::new(TransportLayerNack::default()),
                pli(),
            ]))
            .unwrap();

        let delivered = drain(&mut chain);
        assert_eq!(delivered.len(), 2, "le NACK reste l'affaire de la pile");
        assert!(delivered.iter().all(|message| message.len() == 1));
        assert!(delivered[0][0].as_any().is::<ReceiverReport>());
        assert!(delivered[1][0].as_any().is::<PictureLossIndication>());
    }

    #[test]
    fn other_rtcp_is_not_forwarded() {
        let mut chain = chain();
        chain
            .handle_read(rtcp(vec![Box::new(TransportLayerNack::default())]))
            .unwrap();
        assert!(drain(&mut chain).is_empty());
    }

    #[test]
    fn a_flood_of_requests_keeps_only_the_most_recent() {
        let mut chain = chain();
        for _ in 0..MAX_PENDING * 3 {
            chain.handle_read(rtcp(vec![pli()])).unwrap();
        }
        assert_eq!(drain(&mut chain).len(), MAX_PENDING);
    }
}
