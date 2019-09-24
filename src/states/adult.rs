// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    common::{
        proxied, Approved, Base, Bootstrapped, BootstrappedNotEstablished, Relocated,
        RelocatedNotEstablished,
    },
    elder::{Elder, ElderDetails},
};
use crate::{
    chain::{
        Chain, ExpectCandidatePayload, GenesisPfxInfo, OnlinePayload, SectionInfo, SectionKeyInfo,
        SendAckMessagePayload,
    },
    error::RoutingError,
    event::Event,
    id::{FullId, PublicId},
    messages::{DirectMessage, HopMessage, RoutingMessage},
    outbox::EventBox,
    parsec::ParsecMap,
    peer_manager::PeerManager,
    peer_map::PeerMap,
    routing_message_filter::RoutingMessageFilter,
    routing_table::{Authority, Prefix},
    state_machine::{State, Transition},
    time::{Duration, Instant},
    timer::Timer,
    xor_name::XorName,
    NetworkService,
};
use itertools::Itertools;
use std::fmt::{self, Display, Formatter};

const POKE_TIMEOUT: Duration = Duration::from_secs(60);

pub struct AdultDetails {
    pub network_service: NetworkService,
    pub event_backlog: Vec<Event>,
    pub full_id: FullId,
    pub gen_pfx_info: GenesisPfxInfo,
    pub min_section_size: usize,
    pub msg_backlog: Vec<RoutingMessage>,
    pub peer_map: PeerMap,
    pub peer_mgr: PeerManager,
    pub routing_msg_filter: RoutingMessageFilter,
    pub timer: Timer,
}

pub struct Adult {
    chain: Chain,
    network_service: NetworkService,
    event_backlog: Vec<Event>,
    full_id: FullId,
    gen_pfx_info: GenesisPfxInfo,
    /// Routing messages addressed to us that we cannot handle until we are established.
    msg_backlog: Vec<RoutingMessage>,
    parsec_map: ParsecMap,
    peer_map: PeerMap,
    peer_mgr: PeerManager,
    poke_timer_token: u64,
    routing_msg_filter: RoutingMessageFilter,
    timer: Timer,
}

impl Adult {
    pub fn from_proving_node(
        details: AdultDetails,
        outbox: &mut dyn EventBox,
    ) -> Result<Self, RoutingError> {
        let public_id = *details.full_id.public_id();
        let poke_timer_token = details.timer.schedule(POKE_TIMEOUT);

        let parsec_map = ParsecMap::new(details.full_id.clone(), &details.gen_pfx_info);
        let chain = Chain::new(
            details.min_section_size,
            public_id,
            details.gen_pfx_info.clone(),
        );

        let mut node = Self {
            chain,
            network_service: details.network_service,
            event_backlog: details.event_backlog,
            full_id: details.full_id,
            gen_pfx_info: details.gen_pfx_info,
            msg_backlog: details.msg_backlog,
            parsec_map,
            peer_map: details.peer_map,
            peer_mgr: details.peer_mgr,
            routing_msg_filter: details.routing_msg_filter,
            timer: details.timer,
            poke_timer_token,
        };

        node.init(outbox)?;
        Ok(node)
    }

    fn init(&mut self, outbox: &mut dyn EventBox) -> Result<(), RoutingError> {
        debug!("{} - State changed to Adult.", self);

        for msg in self.msg_backlog.drain(..).collect_vec() {
            self.dispatch_routing_message(msg, outbox)?;
        }

        Ok(())
    }

    pub fn into_elder(
        self,
        sec_info: SectionInfo,
        old_pfx: Prefix<XorName>,
        outbox: &mut dyn EventBox,
    ) -> Result<State, RoutingError> {
        let details = ElderDetails {
            chain: self.chain,
            network_service: self.network_service,
            event_backlog: self.event_backlog,
            full_id: self.full_id,
            gen_pfx_info: self.gen_pfx_info,
            msg_backlog: self.msg_backlog,
            parsec_map: self.parsec_map,
            peer_map: self.peer_map,
            peer_mgr: self.peer_mgr,
            // we reset the message filter so that the node can correctly process some messages as
            // an Elder even if it has already seen them as an Adult
            routing_msg_filter: RoutingMessageFilter::new(),
            timer: self.timer,
        };

        Elder::from_adult(details, sec_info, old_pfx, outbox).map(State::Elder)
    }

    fn dispatch_routing_message(
        &mut self,
        msg: RoutingMessage,
        outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        self.handle_routing_message(msg, outbox)
    }

    // Sends a `ParsecPoke` message to trigger a gossip request from current section members to us.
    //
    // TODO: Should restrict targets to few(counter churn-threshold)/single.
    // Currently this can result in incoming spam of gossip history from everyone.
    // Can also just be a single target once node-ageing makes Offline votes Opaque which should
    // remove invalid test failures for unaccumulated parsec::Remove blocks.
    fn send_parsec_poke(&mut self) {
        let version = *self.gen_pfx_info.first_info.version();
        let recipients = self
            .gen_pfx_info
            .latest_info
            .members()
            .iter()
            .cloned()
            .collect_vec();

        for recipient in recipients {
            self.send_direct_message(&recipient, DirectMessage::ParsecPoke(version));
        }
    }
}

#[cfg(feature = "mock_base")]
impl Adult {
    pub fn chain(&self) -> &Chain {
        &self.chain
    }

    pub fn get_timed_out_tokens(&mut self) -> Vec<u64> {
        self.timer.get_timed_out_tokens()
    }

    pub fn has_unpolled_observations(&self) -> bool {
        self.parsec_map.has_unpolled_observations()
    }
}

impl Base for Adult {
    fn network_service(&self) -> &NetworkService {
        &self.network_service
    }

    fn network_service_mut(&mut self) -> &mut NetworkService {
        &mut self.network_service
    }

    fn full_id(&self) -> &FullId {
        &self.full_id
    }

    fn in_authority(&self, auth: &Authority<XorName>) -> bool {
        if let Authority::Client { ref client_id, .. } = *auth {
            client_id == self.full_id.public_id()
        } else {
            false
        }
    }

    fn min_section_size(&self) -> usize {
        self.chain.min_sec_size()
    }

    fn peer_map(&self) -> &PeerMap {
        &self.peer_map
    }

    fn peer_map_mut(&mut self) -> &mut PeerMap {
        &mut self.peer_map
    }

    fn handle_timeout(&mut self, token: u64, _: &mut dyn EventBox) -> Transition {
        if self.poke_timer_token == token {
            self.send_parsec_poke();
            self.poke_timer_token = self.timer.schedule(POKE_TIMEOUT);
        }

        Transition::Stay
    }

    fn handle_peer_lost(&mut self, pub_id: PublicId, outbox: &mut dyn EventBox) -> Transition {
        RelocatedNotEstablished::handle_peer_lost(self, pub_id, outbox)
    }

    fn handle_direct_message(
        &mut self,
        msg: DirectMessage,
        pub_id: PublicId,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        self.check_direct_message_sender(&msg, &pub_id)?;

        use crate::messages::DirectMessage::*;
        match msg {
            ParsecRequest(version, par_request) => {
                self.handle_parsec_request(version, par_request, pub_id, outbox)
            }
            ParsecResponse(version, par_response) => {
                self.handle_parsec_response(version, par_response, pub_id, outbox)
            }
            BootstrapRequest => {
                self.handle_bootstrap_request(pub_id);
                Ok(Transition::Stay)
            }
            _ => {
                debug!("{} Unhandled direct message: {:?}", self, msg);
                Ok(Transition::Stay)
            }
        }
    }

    fn handle_hop_message(
        &mut self,
        msg: HopMessage,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        if let Some(routing_msg) = self.filter_hop_message(msg)? {
            self.dispatch_routing_message(routing_msg, outbox)?;
        }
        Ok(Transition::Stay)
    }
}

impl Bootstrapped for Adult {
    fn routing_msg_filter(&mut self) -> &mut RoutingMessageFilter {
        &mut self.routing_msg_filter
    }

    fn timer(&mut self) -> &mut Timer {
        &mut self.timer
    }

    fn send_routing_message_impl(
        &mut self,
        routing_msg: RoutingMessage,
        expires_at: Option<Instant>,
    ) -> Result<(), RoutingError> {
        self.send_routing_message_via_proxy(routing_msg, expires_at)
    }
}

impl Relocated for Adult {
    fn peer_mgr(&self) -> &PeerManager {
        &self.peer_mgr
    }

    fn peer_mgr_mut(&mut self) -> &mut PeerManager {
        &mut self.peer_mgr
    }

    fn process_connection(&mut self, pub_id: PublicId, outbox: &mut dyn EventBox) {
        self.add_node(&pub_id, outbox);
    }

    fn is_peer_valid(&self, _pub_id: &PublicId) -> bool {
        true
    }

    fn add_node_success(&mut self, _: &PublicId) {}

    fn add_node_failure(&mut self, pub_id: &PublicId) {
        self.disconnect_peer(pub_id)
    }

    fn send_event(&mut self, event: Event, _: &mut dyn EventBox) {
        self.event_backlog.push(event)
    }
}

impl BootstrappedNotEstablished for Adult {
    fn get_proxy_public_id(&self, proxy_name: &XorName) -> Result<&PublicId, RoutingError> {
        proxied::find_proxy_public_id(self, &self.peer_mgr, proxy_name)
    }
}

impl RelocatedNotEstablished for Adult {
    fn our_prefix(&self) -> &Prefix<XorName> {
        self.chain.our_prefix()
    }

    fn push_message_to_backlog(&mut self, msg: RoutingMessage) {
        self.msg_backlog.push(msg)
    }
}

impl Approved for Adult {
    fn parsec_map_mut(&mut self) -> &mut ParsecMap {
        &mut self.parsec_map
    }

    fn chain_mut(&mut self) -> &mut Chain {
        &mut self.chain
    }

    fn set_pfx_successfully_polled(&mut self, _: bool) {
        // Doesn't do anything
    }

    fn is_pfx_successfully_polled(&self) -> bool {
        false
    }

    fn handle_add_elder_event(
        &mut self,
        new_pub_id: PublicId,
        _: Authority<XorName>,
        _: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        let _ = self.chain.add_member(new_pub_id)?;
        Ok(())
    }

    fn handle_remove_elder_event(
        &mut self,
        pub_id: PublicId,
        _: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        let _ = self.chain.remove_member(pub_id)?;
        Ok(())
    }

    fn handle_online_event(
        &mut self,
        _: OnlinePayload,
        _: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        Ok(())
    }

    fn handle_offline_event(&mut self, _: PublicId) -> Result<(), RoutingError> {
        Ok(())
    }

    fn handle_expect_candidate_event(
        &mut self,
        _: ExpectCandidatePayload,
    ) -> Result<(), RoutingError> {
        Ok(())
    }

    fn handle_purge_candidate_event(&mut self, _: PublicId) -> Result<(), RoutingError> {
        Ok(())
    }

    fn handle_section_info_event(
        &mut self,
        sec_info: SectionInfo,
        old_pfx: Prefix<XorName>,
        _: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        if self.chain.is_member() {
            Ok(Transition::IntoElder { sec_info, old_pfx })
        } else {
            debug!("{} - Unhandled SectionInfo event", self);
            Ok(Transition::Stay)
        }
    }

    fn handle_their_key_info_event(
        &mut self,
        _key_info: SectionKeyInfo,
    ) -> Result<(), RoutingError> {
        Ok(())
    }

    fn handle_send_ack_message_event(
        &mut self,
        _ack_payload: SendAckMessagePayload,
    ) -> Result<(), RoutingError> {
        Ok(())
    }

    fn handle_our_merge_event(&mut self) -> Result<(), RoutingError> {
        debug!("{} - Unhandled OurMerge event", self);
        Ok(())
    }

    fn handle_neighbour_merge_event(&mut self) -> Result<(), RoutingError> {
        debug!("{} - Unhandled NeighbourMerge event", self);
        Ok(())
    }

    fn handle_prune(&mut self) -> Result<(), RoutingError> {
        debug!("{} - Unhandled ParsecPrune event", self);
        Ok(())
    }
}

impl Display for Adult {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "Adult({}({:b}))",
            self.name(),
            self.chain.our_prefix()
        )
    }
}
