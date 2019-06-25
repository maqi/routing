// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    create_connected_clients, create_connected_nodes, poll_all, poll_and_resend, TestClient,
    TestNode, MIN_SECTION_SIZE,
};
use rand::Rng;
use routing::{
    mock::Network, Authority, Event, EventStream, FullId, MessageId, NetworkConfig, Request,
};

/// Connect a client to the network then send an invalid message.
/// Expect the client will be disconnected and banned;
#[test]
// TODO (quic-p2p): This test requires bootstrap blacklist which isn't implemented in quic-p2p.
#[ignore]
fn ban_malicious_client() {
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut nodes = create_connected_nodes(&network, MIN_SECTION_SIZE);
    let mut clients = create_connected_clients(&network, &mut nodes, 1);
    let mut rng = network.new_rng();

    // Send a request with priority 1 from the client; should cause it to get banned.
    let _ = clients[0].inner.send_request(
        Authority::NaeManager(rng.gen()),
        Request::Refresh(vec![], MessageId::new()),
        1,
    );
    let _ = poll_all(&mut nodes, &mut clients);
    expect_next_event!(unwrap!(clients.last_mut()), Event::Terminated);
    let banned_client_ips = nodes[0]
        .inner
        .node_state_unchecked()
        .get_banned_client_ips();
    assert_eq!(banned_client_ips.len(), 1);
    let endpoint = clients[0].endpoint();
    assert_eq!(unwrap!(banned_client_ips.into_iter().next()), endpoint.ip());

    let _ = clients.remove(0);
    let _ = poll_all(&mut nodes, &mut clients);

    // Connect a new client with the same ip address shall get rejected.
    let config = NetworkConfig::client().with_hard_coded_contact(nodes[0].endpoint());
    let client = TestClient::new(&network, Some(config), Some(endpoint));
    clients.push(client);
    let _ = poll_all(&mut nodes, &mut clients);
    expect_next_event!(unwrap!(clients.last_mut()), Event::Terminated);
}

/// Connects two clients to the network using the same ip address and via the same proxy.
/// Expect only one client got connected.
#[test]
// TODO (quic-p2p): This test requires bootstrap blacklist which isn't implemented in quic-p2p.
#[ignore]
fn only_one_client_per_ip() {
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut nodes = create_connected_nodes(&network, MIN_SECTION_SIZE);
    let mut clients = create_connected_clients(&network, &mut nodes, 1);

    // Connect a new client with the same ip address shall get rejected.
    let mut endpoint = clients[0].endpoint();
    endpoint.set_port(endpoint.port() + 1);

    let config = NetworkConfig::client().with_hard_coded_contact(nodes[0].endpoint());
    let client = TestClient::new(&network, Some(config), Some(endpoint));
    clients.push(client);
    let _ = poll_all(&mut nodes, &mut clients);
    expect_next_event!(unwrap!(clients.last_mut()), Event::Terminated);
}

/// Reconnect a client (disconnected as network not having enough nodes) with the same id.
#[test]
// TODO (quic-p2p): This test requires bootstrap blacklist which isn't implemented in quic-p2p.
#[ignore]
fn reconnect_disconnected_client() {
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut nodes = create_connected_nodes(&network, MIN_SECTION_SIZE - 1);

    let config = NetworkConfig::client().with_hard_coded_contact(nodes[1].endpoint());
    let full_id = FullId::new();

    // Client will get rejected as network not having enough nodes.
    let mut clients = vec![TestClient::new_with_full_id(
        &network,
        Some(config),
        None,
        full_id.clone(),
    )];
    poll_and_resend(&mut nodes, &mut clients);
    expect_next_event!(unwrap!(clients.last_mut()), Event::Terminated);

    let _ = clients.remove(0);
    let config = NetworkConfig::node().with_hard_coded_contact(nodes[0].endpoint());
    nodes.push(TestNode::builder(&network).network_config(config).create());
    poll_and_resend(&mut nodes, &mut clients);

    // Reconnecting the client (with same id) shall succeed.
    let config = NetworkConfig::client().with_hard_coded_contact(nodes[1].endpoint());
    clients.push(TestClient::new_with_full_id(
        &network,
        Some(config),
        None,
        full_id,
    ));
    poll_and_resend(&mut nodes, &mut clients);
    expect_next_event!(unwrap!(clients.last_mut()), Event::Connected);
}