// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

mod accumulate;
mod cache;
mod churn;
mod drop;
mod merge;
mod requests;
mod utils;

use routing::{Event, Prefix, XOR_NAME_LEN, XorName};
use routing::mock_crust::{Config, Endpoint, Network};
use routing::mock_crust::crust::PeerId;
pub use self::utils::{Nodes, TestClient, TestNode, create_connected_clients,
                      create_connected_nodes, create_connected_nodes_until_split, gen_bytes,
                      gen_immutable_data, gen_range_except, poll_all, poll_and_resend,
                      sort_nodes_by_distance_to, verify_invariant_for_all_nodes};

// -----  Miscellaneous tests below  -----

fn test_nodes(percentage_size: usize) {
    let min_group_size = 8;
    let size = min_group_size * percentage_size / 100;
    let network = Network::new(min_group_size, None);
    let nodes = create_connected_nodes(&network, size);
    verify_invariant_for_all_nodes(&nodes);
}

#[test]
fn disconnect_on_rebootstrap() {
    let min_group_size = 8;
    let network = Network::new(min_group_size, None);
    let mut nodes = create_connected_nodes(&network, 2);
    // Try to bootstrap to another than the first node. With network size 2, this should fail.
    let config = Config::with_contacts(&[nodes[1].handle.endpoint()]);
    nodes.push(TestNode::builder(&network).config(config).endpoint(Endpoint(2)).create());
    let _ = poll_all(&mut nodes, &mut []);
    // When retrying to bootstrap, we should have disconnected from the bootstrap node.
    assert!(!unwrap!(nodes.last()).handle.is_connected(&nodes[1].handle));
    expect_next_event!(unwrap!(nodes.last()), Event::Terminate);
}

#[test]
fn less_than_group_size_nodes() {
    test_nodes(38)
}

#[test]
fn equal_group_size_nodes() {
    test_nodes(100);
}

#[test]
fn more_than_group_size_nodes() {
    test_nodes(600);
}

#[test]
fn failing_connections_ring() {
    let min_group_size = 8;
    let network = Network::new(min_group_size, None);
    let len = min_group_size * 2;
    for i in 0..(len - 1) {
        let ep0 = Endpoint(1 + i);
        let ep1 = Endpoint(1 + (i % len));

        network.block_connection(ep0, ep1);
        network.block_connection(ep1, ep0);
    }
    let nodes = create_connected_nodes(&network, len);
    verify_invariant_for_all_nodes(&nodes);
}

#[test]
fn failing_connections_unidirectional() {
    let min_group_size = 8;
    let network = Network::new(min_group_size, None);
    network.block_connection(Endpoint(1), Endpoint(6));
    network.block_connection(Endpoint(1), Endpoint(7));
    network.block_connection(Endpoint(6), Endpoint(7));

    let nodes = create_connected_nodes(&network, min_group_size);
    verify_invariant_for_all_nodes(&nodes);
}

#[test]
fn client_connects_to_nodes() {
    let min_group_size = 8;
    let network = Network::new(min_group_size, None);
    let mut nodes = create_connected_nodes(&network, min_group_size + 1);
    let _ = create_connected_clients(&network, &mut nodes, 1);
}

#[test]
fn node_joins_in_front() {
    let min_group_size = 8;
    let network = Network::new(min_group_size, None);
    let mut nodes = create_connected_nodes(&network, 2 * min_group_size);
    let config = Config::with_contacts(&[nodes[0].handle.endpoint()]);
    nodes.insert(0, TestNode::builder(&network).config(config).create());

    let _ = poll_all(&mut nodes, &mut []);

    verify_invariant_for_all_nodes(&nodes);
}

#[test]
fn multiple_joining_nodes() {
    // Create a network with two sections:
    let min_group_size = 8;
    let network = Network::new(min_group_size, None);
    let mut nodes = create_connected_nodes(&network, min_group_size);
    let config = Config::with_contacts(&[nodes[0].handle.endpoint()]);

    // Try adding three nodes at once, to the same section. This makes sure one section can handle
    // this (probably by rejecting some of the nodes).
    nodes.push(TestNode::builder(&network).config(config.clone()).create());
    nodes.push(TestNode::builder(&network).config(config.clone()).create());
    nodes.push(TestNode::builder(&network).config(config.clone()).create());

    let _ = poll_all(&mut nodes, &mut []);
    nodes.retain(|node| !node.routing_table().is_empty());
    let _ = poll_all(&mut nodes, &mut []);

    verify_invariant_for_all_nodes(&nodes);
}

#[test]
fn simultaneous_joining_nodes() {
    // Create a network with two sections:
    let min_group_size = 8;
    let network = Network::new(min_group_size, None);
    let mut nodes = create_connected_nodes_until_split(&network, vec![1, 1], false);
    let config = Config::with_contacts(&[nodes[0].handle.endpoint()]);

    // Add two nodes simultaneously, to two different sections:
    // We now have two sections, with prefixes 0 and 1. Make one joining node contact each section,
    // and tell each section to allocate a name in its own section when `GetNodeName` is received.
    // This is to test that the routing table gets updated correctly (previously one new node would
    // miss the new node added to the neighbouring section).
    let (name0, name1) = (XorName([0u8; XOR_NAME_LEN]), XorName([255u8; XOR_NAME_LEN]));
    let prefix0 = Prefix::new(1, name0);

    for node in &mut *nodes {
        if prefix0.matches(&node.name()) {
            node.inner.set_next_node_name(name0);
        } else {
            node.inner.set_next_node_name(name1);
        }
    }

    let node = TestNode::builder(&network).config(config.clone()).create();
    let prefix = Prefix::new(1, node.name());
    nodes.push(node);
    loop {
        let node = TestNode::builder(&network).config(config.clone()).create();
        if !prefix.matches(&node.name()) {
            nodes.push(node);
            break;
        }
    }

    let _ = poll_all(&mut nodes, &mut []);

    verify_invariant_for_all_nodes(&nodes);
}

#[test]
fn check_close_groups_for_group_size_nodes() {
    let min_group_size = 8;
    let nodes = create_connected_nodes(&Network::new(min_group_size, None), min_group_size);
    let close_groups_complete = nodes.iter()
        .all(|n| nodes.iter().all(|m| m.close_group().contains(&n.name())));
    assert!(close_groups_complete);
}

#[test]
fn whitelist() {
    let min_group_size = 8;
    let network = Network::new(min_group_size, None);
    let mut nodes = create_connected_nodes(&network, min_group_size);
    let config = Config::with_contacts(&[nodes[0].handle.endpoint()]);
    for node in &mut *nodes {
        node.handle.0.borrow_mut().whitelist_peer(PeerId(min_group_size));
    }
    // The next node has peer ID `min_group_size`: It should be able to join.
    nodes.push(TestNode::builder(&network).config(config.clone()).create());
    let _ = poll_all(&mut nodes, &mut []);
    verify_invariant_for_all_nodes(&nodes);
    // The next node has peer ID `min_group_size + 1`: It is not whitelisted.
    nodes.push(TestNode::builder(&network).config(config.clone()).create());
    let _ = poll_all(&mut nodes, &mut []);
    assert!(!unwrap!(nodes.pop()).inner.is_node());
    // A client should be able to join anyway, regardless of the whitelist.
    let mut clients = vec![TestClient::new(&network, Some(config), None)];
    let _ = poll_all(&mut nodes, &mut clients);
    expect_next_event!(clients[0], Event::Connected);
}
