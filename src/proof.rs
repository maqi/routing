// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0 This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use serde::Serialize;
use rust_sodium::crypto::sign::{self, PublicKey, Signature};
use super::vote::Vote;
use error::RoutingError;
use maidsafe_utilities::serialisation;

/// Proof as provided by a close group member
/// This nay be extracted from a `Vote` to be inserted into a `Block`
#[derive(Serialize, Deserialize, PartialOrd, Ord, PartialEq, Eq, Clone, Debug)]
pub struct Proof {
    pub_key: PublicKey,
    sig: Signature,
}

impl Proof {
    /// Create Proof from Vote and public key
    #[allow(unused)]
    pub fn new<T: Serialize + Clone>(key: &PublicKey, vote: &Vote<T>) -> Result<Proof, RoutingError> {
        vote.validate(key)?;
        Ok(Proof {
            pub_key: key.clone(),
            sig: vote.signature().clone(),
        })
    }

    /// getter
    #[allow(unused)]    
    pub fn key(&self) -> &PublicKey {
        &self.pub_key
    }

    /// getter
    #[allow(unused)]    
    pub fn sig(&self) -> &Signature {
        &self.sig
    }

    /// Validates `data` against this `Proof`'s `key` and `sig`.
    #[allow(unused)]    
    pub fn validate<T: Serialize>(&self, payload: &T) -> bool {
         match serialisation::serialise(&payload) {
            Ok(data) => sign::verify_detached(&self.sig, &data[..], &self.pub_key),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    // use super::*;
    // use chain::block_identifier::BlockIdentifier;
    // use rust_sodium::crypto::sign;
    // use sha3::hash;

    // #[test]
    // fn vote_comparisons() {
    //     ::rust_sodium::init();
    //     let keys = sign::gen_keypair();
    //     let test_data1 = BlockIdentifier::Link(hash(b"1"));
    //     let test_data2 = BlockIdentifier::Link(hash(b"1"));
    //     let test_data3 = BlockIdentifier::ImmutableData(hash(b"1"));
    //     let test_node_data_block1 = Vote::new(&keys.0, &keys.1, test_data1).expect("fail1");
    //     let test_node_data_block2 = Vote::new(&keys.0, &keys.1, test_data2).expect("fail2");
    //     let test_node_data_block3 = Vote::new(&keys.0, &keys.1, test_data3).expect("fail3");
    //     assert!(test_node_data_block1.validate());
    //     assert!(test_node_data_block2.validate());
    //     assert!(test_node_data_block3.validate());
    //     assert_eq!(test_node_data_block1.clone(), test_node_data_block2.clone());
    //     assert!(test_node_data_block1 != test_node_data_block3.clone());
    //     assert!(test_node_data_block2 != test_node_data_block3);
    // }
}