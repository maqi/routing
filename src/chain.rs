// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use block::{Block, BlockState, PeersAndAge};
use error::RoutingError;
use fs2::FileExt;
use maidsafe_utilities::serialisation;
use network_event::{AdultsAndInfants, DataIdentifier, Elders};
use peer_id::PeerId;
use serde::Serialize;
use std::fmt::Debug;
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use vote::Vote;

const GROUP_SIZE: usize = 8;
const PRUNE_COUNT: usize = 4;

fn add_vote_into_chain<T: Serialize + Clone + PartialEq>(
    group_size: usize,
    vote: Vote<T>,
    peer_id: &PeerId,
    chain: &mut Vec<Block<T>>,
) -> (bool, Option<(T, PeersAndAge)>) {
    let mut find_blk_index = None;
    let mut prev_blk_state = BlockState::NotYetValid;
    for (blk_index, blk) in chain.iter_mut().enumerate() {
        if blk.payload() == vote.payload() {
            prev_blk_state = blk.block_state(group_size);
            if blk.proofs().iter().any(|x| {
                x.peer_id().pub_key() == peer_id.pub_key()
            })
            {
                info!("duplicate proof");
                return (false, None);
            }

            blk.add_proof(vote.proof(peer_id).unwrap()).unwrap();
            find_blk_index = Some(blk_index);
            break;
        }
    }

    if let Some(index) = find_blk_index {
        let p_age = PeersAndAge::new(chain[index].num_proofs(), chain[index].total_age());
        let result = Some((chain[index].payload().clone(), p_age));
        let become_valid = chain[index].block_state(group_size) == BlockState::Valid &&
            prev_blk_state == BlockState::NotYetValid;

        (become_valid, result)
    } else {
        if let Ok(blk) = Block::new(&vote, &peer_id) {
            chain.push(blk.clone());
            return (
                false,
                Some((
                    blk.payload().clone(),
                    PeersAndAge::new(1, peer_id.age() as usize),
                )),
            );
        }
        info!("Could not find any block for this proof");
        return (false, None);
    }
}

fn march_chain<T: Debug + Serialize + Clone + PartialEq>(
    group_size: usize,
    chain: &mut Vec<Block<T>>,
) {
    let mut marching_index = chain.len();
    let mut valid_block_count = 0;
    let mut pruned_invalid_blocks = Vec::new();
    // We don't have to iterate through the whole chain, only need to scan to the point that
    // having 'PRUNE_COUNT' valid blocks counted from end.
    while marching_index > 0 && valid_block_count <= PRUNE_COUNT {
        marching_index -= 1;
        if chain[marching_index].block_state(group_size) == BlockState::NotYetValid {
            if chain[marching_index].increase_experienced_blocks() == PRUNE_COUNT {
                pruned_invalid_blocks.push(marching_index);
            }
        } else {
            valid_block_count += 1;
        }
    }
    for idx in pruned_invalid_blocks {
        let _ = chain.remove(idx);
    }
}

// Vote -> Quorum Block -> FullBlock (or nearly full Block + Accusation)

#[allow(unused)]
#[derive(Debug, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord)]
pub struct DataChain {
    blocks: Vec<Block<Elders>>,
    group_size: usize,
    path: Option<PathBuf>,
    valid_peers: Vec<Block<AdultsAndInfants>>, // save to aid network catastrophic failure and restart.
    data: Vec<Block<DataIdentifier>>,
}

impl DataChain {
    /// Create a new chain backed up on disk
    /// Provide the directory to create the files in
    pub fn create_in_path(path: PathBuf, group_size: usize) -> io::Result<DataChain> {
        let path = path.join("data_chain");
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;
        // hold a lock on the file for the whole session
        file.lock_exclusive()?;
        Ok(DataChain {
            blocks: Vec::<Block<Elders>>::default(),
            group_size: group_size,
            path: Some(path),
            valid_peers: Vec::<Block<AdultsAndInfants>>::default(),
            data: Vec::<Block<DataIdentifier>>::default(),
        })
    }

    /// Open from existing directory
    pub fn from_path(path: PathBuf) -> Result<DataChain, RoutingError> {
        let path = path.join("data_chain");
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open(&path)?;
        // hold a lock on the file for the whole session
        file.lock_exclusive()?;
        let mut buf = Vec::<u8>::new();
        let _ = file.read_to_end(&mut buf)?;
        Ok(serialisation::deserialise::<DataChain>(&buf[..])?)
    }

    /// Create chain in memory from some blocks
    pub fn from_blocks(blocks: Vec<Block<Elders>>, group_size: usize) -> DataChain {
        DataChain {
            blocks: blocks,
            group_size: group_size,
            path: None,
            valid_peers: Vec::<Block<AdultsAndInfants>>::default(),
            data: Vec::<Block<DataIdentifier>>::default(),
        }
    }

    /// Write current data chain to supplied path
    pub fn write(&self) -> Result<(), RoutingError> {
        if let Some(path) = self.path.to_owned() {
            let mut file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(false)
                .open(&path.as_path())?;
            return Ok(file.write_all(&serialisation::serialise(&self)?)?);
        }
        Err(RoutingError::CannotWriteFile)
    }

    /// Write current data chain to supplied path
    pub fn write_to_new_path(&mut self, path: PathBuf) -> Result<(), RoutingError> {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open(path.as_path())?;
        file.write_all(&serialisation::serialise(&self)?)?;
        self.path = Some(path);
        Ok(file.lock_exclusive()?)
    }

    /// Unlock the lock file
    pub fn unlock(&self) {
        if let Some(ref path) = self.path.to_owned() {
            if let Ok(file) = fs::File::open(path.as_path()) {
                let _ = file.unlock();
            }
        }
    }

    // pub fn add_vote<T>(&mut self, vote: Vote, peer_id: &PeerId) -> Option<(T, PeersAndAge)> {
    //     if !vote.validate_signature(peer_id.pub_key()) {
    //         return None;
    //     }

    //     match vote.payload() {
    //         Elders => self.add_vote_into_chain(vote, peer_id, &mut self.blocks),
    //         _ => self.add_vote_into_chain(vote, peer_id, &mut self.valid_peers),
    //     }
    // }

    /// Add vote relates to elders into chain.
    pub fn add_block_vote(
        &mut self,
        vote: Vote<Elders>,
        peer_id: &PeerId,
    ) -> Option<(Elders, PeersAndAge)> {
        if !vote.validate_signature(peer_id.pub_key()) {
            return None;
        }

        let (become_valid, result) =
            add_vote_into_chain(self.group_size, vote, peer_id, &mut self.blocks);
        if become_valid {
            self.prune_invalid_blocks();
        }
        result
    }

    /// Add vote relates to adult and infant into chain.
    pub fn add_valid_peers_vote(
        &mut self,
        vote: Vote<AdultsAndInfants>,
        peer_id: &PeerId,
    ) -> Option<(AdultsAndInfants, PeersAndAge)> {
        if !vote.validate_signature(peer_id.pub_key()) {
            return None;
        }

        let (become_valid, result) =
            add_vote_into_chain(self.group_size, vote, peer_id, &mut self.valid_peers);
        if become_valid {
            self.prune_invalid_blocks();
        }
        result
    }

    pub fn prune_invalid_blocks(&mut self) {
        // Increase the `experienced_blocks` counter for invalid blocks in both chains.
        march_chain(self.group_size, &mut self.blocks);
        march_chain(self.group_size, &mut self.valid_peers);
    }

    /// Assumes we trust the first `Block`
    fn validate_quorums(&self) -> bool {
        if let Some(mut prev) = self.blocks.first() {
            for blk in self.blocks.iter().skip(1) {
                if blk.get_peer_ids() // TODO, don't count like this use a loop and check quorum age as well
                    .intersection(&prev.get_peer_ids())
                    .count() <= self.group_size / 2
                {
                    return false;
                } else {
                    prev = blk; // TODO check `NetworkEvent` as we may need to add to prev or remove a possible voter
                                // we can probably use a CurrentPeers / Elders list here to be more specific.
                                // Also which `NetworkEvent`s can follow a sequence, i.e. a lost must be followed
                                // with a promote if its an elder or a merge if peers drops to group size.
                                // Most events will follow a sequence that is allowed. if blocks are out of sequence when
                                // net is running a peer should sequence them properly. Here we would fail the chain.
                }
            }
            true
        } else {
            false
        }
    }

    //
    //     /// getter
    //     pub fn chain(&self) -> &Vec<Block> {
    //         &self.chain
    //     }
    //
    //     // get size of chain for storing on disk
    //     #[allow(unused)]
    //     fn size_of(&self) -> u64 {
    //         rustc_serialize::encoded_size(self)
    //     }
    //
    //     /// find a block (user required to test for validity)
    //     pub fn find(&self, block_identifier: &BlockIdentifier) -> Option<&Block> {
    //         self.chain.iter().find(
    //             |x| x.identifier() == block_identifier,
    //         )
    //     }
    //
    //     /// find block by name from top (only first occurrence)
    //     pub fn find_name(&self, name: &[u8; 32]) -> Option<&Block> {
    //         self.chain.iter().rev().find(|x| {
    //             x.valid && Some(name) == x.identifier().najme()
    //         })
    //     }
    //
    //     /// Remove a block, will ignore Links
    //     pub fn remove(&mut self, data_id: &BlockIdentifier) {
    //         self.chain.retain(|x| {
    //             x.identifier() != data_id || x.identifier().is_link()
    //         });
    //     }
    //
    //     /// Retains only the blocks specified by the predicate.
    //     pub fn retain<F>(&mut self, pred: F)
    //     where
    //         F: FnMut(&Block) -> bool,
    //     {
    //         self.chain.retain(pred);
    //     }
    //
    //     /// Clear chain
    //     pub fn clear(&mut self) {
    //         self.chain.clear()
    //     }
    //
    //     /// Check if chain contains a particular identifier
    //     pub fn contains(&self, block_identifier: &BlockIdentifier) -> bool {
    //         self.chain.iter().any(
    //             |x| x.identifier() == block_identifier,
    //         )
    //     }
    //
    //     /// Return position of block identifier
    //     pub fn position(&self, block_identifier: &BlockIdentifier) -> Option<usize> {
    //         self.chain.iter().position(
    //             |x| x.identifier() == block_identifier,
    //         )
    //     }
    //
    //     /// Inserts an element at position index within the chain, shifting all elements
    //     /// after it to the right.
    //     /// Will not validate this block!
    //     /// # Panics
    //     ///
    //     /// Panics if index is greater than the chains length.
    //     pub fn insert(&mut self, index: usize, block: Block) {
    //         self.chain.insert(index, block)
    //     }
    //
    //     /// Validates an individual block. Will get latest link and confirm all signatures
    //     /// were from last known valid group.
    //     pub fn validate_block(&mut self, block: &mut Block) -> bool {
    //         for link in &self.valid_links_at_block_id(block.identifier()) {
    //             if Self::validate_block_with_proof(block, link, self.group_size) {
    //                 block.valid = true;
    //                 return true;
    //             }
    //         }
    //         false
    //     }
    //
    //     /// Removes all invalid blocks, does not confirm chain is valid to this group.
    //     pub fn prune(&mut self) {
    //         self.mark_blocks_valid();
    //         self.chain.retain(|x| x.valid);
    //     }
    //
    //     /// Total length of chain
    //     pub fn len(&self) -> usize {
    //         self.chain.len()
    //     }
    //
    //     /// Number of valid blocks
    //     pub fn valid_len(&self) -> usize {
    //         self.blocks_len() + self.links_len()
    //     }
    //
    //     /// number of valid data blocks
    //     pub fn blocks_len(&self) -> usize {
    //         self.chain
    //             .iter()
    //             .filter(|x| x.identifier().is_block() && x.valid)
    //             .count()
    //     }
    //
    //     /// number of valid links
    //     pub fn links_len(&self) -> usize {
    //         self.chain
    //             .iter()
    //             .filter(|x| x.identifier().is_link() && x.valid)
    //             .count()
    //     }
    //
    //     /// Contains no blocks that are not valid
    //     pub fn is_empty(&self) -> bool {
    //         self.chain.is_empty()
    //     }
    //
    //     /// Should contain majority of the current common_close_group
    //     fn last_valid_link(&mut self) -> Option<&mut Block> {
    //         self.chain.iter_mut().rev().find(|x| {
    //             x.identifier().is_link() && x.valid
    //         })
    //     }
    //
    //     /// Returns all links in chain
    //     /// Does not perform validation on links
    //     pub fn all_links(&self) -> Vec<Block> {
    //         self.chain
    //             .iter()
    //             .cloned()
    //             .filter(|x| x.identifier().is_link())
    //             .collect_vec()
    //     }
    //
    //     /// Validates and returns all links in chain
    //     pub fn valid_data(&mut self) -> Vec<Block> {
    //         self.mark_blocks_valid();
    //         self.chain
    //             .iter()
    //             .cloned()
    //             .filter(|x| !x.identifier().is_link() && x.valid)
    //             .collect_vec()
    //     }
    //
    //     /// Validates and returns all links in chain
    //     pub fn valid_links(&mut self) -> Vec<Block> {
    //         self.mark_blocks_valid();
    //         self.chain
    //             .iter()
    //             .cloned()
    //             .filter(|x| x.identifier().is_link() && x.valid)
    //             .collect_vec()
    //     }
    //
    //     /// Validates and returns all valid links in chain 4 before and after target
    //     pub fn valid_links_at_block_id(&mut self, block_id: &BlockIdentifier) -> Vec<Block> {
    //         // FIXME the value of 4 is arbitrary
    //         // instead the length of last link len() should perhaps be used
    //         let top_links = self.chain
    //             .iter()
    //             .cloned()
    //             .skip_while(|x| x.identifier() != block_id)
    //             .filter(|x| x.identifier().is_link() && x.valid)
    //             .take(4)
    //             .collect_vec();
    //
    //         let mut bottom_links = self.chain
    //             .iter()
    //             .rev()
    //             .cloned()
    //             .skip_while(|x| x.identifier() != block_id)
    //             .filter(|x| x.identifier().is_link() && x.valid)
    //             .take(4)
    //             .collect_vec();
    //         bottom_links.extend(top_links);
    //
    //         bottom_links
    //
    //     }
    //
    //
    //     /// Mark all links that are valid as such.
    //     pub fn mark_blocks_valid(&mut self) {
    //         if let Some(mut first_link) =
    //             self.chain.iter().cloned().find(
    //                 |x| x.identifier().is_link(),
    //             )
    //         {
    //             for block in &mut self.chain {
    //                 block.remove_invalid_signatures();
    //                 if Self::validate_block_with_proof(block, &first_link, self.group_size) {
    //                     block.valid = true;
    //                     if block.identifier().is_link() {
    //                         first_link = block.clone();
    //                     }
    //                 } else {
    //                     block.valid = false;
    //                 }
    //             }
    //         } else {
    //             self.chain.clear();
    //         }
    //     }
    //
    //     /// Merge any blocks from a given chain
    //     /// FIXME - this needs a complete rewrite
    //     pub fn merge_chain(&mut self, chain: &mut DataChain) {
    //         chain.mark_blocks_valid();
    //         chain.prune();
    //         let mut start_pos = 0;
    //         for new in chain.chain().iter().filter(|x| x.identifier().is_block()) {
    //             let mut insert = false;
    //             for (pos, val) in self.chain.iter().enumerate().skip(start_pos) {
    //                 if DataChain::validate_block_with_proof(new, val, self.group_size) {
    //                     start_pos = pos;
    //                     insert = true;
    //                     break;
    //                 }
    //             }
    //
    //             if insert {
    //                 self.chain.insert(start_pos, new.clone());
    //                 start_pos += 1;
    //             }
    //         }
    //     }
    //
    //     fn validate_block_with_proof(block: &Block, proof: &Block, group_size: usize) -> bool {
    //         let p_len = proof
    //             .proofs()
    //             .iter()
    //             .filter(|&y| block.proofs().iter().any(|p| p.key() == y.key()))
    //             .count();
    //         (p_len * 2 >= proof.proofs().len()) || (p_len >= group_size)
    //     }
    // }
    //
    // impl Debug for DataChain {
    //     fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
    //         let print_block = |block: &Block| -> String {
    //             let mut output = format!(
    //                 "    Block {{\n        identifier: {:?}\n        valid: {}\n",
    //                 block.identifier(),
    //                 block.valid
    //             );
    //             for proof in block.proofs() {
    //                 output.push_str(&format!("        {:?}\n", proof))
    //             }
    //             output.push_str("    }");
    //             output
    //         };
    //         write!(
    //             formatter,
    //             "DataChain {{\n    group_size: {}\n    path: ",
    //             self.group_size
    //         )?;
    //         match self.path {
    //             Some(ref path) => writeln!(formatter, "{}", path.display())?,
    //             None => writeln!(formatter, "None")?,
    //         }
    //         if self.chain.is_empty() {
    //             write!(formatter, "    chain empty }}")
    //         } else {
    //             for block in &self.chain {
    //                 writeln!(formatter, "{}", print_block(block))?
    //             }
    //             write!(formatter, "}}")
    //         }
    //     }
    // }

    // impl Accumulator {
    // A new `Block` requires a valid vote and the `PublicKey` of the node
    //  who sent us this. For this reason
    // The `Vote` require a Direct Message from a `Peer` to us.
    // #[allow(unused)]
    // pub fn add_vote(
    //     &mut self,
    //     vote: &Vote,
    //     pub_key: &PublicKey,
    //     age: u8,
    // ) -> Result<PeersAndAge, RoutingRoutingError> {
    //     if !vote.validate_signature(pub_key) {
    //         return Err(RoutingRoutingError::FailedSignature);
    //     }
    //     let digest = vote.payload();
    //     let proof = Proof::new(&pub_key, age, vote)?;
    //
    //     if let Some(blk) = self.blocks.get_mut(&digest.clone()) {
    //         blk.add_proof(proof);
    //         return Ok(PeersAndAge::new(blk.total_proofs(), blk.total_proofs_age()));
    //     };
    //
    //     let mut proofset = BTreeSet::<Proof>::new();
    //     if !proofset.insert(proof) {
    //         return Err(RoutingRoutingError::FailedSignature);
    //     }
    //     let mut block = Block::new(&vote, &pub_key, age)?;
    //     let _fixme = self.blocks.insert(*digest, block.clone());
    //     Ok(PeersAndAge::new(
    //         block.clone().total_proofs(),
    //         block.total_proofs_age(),
    //     ))
    // }
    //
}

impl Default for DataChain {
    fn default() -> DataChain {
        DataChain {
            blocks: Vec::<Block<Elders>>::default(),
            group_size: GROUP_SIZE,
            path: None,
            valid_peers: Vec::<Block<AdultsAndInfants>>::default(),
            data: Vec::<Block<DataIdentifier>>::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maidsafe_utilities::SeededRng;
    use rust_sodium;
    use rust_sodium::crypto::sign;

    const ELDER_DEFAULT_AGE: u8 = 5;
    const DEFAULT_AGE: u8 = 1;

    #[test]
    fn add_vote() {
        let mut rng = SeededRng::thread_rng();
        unwrap!(rust_sodium::init_with_rng(&mut rng));

        let payload = Elders::ElderAccept(PeerId::new(ELDER_DEFAULT_AGE, sign::gen_keypair().0));

        let mut chain = DataChain::default();
        for _ in 0..GROUP_SIZE {
            let keys = sign::gen_keypair();
            let vote = Vote::new(&keys.1, payload.clone()).unwrap();
            let peer_id = PeerId::new(ELDER_DEFAULT_AGE, keys.0);
            assert!(chain.add_block_vote(vote, &peer_id).is_some());
        }
        assert_eq!(chain.blocks[0].num_proofs(), GROUP_SIZE);
    }

    #[test]
    fn prune_invalid_block() {
        let mut rng = SeededRng::thread_rng();
        unwrap!(rust_sodium::init_with_rng(&mut rng));
        let mut chain = DataChain::default();
        {
            // Create one invalid block in elder chain.
            let payload =
                Elders::ElderAccept(PeerId::new(ELDER_DEFAULT_AGE, sign::gen_keypair().0));
            let keys = sign::gen_keypair();
            let vote = Vote::new(&keys.1, payload.clone()).unwrap();
            let peer_id = PeerId::new(ELDER_DEFAULT_AGE, keys.0);
            assert!(chain.add_block_vote(vote, &peer_id).is_some());
        }
        // Create `PRUNE_COUNT` valid blocks in `adult_and_infant` chain.
        for _ in 0..PRUNE_COUNT {
            let payload =
                AdultsAndInfants::PeerAccept(PeerId::new(DEFAULT_AGE, sign::gen_keypair().0));
            for _ in 0..GROUP_SIZE {
                let keys = sign::gen_keypair();
                let vote = Vote::new(&keys.1, payload.clone()).unwrap();
                let peer_id = PeerId::new(ELDER_DEFAULT_AGE, keys.0);
                assert!(chain.add_valid_peers_vote(vote, &peer_id).is_some());
            }
        }
        // The invalid block in the elder chain shall got pruned.
        assert!(chain.blocks.is_empty());
    }
}
