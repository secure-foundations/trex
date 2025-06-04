//! A convenient container abstraction to help manage recursive
//! objects that support some sort of "join" operation on them.

use crate::containers::unordered::{UnorderedMap, UnorderedSet};
use crate::log::*;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};

static CONTAINER_COUNT: AtomicUsize = AtomicUsize::new(0);

/// An opaque index into the [`Container`]
///
/// NOTE: Does *not* implement PartialEq, Eq, ...; instead
/// [`Container::index_eq`] should be used to compare indices.
#[derive(Clone, Copy, Debug)]
pub struct Index {
    container_id: usize,
    idx: usize,
}
impl Index {
    /// Convert to a string. This should only be used for debugging or `.dot` generation purposes.
    #[allow(clippy::inherent_to_string)]
    pub fn to_string(self) -> String {
        self.idx.to_string()
    }
}

impl Index {
    /// Equality comparison that returns true if the two indices are
    /// guaranteed to point to the same value. If it returns false,
    /// then nothing can be said about the indices (i.e., they may or
    /// may not point to the same value). If you want to know whether
    /// the values within the container are actually the same, see
    /// [`Container::index_eq`] instead.
    pub fn surely_equal(&self, other: &Self) -> bool {
        let Self { container_id, idx } = *other;
        self.container_id == container_id && self.idx == idx
    }

    /// Provides a comparison function between indexes which is consistent with `surely_equal` and
    /// is a partial ordering on all indexes, but otherwise provides no special guarantees that
    /// should be relied upon.
    pub fn some_consistent_ordering(&self, other: &Self) -> std::cmp::Ordering {
        let Self { container_id, idx } = *other;
        (self.container_id, self.idx).cmp(&(container_id, idx))
    }
}

/// Structure that allows scheduling joins to happen after the ongoing
/// [`Joinable::join`] that discovered them is completed.
#[derive(Debug)]
pub struct DelayedJoiner {
    index_pairs: Vec<(Index, Index)>,
    clone_and_join_indexes: VecDeque<(Index, (Index, Index))>,
    reserved_freshness: Rc<RefCell<usize>>,
    container_id: usize,
}

impl DelayedJoiner {
    /// A new, empty delayed joiner; should not need to be created manually except in special
    /// circumstances.
    ///
    /// The container passed in allows for control over clone-and-join style operations.
    pub fn new<T: Joinable>(container: &Container<T>) -> Self {
        Self::internal_new(&container.reserved_freshness, container.container_id)
    }

    /// This should *not* be called external to this module.
    fn internal_new(reserved_freshness: &Rc<RefCell<usize>>, container_id: usize) -> Self {
        Self {
            index_pairs: vec![],
            clone_and_join_indexes: Default::default(),
            reserved_freshness: reserved_freshness.clone(),
            container_id,
        }
    }

    /// Clone into a new DelayedJoiner. Should *not* be called external to this module.
    fn clone_using<T: Joinable>(&self, container: &Container<T>) -> Self {
        assert!(
            self.index_pairs.is_empty() && self.clone_and_join_indexes.is_empty(),
            "Should only clone DelayedJoiner when not in the middle of joining",
        );
        Self::new(container)
    }

    /// Schedule a delayed join.
    pub fn schedule(&mut self, into_index: Index, from_index: Index) {
        assert_eq!(into_index.container_id, self.container_id);
        assert_eq!(from_index.container_id, self.container_id);
        if into_index.surely_equal(&from_index) {
            trace!(
                "Trying to schedule a delayed join of two surely-equal indices. Skipping.";
                "indices" => ?into_index
            );
        } else {
            self.index_pairs.push((into_index, from_index));
        }
    }

    /// Get a new reserved index
    fn reserve_index(&mut self) -> Index {
        let mut reserved_freshness = self.reserved_freshness.borrow_mut();
        let idx = Index {
            container_id: self.container_id,
            idx: *reserved_freshness,
        };
        *reserved_freshness += 1;
        idx
    }

    /// Schedule a delayed clone-and-join. Returns a new index for the future newly created member
    /// that is the join of `index1` and `index2`
    #[must_use]
    pub fn schedule_clone_and_join(&mut self, index1: Index, index2: Index) -> Index {
        let new_idx = self.reserve_index();
        self.clone_and_join_indexes
            .push_back((new_idx, (index1, index2)));
        new_idx
    }

    /// Return `true` if no delayed joins (or clone-and-joins) were scheduled.
    pub fn is_empty(&self) -> bool {
        self.index_pairs.is_empty() && self.clone_and_join_indexes.is_empty()
    }

    /// Clear all pairs of pre-joined indexes by looking through the container. These are indices
    /// that point to the same object and thus have a trivial join on them, and thus do not actually
    /// require any joining.
    pub fn clear_any_pre_joined_indexes<T: Joinable>(&mut self, container: &Container<T>) {
        assert_eq!(self.container_id, container.container_id);
        self.index_pairs = self
            .index_pairs
            .iter()
            .cloned()
            .filter(|&(idx1, idx2)| !container.index_eq(idx1, idx2))
            .collect();
    }
}

/// A type that supports fusing itself with another value.
pub trait Joinable: Sized {
    /// Join information from `other` into `self`. If the join is rejected, this function is
    /// expected to return back `other`.
    fn join(&mut self, other: Self, delayed_joiner: &mut DelayedJoiner) -> Result<(), Self>;

    /// Collection of values that this type refers to within the same container
    fn refers_to<'a>(&'a self) -> Box<dyn std::iter::Iterator<Item = Index> + 'a>;

    /// Collection of values that this type refers to within the same container
    fn refers_to_mut<'a>(&'a mut self) -> Box<dyn std::iter::Iterator<Item = &'a mut Index> + 'a>;
}

/// A container that holds recursive [`Joinable`] objects. Recursion
/// is managed through opaque [`Index`]es.
pub struct Container<T: Joinable> {
    reserved_freshness: Rc<RefCell<usize>>,
    container_id: usize,
    index_map: RefCell<Vec<usize>>,
    objects: Vec<Option<T>>,
    delayed_joiner: DelayedJoiner,
}

impl<T: Joinable> Container<T> {
    /// Create a new, empty container
    pub fn new() -> Self {
        let reserved_freshness = Rc::new(RefCell::new(0));
        let container_id = CONTAINER_COUNT.fetch_add(1, Ordering::SeqCst);
        let delayed_joiner = DelayedJoiner::internal_new(&reserved_freshness, container_id);
        Self {
            reserved_freshness,
            container_id,
            index_map: RefCell::new(vec![]),
            objects: vec![],
            delayed_joiner,
        }
    }

    /// Insert `value` into the container, returning an index for
    /// referring to it.
    pub fn insert(&mut self, value: T) -> Index {
        let mut index_map = self.index_map.borrow_mut();
        assert_eq!(
            self.objects.len(),
            index_map.len(),
            "If this assertion ever fails, \
             then we have broken the self-loop == 'we have found the object' invariant."
        );
        let mut reserved_freshness = self.reserved_freshness.borrow_mut();
        assert!(index_map.len() <= *reserved_freshness);
        for l in index_map.len()..*reserved_freshness {
            index_map.push(l);
            self.objects.push(None);
        }
        assert_eq!(
            self.objects.len(),
            index_map.len(),
            "If this assertion ever fails, \
             then we have broken the self-loop == 'we have found the object' invariant."
        );
        let o = self.objects.len();
        self.objects.push(Some(value));
        let idx = Index {
            container_id: self.container_id,
            idx: index_map.len(),
        };
        index_map.push(o);
        *reserved_freshness += 1;
        assert!(index_map.len() <= *reserved_freshness);
        idx
    }

    fn get_obj_index(&self, index: Index) -> usize {
        assert_eq!(
            index.container_id, self.container_id,
            "Using index for a container with ID {} for a container with ID {}",
            index.container_id, self.container_id,
        );

        // Union-find-like chaining
        let mut index_map = self.index_map.borrow_mut();
        // Get the root
        let root = {
            let mut idx = index.idx;
            while idx != index_map[idx] {
                debug_assert!(self.objects[idx].is_none());
                idx = index_map[idx];
            }
            idx
        };
        // Perform the squeezing for better performance
        {
            let mut idx = index.idx;
            while idx != index_map[idx] {
                idx = index_map[idx];
                index_map[idx] = root;
            }
        }
        // Return the root
        root
    }

    /// Get the "canonical" index for a given index. This index will continue to remain valid as the
    /// container evolves, but is guaranteed to stay canonical only until the next update; canonical
    /// indexes may change as the container evolves.
    pub fn get_canonical_index(&self, index: Index) -> Index {
        Index {
            container_id: self.container_id,
            idx: self.get_obj_index(index),
        }
    }

    /// Attempts to join a single value at `from_index` into the value at `into_index`. You probably
    /// want to use [`Self::join`] instead though.
    fn join_one(&mut self, into_index: Index, from_index: Index) {
        let into_idx = self.get_obj_index(into_index);
        let from_idx = self.get_obj_index(from_index);
        if into_idx == from_idx {
            // Nothing to be joined
        } else {
            let from_obj = self.objects[from_idx].take().unwrap();
            match self.objects[into_idx]
                .as_mut()
                .unwrap()
                .join(from_obj, &mut self.delayed_joiner)
            {
                Ok(()) => {
                    self.index_map.borrow_mut()[from_idx] = into_idx;
                }
                Err(from_obj) => {
                    self.objects[from_idx] = Some(from_obj);
                }
            }
        }
    }

    /// Attempt to join the value at `from_index` into the value at `into_index`.
    ///
    /// Both indices continue to remain valid for this container, and now refer to the newly joined
    /// object, assuming joining was allowed by the type. If the type rejects the join, then the
    /// indices continue to remain valid, pointing to their original objects.
    ///
    /// Any extra delayed joins (or clone-and-joins) scheduled into the [`DelayedJoiner`] in the
    /// process of the value joining are also performed before this function returns.
    pub fn join(&mut self, into_index: Index, from_index: Index)
    where
        T: Clone,
    {
        let mut already_cloned_objects = UnorderedMap::new();

        self.join_one(into_index, from_index);
        while !self.delayed_joiner.is_empty() {
            // XXX: Should we be using `index_pairs` as a queue instead of a stack instead?
            while let Some((into_index, from_index)) = self.delayed_joiner.index_pairs.pop() {
                self.join_one(into_index, from_index);
            }

            {
                let mut index_map = self.index_map.borrow_mut();
                let reserved_freshness = self.reserved_freshness.borrow();
                assert!(index_map.len() <= *reserved_freshness);
                for l in index_map.len()..*reserved_freshness {
                    index_map.push(l);
                    self.objects.push(None);
                }
            }

            while let Some((cloned_idx, (idx1, idx2))) =
                self.delayed_joiner.clone_and_join_indexes.pop_front()
            {
                assert_eq!(cloned_idx.idx, self.get_obj_index(cloned_idx));
                let cloned_i = self.get_obj_index(cloned_idx);
                let i1 = self.get_obj_index(idx1);
                let i2 = self.get_obj_index(idx2);
                assert!(self.objects[cloned_i].is_none());
                assert!(self.objects[i1].is_some());
                assert!(self.objects[i2].is_some());

                if let Some(&previously_cloned_i) = already_cloned_objects.get(&i1) {
                    // This new index is pointing to an object that was cloned during this specific
                    // joining cycle, thus the instruction in the delayed joiner to re-clone can be
                    // ignored (and must be ignored, if we want to handle recursive objects properly
                    // during the process of cloning).
                    //
                    // We still schedule a delayed non-cloning-join though, so that this is handled
                    // correctly as expected.
                    self.index_map.borrow_mut()[cloned_i] = previously_cloned_i;
                    self.delayed_joiner.schedule(cloned_idx, idx2);
                } else {
                    // This was not cloned before, regular clone-and-join.
                    self.objects[cloned_i] = self.objects[i1].clone();
                    self.delayed_joiner.schedule(cloned_idx, idx2);
                    already_cloned_objects.insert(i1, cloned_i);
                }
            }
        }
    }

    /// Make a clone of the value at `index` and return an index to the clone. This clone is treated
    /// as being completely disjoint from the original value.
    #[must_use]
    pub fn clone_at(&mut self, index: Index) -> Index
    where
        T: Clone,
    {
        let v = self.get(index).clone();
        self.insert(v)
    }

    /// Get a reference to the value referred to by `index`.
    ///
    /// You probably just want to use the [`std::ops::Index`] impl on
    /// this type though.
    pub fn get(&self, index: Index) -> &T {
        let idx = self.get_obj_index(index);
        self.objects[idx].as_ref().unwrap()
    }

    /// Get a mutable reference to the value referred to by `index`.
    ///
    /// You probably just want to use the [`std::ops::IndexMut`] impl
    /// on this type though.
    pub fn get_mut(&mut self, index: Index) -> &mut T {
        let idx = self.get_obj_index(index);
        self.objects[idx].as_mut().unwrap()
    }

    /// Check if two indices point to the same value.
    ///
    /// Indices may start off pointing to different objects and then
    /// eventually start to point to the same object due to
    /// [`Self::join`].
    pub fn index_eq(&self, a: Index, b: Index) -> bool {
        let idx_a = self.get_obj_index(a);
        let idx_b = self.get_obj_index(b);
        idx_a == idx_b
    }

    /// Perform garbage collection on the iterator, keeping objects alive that are reachable from
    /// the given `accessible_roots`.
    ///
    /// Note: any indexes that are _not_ reachable from the given indexes (either by directly being
    /// in `accessible_roots`, or transitively via repeated application of [`Joinable::refers_to`]
    /// are completely invalidated, and will lead to a panic if used after garbage collection is
    /// performed.
    pub fn garbage_collect_with_roots(&mut self, accessible_roots: impl Iterator<Item = Index>) {
        let mut keep_alive_obj_indexes: UnorderedSet<usize> = Default::default();

        let mut worklist: Vec<usize> = accessible_roots.map(|i| self.get_obj_index(i)).collect();

        while let Some(idx) = worklist.pop() {
            keep_alive_obj_indexes.insert(idx);
            for j in self.objects[idx].as_ref().unwrap().refers_to() {
                let j = self.get_obj_index(j);
                if !keep_alive_obj_indexes.contains(&j) {
                    worklist.push(j);
                }
            }
        }

        for (i, obj) in self.objects.iter_mut().enumerate() {
            if obj.is_some() && !keep_alive_obj_indexes.contains(&i) {
                *obj = None;
            }
        }
    }

    /// Get an iterator to all currently alive objects. You may wish to run garbage collection with
    /// [`Self::garbage_collect_with_roots`] before running this if indexes might've been dropped,
    /// in order to prune the set of alive objects.
    pub fn currently_alive_objects_iter(&self) -> impl Iterator<Item = &T> {
        self.objects.iter().flatten()
    }

    /// Get a mutable iterator to all currently alive objects. See
    /// [`Self::currently_alive_objects_iter`]
    pub fn currently_alive_objects_iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.objects.iter_mut().flatten()
    }

    /// Get an iterator to canonical indices to all currently alive objects. See
    /// [`Self::currently_alive_objects_iter`]
    pub fn currently_alive_canon_indices_iter(&self) -> impl Iterator<Item = Index> + '_ {
        self.objects
            .iter()
            .enumerate()
            .filter(|(_, opt_obj)| opt_obj.is_some())
            .map(|(i, _)| Index {
                container_id: self.container_id,
                idx: i,
            })
    }
}

impl<T: Joinable + Clone> Container<T> {
    /// Make a deep clone of the container, updating any indexes (including internal indices) as
    /// necessary to produce a completely disjoint container whose indexes cannot be used for the
    /// original container, and vice-versa.
    pub fn deep_clone<'a>(&'a self, roots: impl Iterator<Item = &'a mut Index>) -> Self {
        let Self {
            reserved_freshness,
            container_id: _,
            index_map,
            objects,
            delayed_joiner,
        } = self;
        assert_eq!(
            *reserved_freshness.borrow(),
            index_map.borrow().len(),
            "Should not have any unused freshness yet to be squeezed out"
        );

        assert_eq!(
            delayed_joiner.index_pairs.len(),
            0,
            "Unsupported: deep cloning a container that is in the middle of joining"
        );

        let mut r = Self::new();
        for x in roots {
            x.container_id = r.container_id;
        }
        r.index_map = index_map.clone();
        r.objects = objects.clone();
        r.delayed_joiner = delayed_joiner.clone_using(&r);
        for obj in r.objects.iter_mut() {
            if let Some(obj) = obj {
                for idx in obj.refers_to_mut() {
                    idx.container_id = r.container_id;
                }
            }
        }
        *r.reserved_freshness.borrow_mut() = r.index_map.borrow().len();
        r
    }
}

impl<T: Joinable + Default> Container<T> {
    /// Insert the [`Default::default`] element of `T` into the
    /// container.
    pub fn insert_default(&mut self) -> Index {
        self.insert(T::default())
    }
}

impl<T: Joinable> std::ops::Index<Index> for Container<T> {
    type Output = T;
    fn index(&self, index: Index) -> &Self::Output {
        self.get(index)
    }
}
impl<T: Joinable> std::ops::IndexMut<Index> for Container<T> {
    fn index_mut(&mut self, index: Index) -> &mut Self::Output {
        self.get_mut(index)
    }
}

impl<T: Joinable + std::fmt::Debug> std::fmt::Debug for Container<T> {
    /// A custom debug formatter that removes the manual indexing that needs to be done, instead
    /// showing a cleaner view on the container by collapsing the different indexes together.
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let Container {
            reserved_freshness,
            container_id: _,
            index_map,
            objects,
            delayed_joiner: _,
        } = self;

        let mut objs = vec![];
        let index_map_len = index_map.borrow().len();
        for idx in 0..index_map_len {
            let obj_idx = self.get_obj_index(Index {
                container_id: self.container_id,
                idx,
            });
            if obj_idx >= objs.len() {
                objs.resize_with(obj_idx + 1, || (vec![], None));
            }
            objs[obj_idx].0.push(idx);
            objs[obj_idx].1 = objects[obj_idx].as_ref();
        }

        let mut p = f.debug_map();
        for (idxs, obj) in &objs {
            if idxs.is_empty() {
                continue;
            }
            // The format_args on the idxs here is to simply force a "collapsed" view on the idxs
            p.entry(&format_args!("{:?}", idxs), &obj.unwrap());
        }
        if index_map_len < *reserved_freshness.borrow() {
            p.entry(&"and some reserved", &true);
        }
        p.finish()
    }
}

/// A set of [`Index`]s
pub struct IndexSet {
    idxs: UnorderedSet<(usize, usize)>,
}

impl IndexSet {
    /// A new, empty set of [`Index`]s
    pub fn new() -> Self {
        Self {
            idxs: Default::default(),
        }
    }

    /// Returns `true` if the set contains a value.
    pub fn contains(&self, idx: Index) -> bool {
        self.idxs.contains(&(idx.container_id, idx.idx))
    }

    /// Adds a value to the set.
    ///
    /// If the set did not have this value present, `true` is returned.
    ///
    /// If the set did have this value present, `false` is returned.
    pub fn insert(&mut self, idx: Index) -> bool {
        self.idxs.insert((idx.container_id, idx.idx))
    }
}

/// A map of [`Index`]s to `V`
pub struct IndexMap<V> {
    map: UnorderedMap<(usize, usize), V>,
}

impl<V> IndexMap<V> {
    /// A new, empty map
    pub fn new() -> Self {
        Self {
            map: Default::default(),
        }
    }

    /// An iterator over the map
    pub fn iter(&self) -> impl Iterator<Item = (Index, &V)> {
        self.map
            .iter()
            .map(|(&(container_id, idx), v)| (Index { container_id, idx }, v))
    }

    /// Convert the map into an iterator
    pub fn into_iter(self) -> impl Iterator<Item = (Index, V)> {
        self.map
            .into_iter()
            .map(|((container_id, idx), v)| (Index { container_id, idx }, v))
    }

    /// Returns a reference to the value corresponding to the key.
    pub fn get(&self, k: Index) -> Option<&V> {
        self.map.get(&(k.container_id, k.idx))
    }

    /// Returns a mutable reference to the value corresponding to the key.
    pub fn get_mut(&mut self, k: Index) -> Option<&mut V> {
        self.map.get_mut(&(k.container_id, k.idx))
    }

    /// Returns `true` if the map contains no elements.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Inserts a key-value pair into the map.
    ///
    /// If the map did not have this key present, [`None`] is returned.  If the map did have this
    /// key present, the value is updated, and the old value is returned.
    pub fn insert(&mut self, k: Index, v: V) -> Option<V> {
        self.map.insert((k.container_id, k.idx), v)
    }
}

impl<T> Default for IndexMap<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V> FromIterator<(Index, V)> for IndexMap<V> {
    fn from_iter<T: IntoIterator<Item = (Index, V)>>(it: T) -> Self {
        Self {
            map: it
                .into_iter()
                .map(|(Index { container_id, idx }, v)| ((container_id, idx), v))
                .collect(),
        }
    }
}

impl<V: std::fmt::Debug> std::fmt::Debug for IndexMap<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}
