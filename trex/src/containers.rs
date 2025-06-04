//! Generally useful container data structures

use unordered::{UnorderedMap, UnorderedSet};

/// A set of values of type `T`, which maintain their order of insertion into the set, which can
/// then be recovered by converting it into a `Vec<T>`
#[derive(Default)]
pub struct InsertionOrderedSet<T: Eq + std::hash::Hash + Ord + Clone> {
    data: Vec<T>,
    revmap: UnorderedMap<T, usize>,
}

impl<T: Eq + std::hash::Hash + Ord + Clone> InsertionOrderedSet<T> {
    /// A new, empty set
    pub fn new() -> Self {
        Self {
            data: Default::default(),
            revmap: Default::default(),
        }
    }

    /// Convert into a vec, maintaining the order of insertion and all indexes that were returned at
    /// insertion.
    pub fn into_vec(self) -> Vec<T> {
        self.data
    }

    /// Insert `v` into the set, returning an index that can be used for the vector when eventually
    /// [`Self::into_vec`] is run. If `v` already exists in the set, will not perform re-insertion,
    /// but will instead directly refer to the pre-existing value.
    pub fn insert(&mut self, v: T) -> usize {
        if let Some(idx) = self.revmap.get(&v) {
            *idx
        } else {
            let idx = self.data.len();
            self.data.push(v.clone());
            self.revmap.insert(v, idx);
            idx
        }
    }

    /// Get the member of the set at index `idx`.
    pub fn get(&self, idx: usize) -> Option<&T> {
        self.data.get(idx)
    }

    /// Get the index of `v` if it exists in the set
    pub fn get_index(&self, v: &T) -> Option<usize> {
        self.revmap.get(v).cloned()
    }

    /// Iterate over the storage, in the order of insertion
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.data.iter()
    }
}

/// A highly-minimal disjoint-set data structure, also known as union-find. Intended to be used with
/// a separate `Vec<T>` holding actual objects to make itself useful. For a nicer interface that
/// allows sets of values of arbitrary type `T`, see [`DisjointSet`].
#[derive(Default)]
pub struct DisjointSetIndexes {
    forest: std::cell::Cell<Vec<usize>>,
}

impl DisjointSetIndexes {
    /// Construct a new, empty set
    pub fn new() -> Self {
        Self {
            forest: Default::default(),
        }
    }

    /// (Internal-only) provide convenient access to the interal forest, mutably. If called within
    /// itself, then weird results may occur.
    fn borrowed<T>(&self, f: impl FnOnce(&mut Vec<usize>) -> T) -> T {
        let mut forest = self.forest.take();
        let res = f(&mut forest);
        self.forest.set(forest);
        res
    }

    /// Obtain the (current) representative of a set containing `x`
    pub fn representative(&self, x: usize) -> usize {
        self.borrowed(|f| {
            while x >= f.len() {
                f.push(f.len());
            }
            if f[x] == x {
                x
            } else {
                let mut interm = vec![];
                let mut x = x;
                while f[x] != x {
                    interm.push(x);
                    x = f[x];
                }
                for m in interm.into_iter() {
                    f[m] = x;
                }
                x
            }
        })
    }

    /// Merge the two sets that contain the elements `parent` and `child`. There is no _logical_
    /// reason to distinguish `parent` and `child`, but it can help with nicer debug output if
    /// chosen carefully. Here the representative of the set containing `parent` becomes the
    /// representative of the union of both sets.
    pub fn merge(&mut self, parent: usize, child: usize) {
        let rchild = self.representative(child);
        let rparent = self.representative(parent);
        self.borrowed(|f| {
            f[rchild] = rparent;
        })
    }
}

/// A disjoint-set implementation for sets of arbitrary type `T`
#[derive(Default)]
pub struct DisjointSet<T: Clone + std::hash::Hash + Ord + std::cmp::Eq> {
    sets: DisjointSetIndexes,
    storage: InsertionOrderedSet<T>,
}

impl<T: Clone + std::hash::Hash + Ord + std::cmp::Eq> DisjointSet<T> {
    /// A new, empty disjoint set container
    pub fn new() -> Self {
        Self {
            sets: Default::default(),
            storage: InsertionOrderedSet::new(),
        }
    }

    /// Get the (current) representative of a set containing `x`, if it exists, without modifying
    /// the set or inserting it in.
    pub fn get_representative(&self, x: &T) -> Option<&T> {
        self.storage
            .get(self.sets.representative(self.storage.get_index(x)?))
    }

    /// Obtain the (current) representative of a set containing `x`, inserting it as a singleton if
    /// it didn't exist in the set.
    pub fn representative(&mut self, x: T) -> &T {
        let idx = self.storage.insert(x);
        let rep = self.sets.representative(idx);
        self.storage.get(rep).unwrap()
    }

    /// Merge the two sets that contain the elements `parent` and `child`. There is no _logical_
    /// reason to distinguish `parent` and `child`, but it can help with nicer debug output if
    /// chosen carefully. Here the representative of the set containing `parent` becomes the
    /// representative of the union of both sets.
    pub fn merge(&mut self, parent: T, child: T) {
        let pidx = self.storage.insert(parent);
        let cidx = self.storage.insert(child);
        self.sets.merge(pidx, cidx);
    }

    /// An iterator over the discovered disjoint sets
    pub fn disjoint_sets_iter(&self) -> impl IntoIterator<Item = UnorderedSet<&T>> {
        let mut res: UnorderedMap<&T, UnorderedSet<&T>> = Default::default();
        for v in self.storage.iter() {
            res.entry(self.get_representative(v).unwrap())
                .or_default()
                .insert(v);
        }
        res.into_values()
    }
}

pub mod unordered {
    #[cfg(not(feature = "deterministic_containers"))]
    type BaseMap<K, V> = std::collections::HashMap<K, V>;
    #[cfg(feature = "deterministic_containers")]
    type BaseMap<K, V> = std::collections::BTreeMap<K, V>;
    #[cfg(not(feature = "deterministic_containers"))]
    pub type UnorderedMapEntry<'a, K, V> = std::collections::hash_map::Entry<'a, K, V>;
    #[cfg(feature = "deterministic_containers")]
    pub type UnorderedMapEntry<'a, K, V> = std::collections::btree_map::Entry<'a, K, V>;
    #[cfg(not(feature = "deterministic_containers"))]
    type BaseSet<T> = std::collections::HashSet<T>;
    #[cfg(feature = "deterministic_containers")]
    type BaseSet<T> = std::collections::BTreeSet<T>;

    /// An unordered map type. This type specifies the _intention_ of unorderedness, but allows the
    /// crate's features to dictate whether it actually use non-determinism at runtime.
    ///
    /// This type is meant to aid in debugging. Thus, it also ensures that its debug view is always
    /// ordered.
    #[derive(Clone, PartialEq, Eq)]
    pub struct UnorderedMap<K: std::hash::Hash + Ord + Eq, V> {
        map: BaseMap<K, V>,
    }

    impl<K: std::hash::Hash + Ord + Eq, V> UnorderedMap<K, V> {
        /// Make a new, empty unordered map
        pub fn new() -> Self {
            Self {
                map: Default::default(),
            }
        }

        /// Get an iterator over the entries of the map.
        pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
            self.map.iter()
        }

        /// Get an iterator over the entries of the map, with mutable references to the values.
        pub fn iter_mut(&mut self) -> impl Iterator<Item = (&K, &mut V)> {
            self.map.iter_mut()
        }

        /// Returns `true` if the map contains a value for the specified key.
        pub fn contains_key<Q: ?Sized>(&self, k: &Q) -> bool
        where
            K: std::borrow::Borrow<Q>,
            Q: std::hash::Hash + Ord + Eq,
        {
            self.map.contains_key(k)
        }

        /// Returns a reference to the value corresponding to the key.
        pub fn get<Q: ?Sized>(&self, k: &Q) -> Option<&V>
        where
            K: std::borrow::Borrow<Q>,
            Q: std::hash::Hash + Ord + Eq,
        {
            self.map.get(k)
        }

        /// Returns a mutable reference to the value corresponding to the key.
        pub fn get_mut<Q: ?Sized>(&mut self, k: &Q) -> Option<&mut V>
        where
            K: std::borrow::Borrow<Q>,
            Q: std::hash::Hash + Ord + Eq,
        {
            self.map.get_mut(k)
        }

        /// Inserts a key-value pair into the map.
        ///
        /// If the map did not have this key present, [`None`] is returned.
        ///
        /// If the map did have this key present, the value is updated, and the old value is
        /// returned. The key is not updated, though.
        pub fn insert(&mut self, k: K, v: V) -> Option<V> {
            self.map.insert(k, v)
        }

        /// Removes a key from the map, returning the value at the key if the key was previously in
        /// the map.
        pub fn remove<Q: ?Sized>(&mut self, k: &Q) -> Option<V>
        where
            K: std::borrow::Borrow<Q>,
            Q: std::hash::Hash + Ord + Eq,
        {
            self.map.remove(k)
        }

        /// Gets the given key's corresponding entry in the map for in-place manipulation.
        pub fn entry(&mut self, key: K) -> UnorderedMapEntry<'_, K, V> {
            self.map.entry(key)
        }

        /// An iterator visiting all keys in arbitrary order.
        pub fn keys(&self) -> impl Iterator<Item = &K> {
            self.map.keys()
        }

        /// An iterator visiting all values in arbitrary order.
        pub fn values(&self) -> impl Iterator<Item = &V> {
            self.map.values()
        }

        /// An iterator visiting all values mutably in arbitrary order.
        pub fn values_mut(&mut self) -> impl Iterator<Item = &mut V> {
            self.map.values_mut()
        }

        /// Returns the number of elements in the map.
        pub fn len(&self) -> usize {
            self.map.len()
        }

        /// Returns `true` if the map contains no elements.
        pub fn is_empty(&self) -> bool {
            self.map.is_empty()
        }

        /// Creates a consuming iterator visiting all the values in arbitrary order.
        #[cfg(not(feature = "deterministic_containers"))]
        pub fn into_values(self) -> std::collections::hash_map::IntoValues<K, V> {
            self.map.into_values()
        }
        /// Creates a consuming iterator visiting all the values in arbitrary order.
        #[cfg(feature = "deterministic_containers")]
        pub fn into_values(self) -> std::collections::btree_map::IntoValues<K, V> {
            self.map.into_values()
        }
    }

    impl<K: std::hash::Hash + Ord + Eq, V> Default for UnorderedMap<K, V> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<K: std::hash::Hash + Ord + Eq, V> FromIterator<(K, V)> for UnorderedMap<K, V> {
        fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
            Self {
                map: BaseMap::from_iter(iter),
            }
        }
    }

    impl<K: std::hash::Hash + Ord + Eq + std::fmt::Debug, V: std::fmt::Debug> std::fmt::Debug
        for UnorderedMap<K, V>
    {
        #[cfg(not(feature = "deterministic_containers"))]
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            self.map
                .iter()
                .collect::<std::collections::BTreeMap<_, _>>()
                .fmt(f)
        }
        #[cfg(feature = "deterministic_containers")]
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            self.map.fmt(f)
        }
    }

    impl<K: std::hash::Hash + Ord + Eq, V> IntoIterator for UnorderedMap<K, V> {
        type Item = (K, V);
        type IntoIter = <BaseMap<K, V> as IntoIterator>::IntoIter;

        fn into_iter(self) -> Self::IntoIter {
            self.map.into_iter()
        }
    }
    impl<'a, K: std::hash::Hash + Ord + Eq, V> IntoIterator for &'a UnorderedMap<K, V> {
        type Item = (&'a K, &'a V);
        type IntoIter = <&'a BaseMap<K, V> as IntoIterator>::IntoIter;

        fn into_iter(self) -> Self::IntoIter {
            self.map.iter()
        }
    }
    impl<'a, K: std::hash::Hash + Ord + Eq, V> IntoIterator for &'a mut UnorderedMap<K, V> {
        type Item = (&'a K, &'a mut V);
        type IntoIter = <&'a mut BaseMap<K, V> as IntoIterator>::IntoIter;

        fn into_iter(self) -> Self::IntoIter {
            self.map.iter_mut()
        }
    }

    /// An unordered set type. This type specifies the _intention_ of unorderedness, but allows the
    /// crate's features to dictate whether it actually use non-determinism at runtime.
    ///
    /// This type is meant to aid in debugging. Thus, it also ensures that its debug view is always
    /// ordered.
    #[derive(Clone, PartialEq, Eq)]
    pub struct UnorderedSet<T: std::hash::Hash + Ord + Eq> {
        set: BaseSet<T>,
    }

    impl<T: std::hash::Hash + Ord + Eq> UnorderedSet<T> {
        /// Make a new, empty unordered set
        pub fn new() -> Self {
            Self {
                set: BaseSet::new(),
            }
        }

        /// Adds a value to the set.
        ///
        /// If the set did not have this value present, `true` is returned.
        ///
        /// If the set did have this value present, `false` is returned.
        pub fn insert(&mut self, value: T) -> bool {
            self.set.insert(value)
        }

        /// Removes a value from the set. Returns whether the value was present in the set.
        pub fn remove<Q: ?Sized>(&mut self, value: &Q) -> bool
        where
            T: std::borrow::Borrow<Q>,
            Q: std::hash::Hash + Ord + Eq,
        {
            self.set.remove(value)
        }

        /// Get an iterator over the elements of the set.
        pub fn iter(&self) -> impl Iterator<Item = &T> {
            self.set.iter()
        }

        /// Returns `true` if the set contains a value.
        pub fn contains<Q: ?Sized>(&self, value: &Q) -> bool
        where
            T: std::borrow::Borrow<Q>,
            Q: std::hash::Hash + Ord + Eq,
        {
            self.set.contains(value)
        }

        /// Returns the number of elements in the set.
        pub fn len(&self) -> usize {
            self.set.len()
        }

        /// Returns `true` if the set contains no elements.
        pub fn is_empty(&self) -> bool {
            self.set.is_empty()
        }

        /// Visits the values representing the union, i.e., all the values in `self` or `other`,
        /// without duplicates.
        pub fn union<'a>(&'a self, other: &'a Self) -> impl Iterator<Item = &'a T> {
            self.set.union(&other.set)
        }

        /// Visits the elements representing the difference, i.e., the elements that are in `self`
        /// but not in `other`, without duplicates.
        pub fn difference<'a>(&'a self, other: &'a Self) -> impl Iterator<Item = &'a T> {
            self.set.difference(&other.set)
        }

        /// Clears the set, removing all values.
        pub fn clear(&mut self) {
            self.set.clear()
        }
    }

    impl<T: std::hash::Hash + Ord + Eq> Default for UnorderedSet<T> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<T: std::hash::Hash + Ord + Eq + std::fmt::Debug> std::fmt::Debug for UnorderedSet<T> {
        #[cfg(not(feature = "deterministic_containers"))]
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            self.set
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .fmt(f)
        }
        #[cfg(feature = "deterministic_containers")]
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            self.set.fmt(f)
        }
    }

    impl<T: std::hash::Hash + Ord + Eq> Extend<T> for UnorderedSet<T> {
        fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
            self.set.extend(iter);
        }
    }
    impl<'a, T: 'a + std::hash::Hash + Ord + Eq + Copy> Extend<&'a T> for UnorderedSet<T> {
        fn extend<I: IntoIterator<Item = &'a T>>(&mut self, iter: I) {
            self.set.extend(iter);
        }
    }

    impl<T: std::hash::Hash + Ord + Eq> IntoIterator for UnorderedSet<T> {
        type Item = T;
        type IntoIter = <BaseSet<T> as IntoIterator>::IntoIter;

        fn into_iter(self) -> Self::IntoIter {
            self.set.into_iter()
        }
    }
    impl<'a, T: std::hash::Hash + Ord + Eq> IntoIterator for &'a UnorderedSet<T> {
        type Item = &'a T;
        type IntoIter = <&'a BaseSet<T> as IntoIterator>::IntoIter;

        fn into_iter(self) -> Self::IntoIter {
            self.set.iter()
        }
    }

    impl<T: std::hash::Hash + Ord + Eq> FromIterator<T> for UnorderedSet<T> {
        fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
            Self {
                set: BaseSet::from_iter(iter),
            }
        }
    }

    impl<T: std::hash::Hash + Ord + Eq + Clone> std::ops::Sub for &UnorderedSet<T> {
        type Output = UnorderedSet<T>;
        fn sub(self, other: Self) -> Self::Output {
            Self::Output {
                set: &self.set - &other.set,
            }
        }
    }
}
