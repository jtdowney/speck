#![no_std]

use core::{fmt::Debug, mem, ops::BitXor};

pub trait SpeckCipher {
    fn seal_in_place(&self, buffer: &mut [u8]) -> Result<(), Error>;
    fn open_in_place(&self, buffer: &mut [u8]) -> Result<(), Error>;
}

#[derive(Debug)]
pub struct Error;

pub type Speck64_96 = Speck<u32, 3, 26, 3, 8>;
pub type Speck64_128 = Speck<u32, 4, 27, 3, 8>;
pub type Speck128_128 = Speck<u64, 2, 32, 3, 8>;
pub type Speck128_192 = Speck<u64, 3, 33, 3, 8>;
pub type Speck128_256 = Speck<u64, 4, 34, 3, 8>;

pub struct Speck<
    T: Word,
    const KEY_WORDS: usize,
    const ROUNDS: usize,
    const ROTATE_LEFT: u32,
    const ROTATE_RIGHT: u32,
> {
    round_keys: [T; ROUNDS],
}

impl<
	T: Word,
	const KEY_WORDS: usize,
	const ROUNDS: usize,
	const ROTATE_LEFT: u32,
	const ROTATE_RIGHT: u32,
    > Speck<T, KEY_WORDS, ROUNDS, ROTATE_LEFT, ROTATE_RIGHT>
{
    pub fn new_slice(key: &[u8]) -> Result<Self, Error> {
	let word_size = mem::size_of::<T>();
	if key.len() != word_size * KEY_WORDS {
	    return Err(Error);
	}

	let mut words = [T::default(); KEY_WORDS];
	for (i, word) in key.chunks(word_size).enumerate() {
	    words[i] = T::from_le_bytes(word);
	}

	Ok(Self::new(words))
    }

    pub fn new(mut words: [T; KEY_WORDS]) -> Self {
	let mut key = words[0];
	let rest = &mut words[1..];

	let mut round_keys = [T::default(); ROUNDS];
	for (round, round_key) in round_keys.iter_mut().enumerate() {
	    *round_key = key;

	    let round_word = T::from_usize(round);
	    let i = round % (KEY_WORDS - 1);

	    (rest[i], key) = Self::round(rest[i], key, round_word);
	}

	Self { round_keys }
    }

    pub fn encrypt_words(&self, input: [T; 2]) -> [T; 2] {
	let mut y = input[0];
	let mut x = input[1];

	for round_key in self.round_keys {
	    (x, y) = Self::round(x, y, round_key);
	}

	let mut output = [T::default(); 2];
	output[0] = y;
	output[1] = x;

	output
    }

    pub fn decrypt_words(&self, input: [T; 2]) -> [T; 2] {
	let mut y = input[0];
	let mut x = input[1];

	for &round_key in self.round_keys.iter().rev() {
	    (x, y) = Self::unround(x, y, round_key);
	}

	let mut output = [T::default(); 2];
	output[0] = y;
	output[1] = x;

	output
    }

    fn round(mut x: T, mut y: T, k: T) -> (T, T) {
	x = x.rotate_right(ROTATE_RIGHT);
	x = x.wrapping_add(y);
	x = x ^ k;

	y = y.rotate_left(ROTATE_LEFT);
	y = y ^ x;

	(x, y)
    }

    fn unround(mut x: T, mut y: T, k: T) -> (T, T) {
	y = y ^ x;
	y = y.rotate_right(ROTATE_LEFT);

	x = x ^ k;
	x = x.wrapping_sub(y);
	x = x.rotate_left(ROTATE_RIGHT);

	(x, y)
    }
}

impl<
	T: Word,
	const KEY_WORDS: usize,
	const ROUNDS: usize,
	const ROTATE_LEFT: u32,
	const ROTATE_RIGHT: u32,
    > SpeckCipher for Speck<T, KEY_WORDS, ROUNDS, ROTATE_LEFT, ROTATE_RIGHT>
{
    fn seal_in_place(&self, buffer: &mut [u8]) -> Result<(), Error> {
	let word_size = mem::size_of::<T>();
	if buffer.len() != word_size * 2 {
	    return Err(Error);
	}

	let mut words = [T::default(); 2];
	words[0] = T::from_le_bytes(&buffer[0..word_size]);
	words[1] = T::from_le_bytes(&buffer[word_size..]);

	words = self.encrypt_words(words);

	words[0].copy_to_slice(&mut buffer[0..word_size]);
	words[1].copy_to_slice(&mut buffer[word_size..]);

	Ok(())
    }

    fn open_in_place(&self, buffer: &mut [u8]) -> Result<(), Error> {
	let word_size = mem::size_of::<T>();
	if buffer.len() != word_size * 2 {
	    return Err(Error);
	}

	let mut words = [T::default(); 2];
	words[0] = T::from_le_bytes(&buffer[0..word_size]);
	words[1] = T::from_le_bytes(&buffer[word_size..]);

	words = self.decrypt_words(words);

	words[0].copy_to_slice(&mut buffer[0..word_size]);
	words[1].copy_to_slice(&mut buffer[word_size..]);

	Ok(())
    }
}

pub trait Word: Default + BitXor<Output = Self> + Debug + Copy {
    fn from_le_bytes(bytes: &[u8]) -> Self;
    fn copy_to_slice(self, data: &mut [u8]);
    fn from_usize(i: usize) -> Self;
    fn wrapping_add(self, rhs: Self) -> Self;
    fn wrapping_sub(self, rhs: Self) -> Self;
    fn rotate_left(self, n: u32) -> Self;
    fn rotate_right(self, n: u32) -> Self;
}

impl Word for u32 {
    #[inline]
    fn from_le_bytes(bytes: &[u8]) -> Self {
	let mut input = [0; 4];
	input.copy_from_slice(bytes);
	u32::from_le_bytes(input)
    }

    #[inline]
    fn copy_to_slice(self, data: &mut [u8]) {
	let bytes = self.to_le_bytes();
	data.copy_from_slice(&bytes);
    }

    #[inline]
    fn from_usize(i: usize) -> Self {
	i as u32
    }

    #[inline]
    fn wrapping_add(self, rhs: Self) -> Self {
	self.wrapping_add(rhs)
    }

    #[inline]
    fn wrapping_sub(self, rhs: Self) -> Self {
	self.wrapping_sub(rhs)
    }

    #[inline]
    fn rotate_left(self, n: u32) -> Self {
	self.rotate_left(n)
    }

    #[inline]
    fn rotate_right(self, n: u32) -> Self {
	self.rotate_right(n)
    }
}

impl Word for u64 {
    #[inline]
    fn from_le_bytes(bytes: &[u8]) -> Self {
	let mut input = [0; 8];
	input.copy_from_slice(bytes);
	Self::from_le_bytes(input)
    }

    #[inline]
    fn copy_to_slice(self, data: &mut [u8]) {
	let bytes = self.to_le_bytes();
	data.copy_from_slice(&bytes);
    }

    #[inline]
    fn from_usize(i: usize) -> Self {
	i as Self
    }

    #[inline]
    fn wrapping_add(self, rhs: Self) -> Self {
	self.wrapping_add(rhs)
    }

    #[inline]
    fn wrapping_sub(self, rhs: Self) -> Self {
	self.wrapping_sub(rhs)
    }

    #[inline]
    fn rotate_left(self, n: u32) -> Self {
	self.rotate_left(n)
    }

    #[inline]
    fn rotate_right(self, n: u32) -> Self {
	self.rotate_right(n)
    }
}
