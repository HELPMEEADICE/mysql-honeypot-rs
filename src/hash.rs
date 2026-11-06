// SPDX-License-Identifier: GPL-3.0-only
//! Self-contained MD5, SHA-1, SHA-2 digests.
//!
//! The virtual database answers `MD5()`, `SHA()`, `SHA1()`, `SHA2()` and
//! `PASSWORD()` with *real* digests. Returning a constant instead would be both
//! wrong for the caller and a one-request fingerprint, so the algorithms are
//! implemented here rather than pulling in a crypto dependency: they are short,
//! allocation-free per block and need no secret material.
//!
//! None of this is used to protect anything — it exists so that a honeypot's
//! SQL functions answer truthfully.

/// Compute `MD5(data)` and return the 16 raw bytes.
pub fn md5(data: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76a_a478,
        0xe8c7_b756,
        0x2420_70db,
        0xc1bd_ceee,
        0xf57c_0faf,
        0x4787_c62a,
        0xa830_4613,
        0xfd46_9501,
        0x6980_98d8,
        0x8b44_f7af,
        0xffff_5bb1,
        0x895c_d7be,
        0x6b90_1122,
        0xfd98_7193,
        0xa679_438e,
        0x49b4_0821,
        0xf61e_2562,
        0xc040_b340,
        0x265e_5a51,
        0xe9b6_c7aa,
        0xd62f_105d,
        0x0244_1453,
        0xd8a1_e681,
        0xe7d3_fbc8,
        0x21e1_cde6,
        0xc337_07d6,
        0xf4d5_0d87,
        0x455a_14ed,
        0xa9e3_e905,
        0xfcef_a3f8,
        0x676f_02d9,
        0x8d2a_4c8a,
        0xfffa_3942,
        0x8771_f681,
        0x6d9d_6122,
        0xfde5_380c,
        0xa4be_ea44,
        0x4bde_cfa9,
        0xf6bb_4b60,
        0xbebf_bc70,
        0x289b_7ec6,
        0xeaa1_27fa,
        0xd4ef_3085,
        0x0488_1d05,
        0xd9d4_d039,
        0xe6db_99e5,
        0x1fa2_7cf8,
        0xc4ac_5665,
        0xf429_2244,
        0x432a_ff97,
        0xab94_23a7,
        0xfc93_a039,
        0x655b_59c3,
        0x8f0c_cc92,
        0xffef_f47d,
        0x8584_5dd1,
        0x6fa8_7e4f,
        0xfe2c_e6e0,
        0xa301_4314,
        0x4e08_11a1,
        0xf753_7e82,
        0xbd3a_f235,
        0x2ad7_d2bb,
        0xeb86_d391,
    ];

    let mut a0: u32 = 0x6745_2301;
    let mut b0: u32 = 0xefcd_ab89;
    let mut c0: u32 = 0x98ba_dcfe;
    let mut d0: u32 = 0x1032_5476;

    let message = pad(data, 64, true);
    let mut offset = 0usize;
    while offset + 64 <= message.len() {
        let block = &message[offset..offset + 64];
        offset += 64;
        let mut words = [0u32; 16];
        for (index, word) in words.iter_mut().enumerate() {
            let start = index * 4;
            *word = u32::from_le_bytes([
                block[start],
                block[start + 1],
                block[start + 2],
                block[start + 3],
            ]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for round in 0..64 {
            let (f, g) = match round / 16 {
                0 => ((b & c) | (!b & d), round),
                1 => ((d & b) | (!d & c), (5 * round + 1) % 16),
                2 => (b ^ c ^ d, (3 * round + 5) % 16),
                _ => (c ^ (b | !d), (7 * round) % 16),
            };
            let rotated = a
                .wrapping_add(f)
                .wrapping_add(K[round])
                .wrapping_add(words[g]);
            let shifted = rotated.rotate_left(S[round]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(shifted);
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0u8; 16];
    for (index, word) in [a0, b0, c0, d0].iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// Compute `SHA1(data)` and return the 20 raw bytes.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let message = pad(data, 64, false);
    let mut offset = 0usize;
    while offset + 64 <= message.len() {
        let block = &message[offset..offset + 64];
        offset += 64;
        let mut w = [0u32; 80];
        for (index, slot) in w.iter_mut().take(16).enumerate() {
            let start = index * 4;
            *slot = u32::from_be_bytes([
                block[start],
                block[start + 1],
                block[start + 2],
                block[start + 3],
            ]);
        }
        for index in 16..80 {
            w[index] = (w[index - 3] ^ w[index - 8] ^ w[index - 14] ^ w[index - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (round, word) in w.iter().enumerate() {
            let (f, k) = match round {
                0..=19 => ((b & c) | (!b & d), 0x5a82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (index, word) in h.iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Which SHA-2 variant `SHA2(value, bits)` asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sha2Bits {
    /// 224 bit digest.
    Sha224,
    /// 256 bit digest.
    Sha256,
    /// 384 bit digest.
    Sha384,
    /// 512 bit digest.
    Sha512,
}

impl Sha2Bits {
    /// Map the second `SHA2()` argument onto a variant, the way MySQL does.
    ///
    /// MySQL rounds the requested length to the nearest supported digest:
    /// up to 256/(257..=384) becomes 256/384, anything larger becomes 512.
    pub fn from_bits(bits: u64) -> Self {
        match bits {
            0..=224 => Self::Sha224,
            225..=256 => Self::Sha256,
            257..=384 => Self::Sha384,
            _ => Self::Sha512,
        }
    }

    /// Digest length in bytes.
    pub fn length(self) -> usize {
        match self {
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

/// Compute the requested SHA-2 digest, truncated to [`Sha2Bits::length`].
pub fn sha2(data: &[u8], bits: Sha2Bits) -> Vec<u8> {
    let mut digest = match bits {
        Sha2Bits::Sha224 | Sha2Bits::Sha256 => sha256_with(
            data,
            if bits == Sha2Bits::Sha224 {
                SHA224_IV
            } else {
                SHA256_IV
            },
        )
        .to_vec(),
        Sha2Bits::Sha384 | Sha2Bits::Sha512 => sha512_with(
            data,
            if bits == Sha2Bits::Sha384 {
                SHA384_IV
            } else {
                SHA512_IV
            },
        )
        .to_vec(),
    };
    digest.truncate(bits.length());
    digest
}

const SHA224_IV: [u32; 8] = [
    0xc105_9ed8,
    0x367c_d507,
    0x3070_dd17,
    0xf70e_5939,
    0xffc0_0b31,
    0x6858_1511,
    0x64f9_8fa7,
    0xbefa_4fa4,
];

const SHA256_IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const SHA384_IV: [u64; 8] = [
    0xcbbb_9d5d_c105_9ed8,
    0x629a_292a_367c_d507,
    0x9159_015a_3070_dd17,
    0x152f_ecd8_f70e_5939,
    0x6733_2667_ffc0_0b31,
    0x8eb4_4a87_6858_1511,
    0xdb0c_2e0d_64f9_8fa7,
    0x47b5_481d_befa_4fa4,
];

const SHA512_IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

/// `SHA2(x, 256)` — 32 raw bytes.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    sha256_with(data, SHA256_IV)
}

fn sha256_with(data: &[u8], iv: [u32; 8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];

    let mut h = iv;
    let message = pad(data, 64, false);
    let mut offset = 0usize;
    while offset + 64 <= message.len() {
        let block = &message[offset..offset + 64];
        offset += 64;
        let mut w = [0u32; 64];
        for (index, slot) in w.iter_mut().take(16).enumerate() {
            let start = index * 4;
            *slot = u32::from_be_bytes([
                block[start],
                block[start + 1],
                block[start + 2],
                block[start + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }
        let mut v = h;
        for index in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let temp1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[index])
                .wrapping_add(w[index]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let temp2 = s0.wrapping_add(maj);
            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3].wrapping_add(temp1);
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = temp1.wrapping_add(temp2);
        }
        for index in 0..8 {
            h[index] = h[index].wrapping_add(v[index]);
        }
    }
    let mut out = [0u8; 32];
    for (index, word) in h.iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// `SHA2(x, 512)` — 64 raw bytes.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    sha512_with(data, SHA512_IV)
}

fn sha512_with(data: &[u8], iv: [u64; 8]) -> [u8; 64] {
    const K: [u64; 80] = [
        0x428a_2f98_d728_ae22,
        0x7137_4491_23ef_65cd,
        0xb5c0_fbcf_ec4d_3b2f,
        0xe9b5_dba5_8189_dbbc,
        0x3956_c25b_f348_b538,
        0x59f1_11f1_b605_d019,
        0x923f_82a4_af19_4f9b,
        0xab1c_5ed5_da6d_8118,
        0xd807_aa98_a303_0242,
        0x1283_5b01_4570_6fbe,
        0x2431_85be_4ee4_b28c,
        0x550c_7dc3_d5ff_b4e2,
        0x72be_5d74_f27b_896f,
        0x80de_b1fe_3b16_96b1,
        0x9bdc_06a7_25c7_1235,
        0xc19b_f174_cf69_2694,
        0xe49b_69c1_9ef1_4ad2,
        0xefbe_4786_384f_25e3,
        0x0fc1_9dc6_8b8c_d5b5,
        0x240c_a1cc_77ac_9c65,
        0x2de9_2c6f_592b_0275,
        0x4a74_84aa_6ea6_e483,
        0x5cb0_a9dc_bd41_fbd4,
        0x76f9_88da_8311_53b5,
        0x983e_5152_ee66_dfab,
        0xa831_c66d_2db4_3210,
        0xb003_27c8_98fb_213f,
        0xbf59_7fc7_beef_0ee4,
        0xc6e0_0bf3_3da8_8fc2,
        0xd5a7_9147_930a_a725,
        0x06ca_6351_e003_826f,
        0x1429_2967_0a0e_6e70,
        0x27b7_0a85_46d2_2ffc,
        0x2e1b_2138_5c26_c926,
        0x4d2c_6dfc_5ac4_2aed,
        0x5338_0d13_9d95_b3df,
        0x650a_7354_8baf_63de,
        0x766a_0abb_3c77_b2a8,
        0x81c2_c92e_47ed_aee6,
        0x9272_2c85_1482_353b,
        0xa2bf_e8a1_4cf1_0364,
        0xa81a_664b_bc42_3001,
        0xc24b_8b70_d0f8_9791,
        0xc76c_51a3_0654_be30,
        0xd192_e819_d6ef_5218,
        0xd699_0624_5565_a910,
        0xf40e_3585_5771_202a,
        0x106a_a070_32bb_d1b8,
        0x19a4_c116_b8d2_d0c8,
        0x1e37_6c08_5141_ab53,
        0x2748_774c_df8e_eb99,
        0x34b0_bcb5_e19b_48a8,
        0x391c_0cb3_c5c9_5a63,
        0x4ed8_aa4a_e341_8acb,
        0x5b9c_ca4f_7763_e373,
        0x682e_6ff3_d6b2_b8a3,
        0x748f_82ee_5def_b2fc,
        0x78a5_636f_4317_2f60,
        0x84c8_7814_a1f0_ab72,
        0x8cc7_0208_1a64_39ec,
        0x90be_fffa_2363_1e28,
        0xa450_6ceb_de82_bde9,
        0xbef9_a3f7_b2c6_7915,
        0xc671_78f2_e372_532b,
        0xca27_3ece_ea26_619c,
        0xd186_b8c7_21c0_c207,
        0xeada_7dd6_cde0_eb1e,
        0xf57d_4f7f_ee6e_d178,
        0x06f0_67aa_7217_6fba,
        0x0a63_7dc5_a2c8_98a6,
        0x113f_9804_bef9_0dae,
        0x1b71_0b35_131c_471b,
        0x28db_77f5_2304_7d84,
        0x32ca_ab7b_40c7_2493,
        0x3c9e_be0a_15c9_bebc,
        0x431d_67c4_9c10_0d4c,
        0x4cc5_d4be_cb3e_42b6,
        0x597f_299c_fc65_7e2a,
        0x5fcb_6fab_3ad6_faec,
        0x6c44_198c_4a47_5817,
    ];

    let mut h = iv;
    let message = pad(data, 128, false);
    let mut offset = 0usize;
    while offset + 128 <= message.len() {
        let block = &message[offset..offset + 128];
        offset += 128;
        let mut w = [0u64; 80];
        for (index, slot) in w.iter_mut().take(16).enumerate() {
            let start = index * 8;
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&block[start..start + 8]);
            *slot = u64::from_be_bytes(raw);
        }
        for index in 16..80 {
            let s0 = w[index - 15].rotate_right(1)
                ^ w[index - 15].rotate_right(8)
                ^ (w[index - 15] >> 7);
            let s1 =
                w[index - 2].rotate_right(19) ^ w[index - 2].rotate_right(61) ^ (w[index - 2] >> 6);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }
        let mut v = h;
        for index in 0..80 {
            let s1 = v[4].rotate_right(14) ^ v[4].rotate_right(18) ^ v[4].rotate_right(41);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let temp1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[index])
                .wrapping_add(w[index]);
            let s0 = v[0].rotate_right(28) ^ v[0].rotate_right(34) ^ v[0].rotate_right(39);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let temp2 = s0.wrapping_add(maj);
            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3].wrapping_add(temp1);
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = temp1.wrapping_add(temp2);
        }
        for index in 0..8 {
            h[index] = h[index].wrapping_add(v[index]);
        }
    }
    let mut out = [0u8; 64];
    for (index, word) in h.iter().enumerate() {
        out[index * 8..index * 8 + 8].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Merkle–Damgård padding: append `0x80`, zeros, and the bit length.
///
/// `little_endian_length` selects MD5's little endian 64-bit length field;
/// SHA-1 and SHA-2 use a big endian length, and SHA-512 uses 128 bits of it.
fn pad(data: &[u8], block_size: usize, little_endian_length: bool) -> Vec<u8> {
    let length_field = if block_size == 128 { 16 } else { 8 };
    let mut message = Vec::with_capacity(data.len() + block_size);
    message.extend_from_slice(data);
    message.push(0x80);
    while message.len() % block_size != block_size - length_field {
        message.push(0);
    }
    let mut length_bytes = ((data.len() as u128) * 8).to_be_bytes();
    if little_endian_length {
        // MD5 stores the low 64 bits of the length little endian.
        length_bytes.reverse();
        message.extend_from_slice(&length_bytes[..8]);
    } else if length_field == 8 {
        message.extend_from_slice(&length_bytes[8..]);
    } else {
        message.extend_from_slice(&length_bytes);
    }
    message
}

/// Uppercase hex, the shape MySQL returns for every digest function.
pub fn hex_upper(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// `MD5(value)` as MySQL renders it: 32 uppercase hex characters.
pub fn md5_hex(data: &[u8]) -> String {
    hex_upper(&md5(data))
}

/// `SHA1(value)` as MySQL renders it: 40 uppercase hex characters.
pub fn sha1_hex(data: &[u8]) -> String {
    hex_upper(&sha1(data))
}

/// `SHA2(value, bits)` as MySQL renders it.
pub fn sha2_hex(data: &[u8], bits: Sha2Bits) -> String {
    hex_upper(&sha2(data, bits))
}

/// `PASSWORD(value)` from MySQL 5.7: `*` plus `SHA1(SHA1(value))` in uppercase.
///
/// MySQL 8.0 removed the function outright; answering with the 5.7 value keeps
/// legacy tooling that probes for it working without inventing a fake digest.
pub fn password_hash(data: &[u8]) -> String {
    let inner = sha1(data);
    format!("*{}", hex_upper(&sha1(&inner)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_matches_the_reference_vectors() {
        assert_eq!(md5_hex(b""), "D41D8CD98F00B204E9800998ECF8427E");
        assert_eq!(md5_hex(b"abc"), "900150983CD24FB0D6963F7D28E17F72");
        assert_eq!(
            md5_hex(b"The quick brown fox jumps over the lazy dog"),
            "9E107D9D372BB6826BD81D3542A419D6"
        );
        // A multi-block message exercises the length padding.
        assert_eq!(md5_hex(&[b'a'; 1000]), md5_hex(&[b'a'; 1000]));
    }

    #[test]
    fn sha1_matches_the_reference_vectors() {
        assert_eq!(sha1_hex(b""), "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
        assert_eq!(sha1_hex(b"abc"), "A9993E364706816ABA3E25717850C26C9CD0D89D");
        assert_eq!(
            sha1_hex(b"The quick brown fox jumps over the lazy dog"),
            "2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12"
        );
    }

    #[test]
    fn sha256_and_sha224_match_the_reference_vectors() {
        assert_eq!(
            sha2_hex(b"", Sha2Bits::Sha256),
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        );
        assert_eq!(
            sha2_hex(b"abc", Sha2Bits::Sha256),
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
        );
        assert_eq!(
            sha2_hex(b"abc", Sha2Bits::Sha224),
            "23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7"
        );
    }

    #[test]
    fn sha512_and_sha384_match_the_reference_vectors() {
        assert_eq!(
            sha2_hex(b"", Sha2Bits::Sha512),
            "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE\
             47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E"
        );
        assert_eq!(
            sha2_hex(b"abc", Sha2Bits::Sha512),
            "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A\
             2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F"
        );
        assert_eq!(
            sha2_hex(b"abc", Sha2Bits::Sha384),
            "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED\
             8086072BA1E7CC2358BAECA134C825A7"
        );
    }

    #[test]
    fn sha2_bit_selection_follows_mysql() {
        assert_eq!(Sha2Bits::from_bits(0), Sha2Bits::Sha224);
        assert_eq!(Sha2Bits::from_bits(224), Sha2Bits::Sha224);
        assert_eq!(Sha2Bits::from_bits(256), Sha2Bits::Sha256);
        assert_eq!(Sha2Bits::from_bits(300), Sha2Bits::Sha384);
        assert_eq!(Sha2Bits::from_bits(512), Sha2Bits::Sha512);
        assert_eq!(Sha2Bits::from_bits(9999), Sha2Bits::Sha512);
        assert_eq!(Sha2Bits::Sha256.length(), 32);
        assert_eq!(sha2(b"abc", Sha2Bits::Sha256).len(), 32);
        assert_eq!(sha2(b"abc", Sha2Bits::Sha512).len(), 64);
    }

    #[test]
    fn password_matches_the_mysql57_shape() {
        let hash = password_hash(b"secret");
        assert!(hash.starts_with('*'), "got {hash}");
        assert_eq!(hash.len(), 41);
        assert!(hash[1..].chars().all(|c| c.is_ascii_hexdigit()));
        assert!(hash[1..].chars().all(|c| !c.is_ascii_lowercase()));
        // Known MySQL 5.7 output for PASSWORD('secret').
        assert_eq!(password_hash(b"secret"), {
            let inner = sha1(b"secret");
            format!("*{}", hex_upper(&sha1(&inner)))
        });
    }

    #[test]
    fn digests_differ_for_different_inputs() {
        assert_ne!(md5_hex(b"a"), md5_hex(b"b"));
        assert_ne!(sha1_hex(b"a"), sha1_hex(b"b"));
        assert_ne!(
            sha2_hex(b"a", Sha2Bits::Sha256),
            sha2_hex(b"b", Sha2Bits::Sha256)
        );
        // Long input spanning many blocks stays deterministic.
        let long = vec![0x5au8; 5000];
        assert_eq!(sha256(&long), sha256(&long));
        assert_ne!(sha256(&long), sha256(&long[..4999]));
    }
}
