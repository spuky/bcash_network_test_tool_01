/*
 * Copyright (c) 2012-2018 bitPico
 *
 * This file is part of libCoin.
 *
 * libCoin is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License with
 * additional permissions to the one published by the Free Software
 * Foundation, either version 3 of the License, or (at your option)
 * any later version. For more information see LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <coin/big_number.hpp>
#include <coin/data_buffer.hpp>
#include <coin/globals.hpp>
#include <coin/hash.hpp>
#include <coin/key_reserved.hpp>
#include <coin/logger.hpp>
#include <coin/mining.hpp>
#include <coin/sha256.hpp>

using namespace coin;

std::int32_t mining::format_hash_blocks(
    void * buf, const std::uint32_t & len
    )
{
    std::uint8_t * pdata = (std::uint8_t *)buf;
    
    std::uint32_t blocks = 1 + ((len + 8) / 64);
    
    std::uint8_t * pend = pdata + 64 * blocks;
    
    std::memset(pdata + len, 0, 64 * blocks - len);
    
    pdata[len] = 0x80;
    
    std::uint32_t bits = len * 8;
    
    pend[-1] = (bits >> 0) & 0xff, pend[-2] = (bits >> 8) & 0xff;
    pend[-3] = (bits >> 16) & 0xff, pend[-4] = (bits >> 24) & 0xff;
    
    return blocks;
}

void mining::sha256_transform(
    void * ptr_state, void * ptr_input, const void * ptr_init)
{
    SHA256_CTX ctx;
    
    std::uint8_t data[64];

    SHA256_Init(&ctx);

    for (auto i = 0; i < 16; i++)
    {
        ((std::uint32_t *)data)[i] = utility::byte_reverse(
            ((std::uint32_t *)ptr_input)[i]
        );
    }
    
    for (auto i = 0; i < 8; i++)
    {
        ctx.h[i] = ((std::uint32_t *)ptr_init)[i];
    }
    
    SHA256_Update(&ctx, data, sizeof(data));
    
    for (auto i = 0; i < 8; i++)
    {
        ((std::uint32_t *)ptr_state)[i] = ctx.h[i];
    }
}

void mining::format_hash_buffers(
    const block::header_t & hdr, char * ptr_midstate,
    char * data_out, char * ptr_hash1
    )
{
    static const unsigned int g_sha256_init_state[8] =
    {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f,
        0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    struct
    {
        struct
        {
            std::uint32_t version;
            sha256 hash_previous_block;
            sha256 hash_merkle_root;
            std::uint32_t timestamp;
            std::uint32_t bits;
            std::uint32_t nonce;
        } block_header;
        
        std::uint8_t padding_0[64];
        sha256 hash1;
        std::uint8_t padding_1[64];
    } tmp;
    
    std::memset(&tmp, 0, sizeof(tmp));

    tmp.block_header.version = hdr.version;
    tmp.block_header.hash_previous_block =
        hdr.hash_previous_block
    ;
    tmp.block_header.hash_merkle_root = hdr.hash_merkle_root;
    tmp.block_header.timestamp = hdr.timestamp;
    tmp.block_header.bits = hdr.bits;
    tmp.block_header.nonce = hdr.nonce;

    format_hash_blocks(&tmp.block_header, block::header_length);
    format_hash_blocks(&tmp.hash1, sha256::digest_length);

    for (std::uint32_t i = 0; i < sizeof(tmp) / 4; i++)
    {
        ((std::uint32_t *)&tmp)[i] =
            utility::byte_reverse(((std::uint32_t *)&tmp)[i])
        ;
    }

    sha256_transform(ptr_midstate, &tmp.block_header, g_sha256_init_state);

    std::memcpy(data_out, &tmp.block_header, 128);
    
    std::memcpy(ptr_hash1, &tmp.hash1, 64);
}

std::uint32_t mining::scan_hash_blake256_8_round(
    block::header_t * in_header, std::uint32_t max_nonce,
    std::uint32_t & out_hashes, std::uint8_t * out_digest,
    block::header_t * out_header
    )
{
    block::header_t data = *in_header;

    while (globals::instance().state() == globals::state_started)
    {
        if (++data.nonce < max_nonce)
        {
            data_buffer buffer;
            
            buffer.write_uint32(data.version);
            buffer.write_sha256(data.hash_previous_block);
            buffer.write_sha256(data.hash_merkle_root);
            buffer.write_uint32(data.timestamp);
            buffer.write_uint32(data.bits);
            buffer.write_uint32(data.nonce);

            assert(buffer.size() == block::header_length);
            
            auto digest = hash::blake256_8_round(
                reinterpret_cast<std::uint8_t *> (buffer.data()), buffer.size()
            );
            
            out_hashes++;
            
            auto hash_target = big_number().set_compact(
                data.bits
            ).get_sha256();
            
    		if (sha256::from_digest(&digest[0]) <= hash_target)
      		{
            	std::memcpy(out_digest, &digest[0], sha256::digest_length);

            	std::memcpy(out_header, &data, block::header_length);
            
        		return data.nonce;
            }
        }
        
        if (data.nonce >= max_nonce)
        {
            return static_cast<std::uint32_t> (-1);
        }
    }

    return static_cast<std::uint32_t> (-1);
}

std::uint32_t mining::scan_hash_sha256d(
    block::header_t * in_header, std::uint32_t max_nonce,
    std::uint32_t & out_hashes, std::uint8_t * out_digest,
    block::header_t * out_header
    )
{
    block::header_t data = *in_header;
    auto hash_target = big_number().set_compact(data.bits).get_sha256();
    
#if 0 /* If you want to perform midstate calculation. */
    /**
     * Create the hash buffers.
     */
    char midstate_buf[32 + 16];
    char * midstate = utility::alignup<16> (midstate_buf);
    char data_buf[128 + 16];
    char * data_out = utility::alignup<16> (data_buf);
    char hash1_buf[64 + 16];
    char * hash1 = utility::alignup<16> (hash1_buf);

    mining::format_hash_buffers(data, midstate, data_out, hash1);
#endif
    while (globals::instance().state() == globals::state_started)
    {
        if (++data.nonce < max_nonce)
        {
            auto digest = hash::sha256d(
                reinterpret_cast<std::uint8_t *> (&data), block::header_length
            );
            
            out_hashes++;

            if (sha256::from_digest(&digest[0]) <= hash_target)
			{
                std::memcpy(out_digest, &digest[0], sha256::digest_length);

                std::memcpy(out_header, &data, block::header_length);
            
                return data.nonce;
            }
        }
        
        if (data.nonce >= max_nonce)
        {
            return static_cast<std::uint32_t> (-1);
        }
    }

    return static_cast<std::uint32_t> (-1);
}
