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
 
#include <coin/block.hpp>
#include <coin/block_index.hpp>
#include <coin/constants.hpp>
#include <coin/stack_impl.hpp>

using namespace coin;

block_index::block_index()
    : m_hash_block()
    , m_block_index_previous(0)
    , m_block_index_next(0)
    , m_file(0)
    , m_block_position(0)
    , m_chain_trust(0)
    , m_height(0)
    , m_mint(0)
    , m_money_supply(0)
    , m_flags(0)
    , m_version(0)
    , m_hash_merkle_root()
    , m_time(0)
    , m_bits(0)
    , m_nonce(0)
{
    // ...
}

block_index::block_index(
    const std::uint32_t & file, const std::uint32_t & block_position,
    block & blk
    )
    : m_hash_block()
    , m_block_index_previous(0)
    , m_block_index_next(0)
    , m_file(file)
    , m_block_position(block_position)
    , m_chain_trust(0)
    , m_height(0)
    , m_mint(0)
    , m_money_supply(0)
    , m_flags(0)
    , m_version(blk.header().version)
    , m_hash_merkle_root(blk.header().hash_merkle_root)
    , m_time(blk.header().timestamp)
    , m_bits(blk.header().bits)
    , m_nonce(blk.header().nonce)
{
    // ...
}

void block_index::set_hash_block(const sha256 & val)
{
    m_hash_block = val;
}

sha256 block_index::get_block_hash() const
{
    return m_hash_block;
}

block block_index::get_block_header() const
{
    block ret;
    
    ret.m_header.version = m_version;
    
    if (m_block_index_previous)
    {
        ret.m_header.hash_previous_block =
            m_block_index_previous->get_block_hash()
        ;
    }
    
    ret.m_header.hash_merkle_root = m_hash_merkle_root;
    ret.m_header.timestamp = static_cast<std::uint32_t> (m_time);
    ret.m_header.bits = m_bits;
    ret.m_header.nonce = m_nonce;
    
    return ret;
}

void block_index::set_block_index_previous(block_index * val)
{
    m_block_index_previous = val;
}

void block_index::set_block_index_next(block_index * val)
{
    m_block_index_next = val;
}

block_index * block_index::block_index_previous()
{
    return m_block_index_previous;
}

const block_index * block_index::block_index_previous() const
{
    return m_block_index_previous;
}

block_index * block_index::block_index_next()
{
    return m_block_index_next;
}

const block_index * block_index::block_index_next() const
{
    return m_block_index_next;
}

const std::uint32_t & block_index::file() const
{
    return m_file;
}

const std::uint32_t & block_index::block_position() const
{
    return m_block_position;
}

void block_index::set_chain_trust(const big_number & val)
{
    m_chain_trust = val;
}

const big_number & block_index::chain_trust() const
{
    return m_chain_trust;
}

void block_index::set_height(const std::int32_t & val)
{
    m_height = val;
}

const std::int32_t & block_index::height() const
{
    return m_height;
}

void block_index::set_mint(const std::int64_t & value)
{
    m_mint = value;
}

const std::int64_t & block_index::mint() const
{
    return m_mint;
}

void block_index::set_money_supply(const std::int64_t & value)
{
    m_money_supply = value;
}

const std::int64_t & block_index::money_supply() const
{
    return m_money_supply;
}

const std::uint32_t & block_index::flags() const
{
    return m_flags;
}

const std::int32_t & block_index::version() const
{
    return m_version;
}

const sha256 & block_index::hash_merkle_root() const
{
    return m_hash_merkle_root;
}

const std::int64_t & block_index::time() const
{
    return m_time;
}

const std::uint32_t & block_index::bits() const
{
    return m_bits;
}

const std::uint32_t & block_index::nonce() const
{
    return m_nonce;
}

big_number block_index::get_block_trust()
{
    big_number target;
    
    target.set_compact(m_bits);
    
    if (target <= 0)
    {
        return 0;
    }
    
    /**
     * Calculate the work amount for the block.
     */
    big_number pow_trust = constants::proof_of_work_limit / (target + 1);
    
    return pow_trust > 1 ? pow_trust : 1;
}

std::int64_t block_index::get_median_time_past()
{
    std::int64_t median[median_time_span];
    std::int64_t * begin = &median[median_time_span];
    std::int64_t * end = &median[median_time_span];

    auto index = this;
    
    for (
        auto i = 0; i < median_time_span && index; i++,
        index = index->block_index_previous()
        )
    {
        *(--begin) = index->time();
    }
    
    std::sort(begin, end);
    
    return begin[(end - begin) / 2];
}

std::int64_t block_index::get_median_time()
{
    auto index = this;
    
    for (auto i = 0; i < median_time_span / 2; i++)
    {
        if (index->block_index_next() == 0)
        {
            return m_time;
        }
        
        index = index->block_index_next();
    }
    
    return index->get_median_time_past();
}

bool block_index::is_proof_of_work() const
{
    return true;
}

bool block_index::is_in_main_chain() const
{
    return
        m_block_index_next || this == stack_impl::get_block_index_best()
    ;
}

const block_index * block_index::get_ancestor(
    const std::int32_t & height
    ) const
{
    if (height > m_height || height < 0)
    {
        return nullptr;
    }
    
    const block_index * ret = this;

    std::int32_t i = height;
    
    while (i++ < m_height && ret)
    {
        ret = ret->block_index_previous();
    }
    
    return ret;
}
