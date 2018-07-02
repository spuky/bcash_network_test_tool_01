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

#include <coin/transaction_merkle.hpp>

using namespace coin;

transaction_merkle::transaction_merkle()
    : transaction()
    , m_index(-1)
    , m_spv_block_height(0)
{
    // ...
}

transaction_merkle::transaction_merkle(const transaction & tx)
    : transaction(tx)
    , m_index(-1)
    , m_spv_block_height(0)
{
    // ...
}

void transaction_merkle::encode()
{
    encode(*this);
}

void transaction_merkle::encode(data_buffer & buffer)
{
    transaction::encode(buffer, true, true);

    buffer.write_sha256(m_block_hash);

    buffer.write_var_int(m_merkle_branch.size());
    
    for (auto & i : m_merkle_branch)
    {
        buffer.write_sha256(i);
    }

    buffer.write_int32(m_index);
}

void transaction_merkle::decode()
{
    decode(*this);
}

void transaction_merkle::decode(data_buffer & buffer)
{
    transaction::decode(buffer, true);

    m_block_hash = buffer.read_sha256();

    auto len = buffer.read_var_int();

    for (auto i = 0; i < len; i++)
    {
        m_merkle_branch.push_back(buffer.read_sha256());
    }
    
    m_index = buffer.read_int32();
}

std::pair<bool, std::string> transaction_merkle::accept_to_memory_pool()
{
    if (globals::instance().is_client_spv() == true)
    {
        if (is_in_main_chain() == false && client_connect_inputs() == false)
        {
            return std::make_pair(false, "client unknown");
        }
        
        return transaction::accept_to_transaction_pool_2();
    }
    else
    {
        return transaction::accept_to_transaction_pool_2();
    }
    
    return std::make_pair(false, "unknown");
}

void transaction_merkle::set_spv_block_height(const std::int32_t & val)
{
    m_spv_block_height = val;
}

const std::int32_t & transaction_merkle::spv_block_height() const
{
    return m_spv_block_height;
}
