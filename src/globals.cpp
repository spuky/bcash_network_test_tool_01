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

#include <cassert>
#include <mutex>

#include <coin/block_merkle.hpp>
#include <coin/globals.hpp>
#include <coin/logger.hpp>
#include <coin/script.hpp>
#include <coin/secret.hpp>
#include <coin/transaction.hpp>
#include <coin/wallet.hpp>

using namespace coin;

globals::globals()
    : m_strand(m_io_service)
    , m_state(state_none)
#if (defined __ANDROID__ || defined __IPHONE_OS_VERSION_MAX_ALLOWED)
    , m_operation_mode(protocol::operation_mode_client)
#else
    , m_operation_mode(protocol::operation_mode_peer)
#endif // __IPHONE_OS_VERSION_MAX_ALLOWED
    , m_debug(true)
    , m_is_client_spv(false)
    , m_version_nonce(0)
    , m_best_block_height(-1)
    , m_block_index_fbbh_last(0)
    , m_time_best_received(0)
    , m_transactions_updated(0)
    , m_peer_block_counts(5, 0)
    , m_transaction_fee(constants::default_tx_fee)
    , m_option_rescan(false)
    , m_last_block_transactions(0)
    , m_last_block_size(0)
    , m_money_supply(0)
    , m_coinbase_flags(new script())
    , m_spv_active_tcp_connection_identifier(0)
    , m_spv_best_block_height(-1)
    , m_spv_use_getblocks(false)
    , m_peer_headers_first_active_tcp_connection_identifier(0)
    , m_peer_use_headers_first_chain_sync(true)
    , m_spv_time_wallet_created(std::time(0))
    , m_spv_average_false_positive_rate(spv_false_positive_rate())
    , m_db_private(false)
{
    /**
     * P2SH (BIP16 support) can be removed eventually.
     */
    auto p2sh = "/P2SH/";

    *m_coinbase_flags << std::vector<std::uint8_t>(p2sh, p2sh + strlen(p2sh));
    
    /**
     * Insert the genesis block into the peer_headers_first_heights_and_hashes.
     */
    m_peer_headers_first_heights_and_hashes[0] =
        (constants::test_net ?
        block::get_hash_genesis_test_net() : block::get_hash_genesis()
    );
}

globals & globals::instance()
{
    static globals g_globals;

    return g_globals;
}

void globals::set_operation_mode(const protocol::operation_mode_t & val)
{
    m_operation_mode = val;
}

protocol::operation_mode_t & globals::operation_mode()
{
    return m_operation_mode;
}

script & globals::coinbase_flags()
{
	std::lock_guard<std::recursive_mutex> l1(recursive_mutex_);
	
    return *m_coinbase_flags;
}

void globals::set_spv_active_tcp_connection_identifier(
    const std::uint32_t & val
    )
{
    m_spv_active_tcp_connection_identifier = val;
}

const std::uint32_t & globals::spv_active_tcp_connection_identifier() const
{
    return m_spv_active_tcp_connection_identifier;
}

std::map<sha256, std::unique_ptr<block_merkle> > & globals::spv_block_merkles()
{
	std::lock_guard<std::recursive_mutex> l1(recursive_mutex_);
	
    return m_spv_block_merkles;
}

void globals::set_spv_block_last(const block_merkle & val)
{
	std::lock_guard<std::recursive_mutex> l1(recursive_mutex_);
	
    m_spv_block_last.reset(new block_merkle(val));
}

void globals::set_spv_block_last(const std::unique_ptr<block_merkle> & val)
{
	std::lock_guard<std::recursive_mutex> l1(recursive_mutex_);
	
    if (val)
    {
        m_spv_block_last.reset(new block_merkle(*val));
    }
    else
    {
        m_spv_block_last.reset();
    }
}

const std::unique_ptr<block_merkle> & globals::spv_block_last() const
{
	std::lock_guard<std::recursive_mutex> l1(recursive_mutex_);
	
    if (
        m_spv_block_last &&
        m_spv_block_last->height() > m_spv_best_block_height
        )
    {
        m_spv_best_block_height = m_spv_block_last->height();
    }
    
    return m_spv_block_last;
}

std::map<sha256, std::unique_ptr<block_merkle> > &
    globals::spv_block_merkle_orphans()
{
	std::lock_guard<std::recursive_mutex> l1(recursive_mutex_);
	
    return m_spv_block_merkle_orphans;
}

void globals::set_spv_block_orphan_last(const block_merkle & val)
{
	std::lock_guard<std::recursive_mutex> l1(recursive_mutex_);
	
    m_spv_block_orphan_last.reset(new block_merkle(val));
}

const std::unique_ptr<block_merkle> & globals::spv_block_orphan_last() const
{
	std::lock_guard<std::recursive_mutex> l1(recursive_mutex_);
	
    return m_spv_block_orphan_last;
}

void globals::set_spv_best_block_height(const std::int32_t & value)
{
    m_spv_best_block_height = value;
}

const std::int32_t & globals::spv_best_block_height() const
{
    return m_spv_best_block_height;
}

const std::unique_ptr<transaction_bloom_filter> &
    globals::spv_transaction_bloom_filter() const
{
	std::lock_guard<std::recursive_mutex> l1(recursive_mutex_);
	
    return m_spv_transaction_bloom_filter;
}

std::vector<sha256> globals::spv_block_locator_hashes()
{
    std::vector<sha256> ret;

    std::int32_t step = 1, start = 0;
    
    const auto * block_last = globals::instance().spv_block_last().get();

    while (block_last && block_last->height() > 0)
    {
        ret.push_back(block_last->get_hash());

        if (++start >= 10)
        {
            step *= 2;
        }
        
        /**
         * Exponentially larger steps back.
         */
        for (auto i = 0; block_last && i < step; i++)
        {
            if (
                m_spv_block_merkles.count(
                block_last->block_header().hash_previous_block) > 0
                )
             {
                block_last =
                    m_spv_block_merkles[block_last->block_header(
                    ).hash_previous_block].get()
                ;
            }
            else
            {
                block_last = nullptr;
            }
        }
    }

    ret.push_back(
        (constants::test_net ?
        block::get_hash_genesis_test_net() : block::get_hash_genesis())
    );

    return ret;
}

void globals::set_spv_use_getblocks(const bool & val)
{
    m_spv_use_getblocks = val;
}

const bool & globals::spv_use_getblocks() const
{
    return m_spv_use_getblocks;
}

void globals::set_peer_headers_first_active_tcp_connection_identifier(
    const std::uint32_t & val
	)
{
	m_peer_headers_first_active_tcp_connection_identifier = val;
}

const std::uint32_t &
	globals::peer_headers_first_active_tcp_connection_identifier() const
{
	return m_peer_headers_first_active_tcp_connection_identifier;
}

std::map<sha256, std::unique_ptr<block> > &
	globals::peer_headers_first_blocks()
{
	std::lock_guard<std::recursive_mutex> l1(recursive_mutex_);
	
	return m_peer_headers_first_blocks;
}

std::map<std::uint32_t, sha256> &
	globals::peer_headers_first_heights_and_hashes()
{
	std::lock_guard<std::recursive_mutex> l1(recursive_mutex_);
	
	return m_peer_headers_first_heights_and_hashes;
}

void globals::set_peer_headers_first_block_last(const block & val)
{
	std::lock_guard<std::recursive_mutex> l1(recursive_mutex_);
	
    m_peer_headers_first_block_last.reset(new block(val));
}

void globals::set_peer_headers_first_block_last(
	const std::unique_ptr<block> & val
	)
{
	std::lock_guard<std::recursive_mutex> l1(recursive_mutex_);
	
    if (val)
    {
        m_peer_headers_first_block_last.reset(new block(*val));
    }
    else
    {
        m_peer_headers_first_block_last.reset();
    }
}

const std::unique_ptr<block> & globals::peer_headers_first_block_last() const
{
	std::lock_guard<std::recursive_mutex> l1(recursive_mutex_);
	
	return m_peer_headers_first_block_last;
}

std::vector<sha256> globals::peer_headers_first_block_locator_hashes()
{
    std::vector<sha256> ret;

    std::int32_t step = 1, start = 0;
    
    const auto * block_last =
    	globals::instance().peer_headers_first_block_last().get()
    ;

    while (block_last && block_last->peer_headers_first_sync_height() > 0)
    {
		ret.push_back(block_last->get_hash());

        if (++start >= 10)
        {
            step *= 2;
        }
        
        /**
         * Exponentially larger steps back.
         */
        for (auto i = 0; block_last && i < step; i++)
        {
        	if (
            	m_peer_headers_first_blocks.count(
                block_last->header().hash_previous_block) > 0
            	)
         	{
                block_last =
                    m_peer_headers_first_blocks[block_last->header(
                    ).hash_previous_block].get()
                ;
            }
            else
            {
            	block_last = nullptr;
            }
        }
    }

    ret.push_back(
        (constants::test_net ?
        block::get_hash_genesis_test_net() : block::get_hash_genesis())
    );

    return ret;
}

void globals::set_peer_use_headers_first_chain_sync(const bool & val)
{
    m_peer_use_headers_first_chain_sync = val;
}

const bool & globals::peer_use_headers_first_chain_sync() const
{
    return m_peer_use_headers_first_chain_sync;
}

void globals::set_spv_time_wallet_created(const std::time_t & val)
{
    m_spv_time_wallet_created = val;
}

const std::time_t globals::spv_time_wallet_created() const
{
    /**
     * Return t - one day.
     */
    return m_spv_time_wallet_created - 1 * 24 * 60 * 60;
}

std::map<sha256, std::vector<transaction> > &
    globals::spv_block_merkle_orphan_transactions()
{
	std::lock_guard<std::recursive_mutex> l1(recursive_mutex_);
	
    return m_spv_block_merkle_orphan_transactions;
}

void globals::set_db_private(const bool & val)
{
    m_db_private = val;
}

const bool & globals::db_private() const
{
    return m_db_private;
}

void globals::spv_reset_bloom_filter()
{
    /**
     * Reset the (average) false positive rate.
     */
    m_spv_average_false_positive_rate = spv_false_positive_rate();
    
    /**
     * The number of elements (keys or point_out's).
     */
    std::uint32_t elements = 0;
    
    /**
     * A random value to add to the seed value in the hash function used by
     * the bloom filter.
     */
    auto tweak = static_cast<std::uint32_t> (std::rand());
    
    if (m_wallet_main)
    {
        std::set<point_out> utxos;
        
        /**
         * UTXO's
         */
        auto wallet_transactions = m_wallet_main->transactions();
        
        for (auto & i : wallet_transactions)
        {
#if 1
            /**
             * Get all.
             */
            auto index = 0;
            
            for (auto & j : i.second.transactions_in())
            {
                if (index < i.second.transactions_out().size())
                {
                    auto hash = j.previous_out().get_hash();
                    
                    utxos.insert(j.previous_out());
                    
                    log_info(
                        "Reset bloom filter for (" <<
                        (i.second.is_spent(index) ? "spent" : "unspent") <<
                        ") point_out " << hash.to_string() << "."
                    );
                }
                
                index++;
            }
#else
            /**
             * Get unspent.
             */
            for (auto n = 0; n < i.second.transactions_in().size(); n++)
            {
                if (
                    n < i.second.transactions_out().size() &&
                    i.second.is_spent(n) == false
                    )
                {
                    auto hash =
                        i.second.transactions_in()[n].previous_out().get_hash()
                    ;
                    
                    log_info(
                        "Reset bloom filter for (UTXO) point_out " <<
                        hash.to_string() << "."
                    );
                    
                    utxos.insert(i.second.transactions_in()[n].previous_out());
                }
            }
#endif
            /**
             * Limit to 5,000 items.
             */
            if (utxos.size() >= 5000)
            {
                log_info(
                    "Globals, reset bloom filter discovered more than "
                    "5000 elements, breaking."
                );
                
                break;
            }
        }
        
        if (m_wallet_main->is_crypted() == true)
        {
            elements += m_wallet_main->crypted_keys().size();
        }
        else
        {
            elements += m_wallet_main->keys().size();
        }
        
        elements += utxos.size();
        
        /**
         * Allocate the (SPV) transaction_bloom_filter.
         */
        m_spv_transaction_bloom_filter.reset(
            new transaction_bloom_filter(elements < 200 ? 300 : elements + 100,
            spv_false_positive_rate(), tweak,
            transaction_bloom_filter::update_all)
        );
        
        for (auto & i : utxos)
        {
            m_spv_transaction_bloom_filter->insert(i);
        }
        
        if (m_wallet_main->is_crypted() == true)
        {
            /**
             * Iterate all keys.
             */
            for (auto & i : m_wallet_main->crypted_keys())
            {
                auto pub_key = i.second.first;

                auto hash = pub_key.get_id();
                
                m_spv_transaction_bloom_filter->insert(
                    std::vector<std::uint8_t> (&hash.digest()[0],
                    &hash.digest()[0] + ripemd160::digest_length)
                );
                
                log_info(
                    "Reset bloom filter for (crypted) address " <<
                    address(hash).to_string() << "."
                );
            }
        }
        else
        {
            /**
             * Iterate all keys.
             */
            for (auto & i : m_wallet_main->keys())
            {
                const auto & key_id = i.first;
                
                key k;
                
                if (m_wallet_main->get_key(key_id, k) == true)
                {
                    auto compressed = false;
                    
                    auto s = k.get_secret(compressed);
                    
                    if (m_wallet_main->address_book().count(key_id) > 0)
                    {
                        k.set_secret(s, compressed);
                        
                        auto pub_key = k.get_public_key();

                        auto hash = pub_key.get_id();
                        
                        m_spv_transaction_bloom_filter->insert(
                            std::vector<std::uint8_t> (&hash.digest()[0],
                            &hash.digest()[0] + ripemd160::digest_length)
                        );
                        
                        log_info(
                            "Reset bloom filter for address " <<
                            address(key_id).to_string() << "."
                        );
                    }
                    else
                    {
                        k.set_secret(s, compressed);
                        
                        auto pub_key = k.get_public_key();

                        auto hash = pub_key.get_id();
                        
                        m_spv_transaction_bloom_filter->insert(
                            std::vector<std::uint8_t> (&hash.digest()[0],
                            &hash.digest()[0] + ripemd160::digest_length)
                        );
                        
                        log_info(
                            "Reset bloom filter for address " <<
                            address(key_id).to_string() << "."
                        );
                    }
                }
            }
        }
    }
}

const double globals::spv_false_positive_rate() const
{
    return 0.00005;
}

void globals::set_spv_average_false_positive_rate(const double & val)
{
    m_spv_average_false_positive_rate = val;
}

const double & globals::spv_average_false_positive_rate() const
{
    return m_spv_average_false_positive_rate;
}
