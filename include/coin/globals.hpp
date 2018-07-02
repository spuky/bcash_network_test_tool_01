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

#ifndef COIN_GLOBALS_HPP
#define COIN_GLOBALS_HPP

#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <set>
#include <vector>

#include <boost/asio.hpp>

#include <coin/block_index.hpp>
#include <coin/constants.hpp>
#include <coin/inventory_vector.hpp>
#include <coin/median_filter.hpp>
#include <coin/point_out.hpp>
#include <coin/protocol.hpp>
#include <coin/sha256.hpp>

namespace coin {

    class block;
    class block_merkle;
    class data_buffer;
    class script;
    class transaction;
    class transaction_bloom_filter;
    class wallet;
    
    /**
     * Implements a settable global variables. It is ok for this to be a
     * singleton even in the presence of multiple instances in the same
     * memory space.
     */
    class globals
    {
        public:

            /**
             * The (application) states.
             */
            typedef enum
            {
                state_none,
                state_starting,
                state_started,
                state_stopping,
                state_stopped
            } state_t;
        
            /**
             * Constructor
             */
            globals();
        
            /**
             * The singleton accessor.
             */
            static globals & instance();
        
            /**
             * The boost::asio::io_service.
             */
            boost::asio::io_service & io_service()
            {
                return m_io_service;
            }
        
            /**
             * The boost::asio::strand.
             */
            boost::asio::strand & strand()
            {
                return m_strand;
            }
        
            /**
             * Sets the state.
             * @param val The state_t.
             */
            void set_state(const state_t & val)
            {
                m_state = val;
            }
        
            /**
             * The state.
             */
            const state_t & state() const
            {
                return m_state;
            }
        
            /**
             * If true we are in debug mode.
             */
            const bool & debug() const
            {
                return m_debug;
            }
        
            /**
             * Set's the operation mode.
             * @param val The value.
             */
            void set_operation_mode(const protocol::operation_mode_t & val);
        
            /**
             * The protocol::operation_mode_t.
             */
            protocol::operation_mode_t & operation_mode();
        
            /**
             * Set if we are a (SPV) client.
             */
            void set_client_spv(const bool & val)
            {
                assert(m_operation_mode == protocol::operation_mode_client);
                
                m_is_client_spv = val;
            }
        
            /**
             * If true we are a (SPV) client.
             */
            const bool & is_client_spv() const
            {                
                return m_is_client_spv;
            }
        
            /**
             * Sets the version nonce.
             */
            void set_version_nonce(const std::uint64_t & val)
            {
                assert(val != 0);
                
                m_version_nonce = val;
            }
        
            /**
             * The version nonce (used to detect connections to ourselves).
             */
            const std::uint64_t & version_nonce() const
            {
                assert(m_version_nonce != 0);
                
                return m_version_nonce;
            }
        
            /**
             * Sets the best block height.
             * @param value The value.
             */
            void set_best_block_height(const std::int32_t & value)
            {
                m_best_block_height = value;
            }
        
            /**
             * The best block height.
             */
            const std::int32_t & best_block_height() const
            {
                return m_best_block_height;
            }
        
            /**
             * The block indexes.
             */
            std::map<sha256, block_index *> & block_indexes()
            {
            	std::lock_guard<std::recursive_mutex> l1(recursive_mutex_);
                
                return m_block_indexes;
            }
        
            /**
             * Sets the hash of the best chain.
             */
            void set_hash_best_chain(const sha256 & value)
            {
            	std::lock_guard<std::recursive_mutex> l1(recursive_mutex_);
                
                m_hash_best_chain = value;
            }
        
            /**
             * The hash of the best chain.
             */
            sha256 & hash_best_chain()
            {
            	std::lock_guard<std::recursive_mutex> l1(recursive_mutex_);
                
                return m_hash_best_chain;
            }
        
            /**
             * Sets the block index fbbh last.
             * @param val The block_index.
             */
            void set_block_index_fbbh_last(block_index * val)
            {
            	std::lock_guard<std::recursive_mutex> l1(recursive_mutex_);
                
                m_block_index_fbbh_last = val;
            }
        
            /**
             * The block index used by find_block_by_height.
             */
            const block_index * block_index_fbbh_last() const
            {
            	std::lock_guard<std::recursive_mutex> l1(recursive_mutex_);
                
                return m_block_index_fbbh_last;
            }
        
            /**
             * Sets the time best received.
             */
            void set_time_best_received(const std::int64_t & value)
            {
                m_time_best_received = value;
            }
        
            /**
             * The time of the best received block.
             */
            const std::int64_t & time_best_received() const
            {
                return m_time_best_received;
            }
        
            /**
             * Sets the number of transactions that have been updated.
             * @pram value The value.
             *
             */
            void set_transactions_updated(const std::int32_t & value)
            {
                m_transactions_updated = value;
            }
        
            /**
             * The number of transactions that have been updated.
             */
            const std::uint32_t & transactions_updated() const
            {
                return m_transactions_updated;
            }
        
            /**
             * Sets the main wallet.
             * @param val The wallet.
             */
            void set_wallet_main(const std::shared_ptr<wallet> & val)
            {
            	std::lock_guard<std::recursive_mutex> l1(recursive_mutex_);
                
                m_wallet_main = val;
            }
        
            /**
             * The (main) wallet.
             */
            const std::shared_ptr<wallet> & wallet_main() const
            {
            	std::lock_guard<std::recursive_mutex> l1(recursive_mutex_);
                
                return m_wallet_main;
            }
        
            /**
             * The orphan blocks.
             */
            std::map<sha256, std::shared_ptr<block> > & orphan_blocks()
            {
            	std::lock_guard<std::recursive_mutex> l1(recursive_mutex_);
                
                return m_orphan_blocks;
            }
        
            /**
             * The orphan blocks by previous.
             */
            std::multimap<
                sha256, std::shared_ptr<block>
            > & orphan_blocks_by_previous()
            {
            	std::lock_guard<std::recursive_mutex> l1(recursive_mutex_);
                
                return m_orphan_blocks_by_previous;
            }

            /**
             * The orphan transactions.
             */
            std::map<
                sha256, std::shared_ptr<data_buffer>
            > & orphan_transactions()
            {
            	std::lock_guard<std::recursive_mutex> l1(recursive_mutex_);
                
                return m_orphan_transactions;
            }
        
            /**
             * The orphan transactions by previous.
             */
            std::map<
                sha256, std::map<sha256, std::shared_ptr<data_buffer> >
            > & orphan_transactions_by_previous()
            {
            	std::lock_guard<std::recursive_mutex> l1(recursive_mutex_);
                
                return m_orphan_transactions_by_previous;
            }
        
            /**
             * The number of blocks other peers claim to have.
             */
            median_filter<std::uint32_t> & peer_block_counts()
            {
            	std::lock_guard<std::recursive_mutex> l1(recursive_mutex_);
                
                return m_peer_block_counts;
            }
        
            /**
             * The relay inventory_vector's.
             */
            std::map<inventory_vector, data_buffer> & relay_invs()
            {
            	std::lock_guard<std::recursive_mutex> l1(recursive_mutex_);
                
                return m_relay_invs;
            }
        
            /**
             * The relay inventory_vector expirations.
             */
            std::deque<
                std::pair<std::int64_t, inventory_vector>
                > & relay_inv_expirations()
            {
            	std::lock_guard<std::recursive_mutex> l1(recursive_mutex_);
                
                return m_relay_inv_expirations;
            }
        
            /**
             * Sets the transaction feed.
             * @param val The value.
             */
            void set_transaction_fee(const std::int64_t & val)
            {
                m_transaction_fee = val;
            }
        
            /**
             * The transaction fee.
             */
            const std::int64_t & transaction_fee() const
            {
                return m_transaction_fee;
            }
        
            /**
             * Sets the option to rescan.
             * @param val The value.
             */
            void set_option_rescan(const bool & val)
            {
                m_option_rescan = val;
            }
        
            /**
             * The option to rescan starting at the genesis block.
             */
            const bool & option_rescan() const
            {
                return m_option_rescan;
            }
        
            /**
             * Sets the number of transactions in the last block.
             * @param val The value.
             */
            void set_last_block_transactions(const std::uint64_t & val)
            {
                m_last_block_transactions = val;
            }
        
            /**
             * The number of transactions in the last block.
             */
            const std::uint64_t & last_block_transactions() const
            {
                return m_last_block_transactions;
            }
        
            /**
             * Sets the last block size.
             * @param val The value.
             */
            void set_last_block_size(const std::uint64_t & val)
            {
                m_last_block_size = val;
            }
        
            /**
             * The last block size.
             */
            const std::uint64_t & last_block_size() const
            {
                return m_last_block_size;
            }
        
            /**
             * Set the money supply.
             * @param val The value.
             */
            void set_money_supply(const std::uint64_t & val)
            {
                m_money_supply = val;
            }
        
            /**
             * The money supply.
             */
            const std::uint64_t & money_supply() const
            {
                return m_money_supply;
            }
        
            /**
             * Sets our public address as seen by others.
             * @param val The value.
             */
            void set_address_public(const boost::asio::ip::address & val)
            {
                m_address_public = val;
            }
        
            /**
             * Our public address as seen by others.
             */
            const boost::asio::ip::address & address_public() const
            {
                return m_address_public;
            }
        
            /**
             * The coinbase flags.
             */
            script & coinbase_flags();
        
            /**
             * Sets the active tcp_connection identifier.
             * @param val The value.
             */
            void set_spv_active_tcp_connection_identifier(
                const std::uint32_t & val
            );
        
            /**
             * The (SPV) active tcp_connection identifier.
             */
            const std::uint32_t & spv_active_tcp_connection_identifier() const;
        
            /**
             * The (SPV) block_merkle's
             */
            std::map<sha256, std::unique_ptr<block_merkle> > &
                spv_block_merkles()
            ;
        
            /**
             * Sets the last (SPV) block we've received.
             * @param val The block_merkle.
             */
            void set_spv_block_last(const block_merkle & val);
        
            /**
             * Sets the last (SPV) block we've received.
             * @param val The block_merkle.
             */
            void set_spv_block_last(const std::unique_ptr<block_merkle> & val);
 
            /**
             * The last (SPV) block_merkle we've received.
             */
            const std::unique_ptr<block_merkle> & spv_block_last() const;
        
            /**
             * The (SPV) block_merkle orphans.
             */
            std::map<sha256, std::unique_ptr<block_merkle> >
                & spv_block_merkle_orphans()
            ;
        
            /**
             * Sets the last (SPV) orphan block_merkle we've received.
             * @param val The block_merkle.
             */
            void set_spv_block_orphan_last(const block_merkle & val);
        
            /**
             * The last (SPV) orphan block_merkle we've received.
             */
            const std::unique_ptr<block_merkle> &
                spv_block_orphan_last() const
            ;

            /**
             * Sets the best (SPV) block height.
             * @param value The value.
             */
            void set_spv_best_block_height(const std::int32_t & value);
        
            /**
             * The best (SPV) block height.
             */
            const std::int32_t & spv_best_block_height() const;
        
            /**
             * The SPV transaction_bloom_filter.
             */
            const std::unique_ptr<transaction_bloom_filter>
                & spv_transaction_bloom_filter() const
            ;
        
            /**
             * Returns the (SPV) block locators by stepping back over
             * previously validated blocks in the chain.
             */
            std::vector<sha256> spv_block_locator_hashes();
        
            /**
             * If true getblocks is used over getheaders during chain
             * synchronization.
             * @param val The value.
             */
            void set_spv_use_getblocks(const bool & val);
        
            /**
             * If true (SPV) getblocks is used over getheaders during chain
             * synchronization..
             */
            const bool & spv_use_getblocks() const;
        
            /**
             * Sets the (peer) headers first synchronization active
             * tcp_connection identifier.
             */
        	void set_peer_headers_first_active_tcp_connection_identifier(
         	   const std::uint32_t & val
            );
        
            /**
             * The (peer) headers first synchronization active tcp_connection
             * identifier.
             */
            const std::uint32_t &
            	peer_headers_first_active_tcp_connection_identifier() const
            ;
        
            /**
             * The (peer) block::header's
             */
            std::map<sha256, std::unique_ptr<block> >
                & peer_headers_first_blocks()
            ;
        
            /**
             * The (peer) validated block header heights and hashes.
             */
            std::map<std::uint32_t, sha256>
                & peer_headers_first_heights_and_hashes()
            ;
        
            /**
             * Sets the last (peer) block::header we've received.
             * @param val The block.
             */
            void set_peer_headers_first_block_last(const block & val);
        
            /**
             * Sets the last peer block::header we've received.
             * @param val The block.
             */
            void set_peer_headers_first_block_last(
            	const std::unique_ptr<block> & val
            );
 
            /**
             * The last (peer) block::header we've received.
             */
            const std::unique_ptr<block> &
            	peer_headers_first_block_last() const
            ;
        
            /**
             * Returns the (peer) block locators by stepping back over
             * previously validated block headers in the chain.
             */
            std::vector<sha256> peer_headers_first_block_locator_hashes();
        
            /**
             * If true getheaders is used over getblocks during chain
             * synchronization.
             * @param val The value.
             */
            void set_peer_use_headers_first_chain_sync(const bool & val);
        
            /**
             * If true getheaders is used over getblocks during chain
             * synchronization.
             */
            const bool & peer_use_headers_first_chain_sync() const;
        
            /**
             * Set the time our (SPV) wallet was created.
             * @param val The std::time.
             */
            void set_spv_time_wallet_created(const std::time_t & val);
        
            /**
             * The time our wallet was created.
             */
            const std::time_t spv_time_wallet_created() const;
        
            /**
             * The (SPV) orphan transactions.
             */
            std::map<sha256, std::vector<transaction> > &
                spv_block_merkle_orphan_transactions()
            ;
        
            /**
             * Set's DB_PRIVATE flag.
             * @param val The value.
             */
            void set_db_private(const bool & val);
        
            /**
             * If true the DB_PRIVATE flag should be used.
             */
            const bool & db_private() const;
        
            /**
             * Resets the (SPV) transaction_bloom_filter to the current
             * current environment.
             */
            void spv_reset_bloom_filter();

            /**
             * The false positive rate.
             */
            const double spv_false_positive_rate() const;
    
            /**
             * Set's the (average) false positive rate.
             * @param val The value.
             */
            void set_spv_average_false_positive_rate(const double & val);
        
            /**
             * The (average) false positive rate.
             */
            const double & spv_average_false_positive_rate() const;
        
        private:
        
            /**
             * The boost::asio::io_service.
             */
            boost::asio::io_service m_io_service;
        
            /**
             * The boost::asio::strand.
             */
            boost::asio::strand m_strand;
        
            /**
             * The state.
             */
            state_t m_state;
        
        	/**
        	 * The std::recursive_mutex for all containers and pointers.
          	 */
            mutable std::recursive_mutex recursive_mutex_;
    
            /**
             * If true we are in debug mode.
             */
            bool m_debug;
        
            /**
             * The protocol::operation_mode_t.
             */
            protocol::operation_mode_t m_operation_mode;
        
            /**
             * If true we are a (SPV) client.
             */
            bool m_is_client_spv;
        
            /**
             * The version nonce (used to detect connections to ourselves).
             */
            std::uint64_t m_version_nonce;
        
            /**
             * The best block height.
             */
            std::int32_t m_best_block_height;
        
            /**
             * The block indexes.
             */
            std::map<sha256, block_index *> m_block_indexes;
        
            /**
             * The hash of the best chain.
             */
            sha256 m_hash_best_chain;
        
            /**
             * The block index used by find_block_by_height.
             */
            block_index * m_block_index_fbbh_last;
        
            /**
             * The time of the best received block.
             */
            std::int64_t m_time_best_received;
        
            /**
             * The number of transactions that have been updated.
             */
            std::uint32_t m_transactions_updated;
        
            /**
             * The (main) wallet.
             */
            std::shared_ptr<wallet> m_wallet_main;
        
            /**
             * The orphan blocks.
             */
            std::map<sha256, std::shared_ptr<block> > m_orphan_blocks;
        
            /**
             * The orphan blocks by previous.
             */
            std::multimap<
                sha256, std::shared_ptr<block>
            > m_orphan_blocks_by_previous;

            /**
             * The orphan transactions.
             */
            std::map<
                sha256, std::shared_ptr<data_buffer>
            > m_orphan_transactions;
        
            /**
             * The orphan transactions by previous.
             */
            std::map<
                sha256, std::map<sha256, std::shared_ptr<data_buffer> >
            > m_orphan_transactions_by_previous;

            /**
             * The number of blocks other peers claim to have.
             */
            median_filter<std::uint32_t> m_peer_block_counts;
        
            /**
             * The relay inventory_vector's.
             */
            std::map<inventory_vector, data_buffer> m_relay_invs;
        
            /**
             * The relay inventory_vector expirations.
             */
            std::deque<
                std::pair<std::int64_t, inventory_vector>
            > m_relay_inv_expirations;
        
            /**
             * The transaction fee.
             */
            std::int64_t m_transaction_fee;
        
            /**
             * The option to rescan starting at the genesis block.
             */
            bool m_option_rescan;
        
            /**
             * The number of transactions in the last block.
             */
            std::uint64_t m_last_block_transactions;
   
            /**
             * The last block size.
             */
            std::uint64_t m_last_block_size;
        
            /**
             * The money supply.
             */
            std::uint64_t m_money_supply;
        
            /**
             * Our public address as seen by others.
             */
            boost::asio::ip::address m_address_public;
        
            /**
             * The coinbase flags.
             */
            std::shared_ptr<script> m_coinbase_flags;
        
            /**
             * The (SPV) active tcp_connection identifier.
             */
            std::uint32_t m_spv_active_tcp_connection_identifier;
        
            /**
             * The (SPV) block_merkle's
             */
            std::map<sha256, std::unique_ptr<block_merkle> >
                m_spv_block_merkles
            ;
        
            /**
             * The last (SPV) block_merkle we've received.
             */
            std::unique_ptr<block_merkle> m_spv_block_last;
        
            /**
             * The (SPV) block_merkle orphans.
             */
            std::map<sha256, std::unique_ptr<block_merkle> >
                m_spv_block_merkle_orphans
            ;
        
            /**
             * The last (SPV) orphan block_merkle we've received.
             */
            std::unique_ptr<block_merkle> m_spv_block_orphan_last;
        
            /**
             * The (SPV) best block height.
             */
            mutable std::int32_t m_spv_best_block_height;
        
            /**
             * The SPV transaction_bloom_filter.
             */
            std::unique_ptr<transaction_bloom_filter>
                m_spv_transaction_bloom_filter
            ;
        
            /**
             * If true (SPV) getblocks is used over getheaders during chain
             * synchronization.
             */
            bool m_spv_use_getblocks;
        
            /**
             * The (peer) headers first synchronization active tcp_connection
             * identifier.
             */
            std::uint32_t m_peer_headers_first_active_tcp_connection_identifier;
        
            /**
             * The (peer) block::header's
             */
            std::map<sha256, std::unique_ptr<block> >
                m_peer_headers_first_blocks
            ;
        
        	/**
             * The (peer) validated block header heights and hashes.
             */
            std::map<std::uint32_t, sha256>
            	m_peer_headers_first_heights_and_hashes
            ;
        
            /**
             * The last (peer) block::header we've received.
             */
            std::unique_ptr<block> m_peer_headers_first_block_last;
        
            /**
             * If true getheaders is used over getblocks during chain
             * synchronization.
             */
            bool m_peer_use_headers_first_chain_sync;
        
            /**
             * The time our wallet was created.
             */
            std::time_t m_spv_time_wallet_created;
        
            /**
             * The (SPV) block_merkle orphan transactions.
             */
            std::map<sha256, std::vector<transaction> >
                m_spv_block_merkle_orphan_transactions
            ;
        
            /**
             * The (average) false positive rate.
             */
            double m_spv_average_false_positive_rate;
        
            /**
             * If true the DB_PRIVATE flag should be used.
             */
            bool m_db_private;
        
        protected:
        
            // ...
    };
    
}  // namespace coin

#endif // COIN_GLOBALS_HPP
