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

#ifndef COIN_TCP_CONNECTION_HPP
#define COIN_TCP_CONNECTION_HPP

#include <chrono>
#include <deque>
#include <functional>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <boost/asio.hpp>

#include <coin/inventory_vector.hpp>
#include <coin/protocol.hpp>
#include <coin/sha256.hpp>
#include <coin/transaction_bloom_filter.hpp>

namespace coin {
    
    class block;
    class block_index;
    class block_locator;
    class block_merkle;
    class message;
    class stack_impl;
    class tcp_transport;
    class transaction;
    class transaction_bloom_filter;
    
    /**
     * Implement a tcp connection.
     */
    class tcp_connection : public std::enable_shared_from_this<tcp_connection>
    {
        public:
        
            /**
             * The direction.
             */
            typedef enum
            {
                direction_incoming,
                direction_outgoing,
            } direction_t;
        
            /**
             * Constructor
             * ios The boost::asio::io_service.
             * @param owner The stack_impl.
             * @param direction The direction_t
             * @param transport The tcp_transport.
             */
            explicit tcp_connection(
                boost::asio::io_service & ios, stack_impl & owner,
                const direction_t & direction,
                std::shared_ptr<tcp_transport> transport
            );
        
            /**
             * Destructor
             */
            ~tcp_connection();
        
            /**
             * Starts direction_incoming.
             */
            void start();
        
            /**
             * Starts direction_outgoing.
             * @param ep The boost::asio::ip::tcp::endpoint.
             */
            void start(const boost::asio::ip::tcp::endpoint ep);
        
            /**
             * Stops
             */
            void stop();
        
            /** 
             * Stops after the specified interval.
             * @param interval The interval in seconds.
             */
            void stop_after(const std::uint32_t & interval);
        
            /**
             * Sends a raw buffer.
             * @param buf The buffer.
             * @param len The length.
             */
            void send(const char * buf, const std::size_t & len);
        
            /**
             * Sends an addr message.
             * @param local_address_only If true only the local address will
             * be sent.
             */
            void send_addr_message(const bool & local_address_only = false);
        
            /**
             * Sends a getblocks message.
             * @param hash_stop The hash stop.
             * @param locator The block locator.
             */
            void send_getblocks_message(
                const sha256 & hash_stop, const block_locator & locator
            );
        
            /**
             * Sends a getblocks message.
             * @param index_begin The start block index.
             * @param hash_end The end hash.
             */
            void send_getblocks_message(
                const block_index * index_begin, const sha256 & hash_end
            );
        
            /**
             * Sends an inv message.
             * @param type The inventory_vector::type_t.
             * @param hash_block The hash of the block.
             */
            void send_inv_message(
                const inventory_vector::type_t type, const sha256 hash_block
            );
        
            /**
             * Sends an inv message.
             * @param type The inventory_vector::type_t.
             * @param block_hashes The hashes of the blocks.
             */
            void send_inv_message(
                const inventory_vector::type_t type,
                const std::vector<sha256> block_hashes
            );
        
            /**
             * Sends a (relayed) encoded inv given command.
             * @param command The command.
             * @param
             */
            void send_relayed_inv_message(
                const inventory_vector inv, const data_buffer buffer
            );
        
            /**
             * Sends a getdata message by appending the inventory_vector to
             * the queue.
             * getdata The inventory_vector's.
             */
            void send_getdata_message(
                const std::vector<inventory_vector> & getdata
            );

            /**
             * Sends a block message.
             * @param blk The block.
             */
            void send_block_message(const block blk);
        
            /**
             * Sends a filterload message.
             * @param filter The transaction_bloom_filter.
             */
            void send_filterload_message(
                const transaction_bloom_filter & filter
            );
        
            /**
             * Sens a filteradd message.
             * @param data The data.
             */
            void send_filteradd_message(
                const std::vector<std::uint8_t> & data
            );
        
            /**
             * Sends a filterclear message.
             */
            void send_filterclear_message();
        
            /**
             * Sends a tx message.
             * @param tx The transaction.
             */
            void send_tx_message(const transaction tx);
        
            /**
             * Sends a headers message.
             * @param headers The block headers.
             */
            void send_headers_message(const std::vector<block> & headers);
        
            /**
             * The tcp_transport.
             */
            std::weak_ptr<tcp_transport> & get_tcp_transport();
        
            /**
             * The direction.
             */
            const direction_t & direction() const;
        
            /**
             * The (remote) protocol version.
             */
            const std::uint32_t & protocol_version() const;
        
            /**
             * The (remote) protocol version services.
             */
            const std::uint64_t & protocol_version_services() const;
        
            /**
             * The (remote) protocol version timestamp.
             */
            const std::uint64_t & protocol_version_timestamp() const;
        
            /**
             * The (remote) protocol version start height.
             */
            const std::int32_t & protocol_version_start_height() const;
        
            /**
             * The (remote) protocol version user agent.
             */
            const std::string & protocol_version_user_agent() const;
        
            /**
             * The (remote) protocol version source address.
             */
            const protocol::network_address_t &
                protocol_version_addr_src() const
            ;
        
            /**
             * The (remote) protocol version relay.
             */
            const bool & protocol_version_relay() const;
        
            /**
             * Sets the on probe handler (probe-only mode).
             * @param f The std::function.
             */
            void set_on_probe(
                const std::function<void (const std::uint32_t &,
                const std::string &, const std::uint64_t &,
                const std::int32_t &)> & f
            );
        
            /**
             * Sets the hash of the known checkpoint.
             * @param val The sha256.
             */
            void set_hash_checkpoint_known(const sha256 & val);
        
            /**
             * The hash of the known checkpoint.
             */
            const sha256 & hash_checkpoint_known() const;
        
            /**
             * Clears the "seen" protocol::network_address_t objects.
             */
            void clear_seen_network_addresses();
        
            /**
             * Sets the Denial-of-Service score.
             * @param val The value.
             */
            void set_dos_score(const std::uint8_t & val);
        
            /**
             * The Denial-of-Service score.
             */
            const std::uint8_t & dos_score() const;
        
            /**
             * Sets the (SPV) Denial-of-Service score.
             * @param val The value.
             */
            void set_spv_dos_score(const double & val);
        
            /**
             * The (SPV) Denial-of-Service score.
             */
            const double & spv_dos_score() const;
        
            /**
             * If set to true the connection will stop after the initial
             * handshake and the address_manager will be informed.
             * @param val The value.
             */
            void set_probe_only(const bool & val);
        
            /**
             * The hash of the best block header we have sent to the remote
             * node.
             */
            const sha256 & hash_best_block_header_sent() const;
        
            /**
             * If true we have received a sendheaders message.
             */
            const bool & is_sendheaders() const;
        
        	/**
      		 * If true a (peer) headers first chain synchronization block has
             * stalled.
         	 */
        	bool peer_headers_first_block_is_stalled();
        
            /**
             * The number of (peer) headers first chain synchronization blocks
             * that have requested.
             * @param val The value.
             */
        	void set_peer_headers_first_blocks_requested(
         	   const std::uint32_t & val
			);
        
            /**
             * The number of (peer) headers first chain synchronization blocks
             * that have requested.
             */
            const std::uint32_t  & peer_headers_first_blocks_requested() const;
        
            /**
             * The identifier.
             */
            const std::uint32_t & identifier() const;
        
            /**
             * The RTT (round trip time).
             */
            const std::uint32_t rtt();

            /**
             * If true the transport is valid (usable).
             */
            bool is_transport_valid();
        
            /**
             * The on read handler.
             * @param buf The buffer.
             * @param len The length.
             */
            void on_read(const char * buf, const std::size_t & len);
        
        private:
        
            /**
             * Starts direction_incoming.
             */
            void do_start();
        
            /**
             * Starts direction_outgoing.
             * @param ep The boost::asio::ip::tcp::endpoint.
             */
            void do_start(const boost::asio::ip::tcp::endpoint ep);
        
            /**
             * Stops
             */
            void do_stop();
        
            /**
             * Sends a verack message.
             */
            void send_verack_message();
        
            /**
             * Sends a version message.
             */
            void send_version_message();
        
            /**
             * Sends an address message.
             * @param addr The address.
             */
            void send_addr_message(const protocol::network_address_t & addr);
        
            /**
             * Sends an address message.
             * @param addr The address.
             */
            void do_send_addr_message(const protocol::network_address_t & addr);
        
            /**
             * Sends a tx message.
             * @param tx The transaction.
             */
            void do_send_tx_message(const transaction & tx);
        
            /**
             * Sends a getaddr message.
             */
            void send_getaddr_message();
        
            /**
             * Sends a ping message.
             */
            void send_ping_message();

            /**
             * Sends a pong message.
             * @param nonce The nonce.
             */
            void send_pong_message(const std::uint64_t & nonce);
        
            /**
             * Sends a getdata message if there are any in the queue.
             */
            void send_getdata_message();

            /**
             * Sends a getheaders message.
             * @param hash_stop The hash stop.
             * @param locator The block locator.
             */
            void send_getheaders_message(
                const sha256 & hash_stop, const block_locator & locator
            );
        
        	/**
          	 * Sends a sendheaders message.
             */
        	void send_sendheaders_message();
        
            /**
             * Sends a merkleblock message.
             * @param merkleblock The block_merkle.
             */
            void send_merkleblock_message(const block_merkle & merkleblock);

            /**
             * Sends a mempool message.
             */
            void send_mempool_message();
        
            /**
             * Relays an encoded inv given message command.
             * @param command The command.
             * @param
             */
            void relay_inv(
                const inventory_vector & inv, const data_buffer & buffer
            );
        
            /**
             * Handles a message.
             * @param msg The message.
             */
            bool handle_message(message & msg);
        
            /**
             * The ping timer handler.
             * @param ec The boost::system::error_code.
             */
            void do_ping(const boost::system::error_code & ec);
        
            /**
             * Sends getblocks if needed.
             * @param ec The boost::system::error_code.
             */
            void do_send_getblocks(const boost::system::error_code & ec);
        
            /**
             * Sends an inv message.
             * @param type The inventory_vector::type_t.
             * @param hash_block The hash of the block.
             */
            void do_send_inv_message(
                const inventory_vector::type_t & type, const sha256 & hash_block
            );
        
            /**
             * Sends an inv message.
             * @param type The inventory_vector::type_t.
             * @param block_hashes The hashes of the blocks.
             */
            void do_send_inv_message(
                const inventory_vector::type_t & type,
                const std::vector<sha256> & block_hashes
            );
        
            /**
             * Sends a (relayed) encoded inv given command.
             * @param command The command.
             * @param
             */
            void do_send_relayed_inv_message(
                const inventory_vector & inv, const data_buffer & buffer
            );
        
            /**
             * Sends a block message.
             * @param blk The block.
             */
            void do_send_block_message(const block & blk);
        
            /**
             * Sends getheaders if needed.
             * @param ec The boost::system::error_code.
             */
            void do_send_getheaders(const boost::system::error_code & ec);
        
            /**
             * Rebroadcasts addr messages every 24 hours.
             */
            void do_rebroadcast_addr_messages(const std::uint32_t & interval);
        
            /**
             * The cbstatus timer handler.
             * @param interval The interval.
             */
            void do_send_cbstatus(const std::uint32_t & interval);
    
            /**
             * Inserts a seen inventor_vector object.
             * @param inv The inventory_vector.
             */
            bool insert_inventory_vector_seen(const inventory_vector & inv);
        
            /**
             * The identifier.
             */
            std::uint32_t m_identifier;
        
            /**
             * The tcp_transport.
             */
            std::weak_ptr<tcp_transport> m_tcp_transport;
        
            /**
             * The direction.
             */
            direction_t m_direction;
        
            /**
             * The (remote) protocol version.
             */
            std::uint32_t m_protocol_version;
        
            /**
             * The (remote) protocol version services.
             */
            std::uint64_t m_protocol_version_services;
        
            /**
             * The (remote) protocol version timestamp.
             */
            std::uint64_t m_protocol_version_timestamp;
        
            /**
             * The (remote) protocol version start height.
             */
            std::int32_t m_protocol_version_start_height;
        
            /**
             * The (remote) protocol version user agent.
             */
            std::string m_protocol_version_user_agent;
        
            /**
             * The (remote) protocol version source address.
             */
            protocol::network_address_t m_protocol_version_addr_src;
        
            /**
             * The (remote) protocol version relay.
             */
            bool m_protocol_version_relay;
        
            /**
             * The probe handler (probe-only mode).
             */
            std::function<
                void (const std::uint32_t &, const std::string &,
                const std::uint64_t &, const std::int32_t &)
            > m_on_probe;
        
            /**
             * Our public address as advertised in the version message.
             */
            boost::asio::ip::address m_address_public;
        
            /**
             * The hash of the known checkpoint.
             */
            sha256 m_hash_checkpoint_known;
        
            /**
             * The hash continue for getblocks and getdata.
             */
            sha256 m_hash_continue;
        
            /**
             * If true we sent a getaddr message.
             */
            bool m_sent_getaddr;
        
            /**
             * The "seen" protocol::network_address_t objects.
             */
            std::set<protocol::network_address_t> m_seen_network_addresses;
        
            /**
             * The Denial-of-Service score.
             */
            std::uint8_t m_dos_score;
        
            /**
             * The (SPV) Denial-of-Service score.
             */
            double m_spv_dos_score;
        
            /**
             * If set to true the connection will stop after the initial
             * handshake occurs and the address_manager will be informed.
             */
            bool m_probe_only;
        
        	/**
             * The hash of the best block header we have sent to the remote
             * node.
             */
            sha256 m_hash_best_block_header_sent;
        
        	/**
             * If true we have received a sendheaders message.
             */
            bool m_is_sendheaders;
        
            /**
             * The number of (peer) headers first chain synchronization blocks
             * that have requested.
             */
            std::uint32_t m_peer_headers_first_blocks_requested;
        
            /**
             * The state.
             */
            enum
            {
                state_none,
                state_starting,
                state_started,
                state_stopping,
                state_stopped,
            } m_state;
        
        protected:
        
            /**
             * The boost::asio::io_service.
             */
            boost::asio::io_service & io_service_;
        
            /**
             * The boost::asio::strand.
             */
            boost::asio::strand & strand_;
        
            /**
             * The stack_impl.
             */
            stack_impl & stack_impl_;

            /**
             * The read queue.
             */
            std::deque<char> read_queue_;
        
            /**
             * The ping timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_ping_;
        
            /**
             * The ping timeout timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_ping_timeout_;
        
            /**
             * The last time we have sent a ping message.
             */
            std::chrono::milliseconds interval_ping_;
        
            /**
             * The last time we have received a pong message.
             */
            std::chrono::milliseconds interval_pong_;
        
            /**
             * The last calculated RTT.
             */
            std::uint32_t interval_rtt_last_;
        
            /**
             * The ping interval in seconds.
             */
            enum { interval_ping = 60 };
        
            /**
             * If true we have sent an initial getblock's message.
             */
            bool did_send_getblocks_;
        
            /**
             * The inventory_vector's used in getdata messages.
             */
            std::vector<inventory_vector> getdata_;
        
            /**
             * The last getblocks index_begin.
             */
            block_index * last_getblocks_index_begin_;
        
            /**
             * The last getblocks hash_end.
             */
            sha256 last_getblocks_hash_end_;
        
            /**
             * The time the last block was received.
             */
            std::time_t time_last_block_received_;
        
            /**
             * The delayed stop timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_delayed_stop_;
        
            /**
             * The version timeout timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_version_timeout_;
        
            /**
             * The getblocks timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_getblocks_;
        
            /**
             * The getheaders timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_getheaders_;
        
            /**
             * The addr rebroadcast timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_addr_rebroadcast_;
        
            /**
             * The last time a getblocks was sent.
             */
            std::time_t time_last_getblocks_sent_;
        
            /**
             * The last time a headers was received.
             */
            std::time_t time_last_headers_received_;
        
            /**
             * The BIP-0037 transaction bloom filter.
             */
            std::unique_ptr<transaction_bloom_filter>
                transaction_bloom_filter_
            ;

            /**
             * The (SPV) getheaders timeout timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_spv_getheader_timeout_;
        
            /**
             * The (SPV) getblocks timeout timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_spv_getblocks_timeout_;

            /**
             * The (peer) getheaders timeout timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_peer_getheader_timeout_;

            /**
             * The seen inventory_vector object set.
             */
            std::set<inventory_vector> inventory_vectors_seen_set_;
        
            /**
             * The seen inventory_vector object set.
             */
            std::deque<inventory_vector> inventory_vectors_seen_queue_;
        
            /**
             * The current block_merkle waiting for receipt of it's matched
             * transactions.
             */
            std::shared_ptr<block_merkle> spv_block_merkle_current_;
        
            /**
             * The current block_merkle's matched transactions.
             */
            std::set<sha256> spv_block_merkle_current_tx_hashes_;
        
            /**
             * This block_merkle has no matching received transactions.
             */
            std::vector<transaction> spv_block_merkle_current_tx_received_;
    };
    
} // namespace coin

#endif // COIN_TCP_CONNECTION_HPP
