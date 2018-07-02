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

#include <algorithm>
#include <cassert>

#include <coin/address_manager.hpp>
#include <coin/block_merkle.hpp>
#include <coin/block_locator.hpp>
#include <coin/checkpoints.hpp>
#include <coin/db_tx.hpp>
#include <coin/globals.hpp>
#include <coin/logger.hpp>
#include <coin/message.hpp>
#include <coin/network.hpp>
#include <coin/random.hpp>
#include <coin/tcp_acceptor.hpp>
#include <coin/tcp_connection.hpp>
#include <coin/tcp_connection_manager.hpp>
#include <coin/tcp_transport.hpp>
#include <coin/transaction_pool.hpp>
#include <coin/stack_impl.hpp>
#include <coin/time.hpp>
#include <coin/utility.hpp>
#include <coin/wallet_manager.hpp>

using namespace coin;

tcp_connection::tcp_connection(
    boost::asio::io_service & ios, stack_impl & owner,
    const direction_t & direction, std::shared_ptr<tcp_transport> transport
    )
    : m_tcp_transport(transport)
    , m_identifier(random::uint32())
    , m_direction(direction)
    , m_protocol_version(0)
    , m_protocol_version_services(0)
    , m_protocol_version_timestamp(0)
    , m_protocol_version_start_height(-1)
    , m_protocol_version_relay(true)
    , m_sent_getaddr(false)
    , m_dos_score(0)
    , m_spv_dos_score(0.0)
    , m_probe_only(false)
    , m_is_sendheaders(false)
    , m_peer_headers_first_blocks_requested(0)
    , m_state(state_none)
    , io_service_(ios)
    , strand_(globals::instance().strand())
    , stack_impl_(owner)
    , timer_ping_(io_service_)
    , timer_ping_timeout_(io_service_)
    , interval_ping_(
        std::chrono::duration_cast<std::chrono::milliseconds> (
        std::chrono::system_clock::now().time_since_epoch())
    )
    , interval_pong_(interval_ping_)
    , interval_rtt_last_(0)
    , did_send_getblocks_(false)
    , last_getblocks_index_begin_(0)
    , time_last_block_received_(std::time(0))
    , timer_delayed_stop_(io_service_)
    , timer_version_timeout_(io_service_)
    , timer_getblocks_(io_service_)
    , timer_getheaders_(io_service_)
    , timer_addr_rebroadcast_(io_service_)
    , time_last_getblocks_sent_(std::time(0) - 60)
    , time_last_headers_received_(0)
    , timer_spv_getheader_timeout_(io_service_)
    , timer_spv_getblocks_timeout_(io_service_)
	, timer_peer_getheader_timeout_(io_service_)
{
    // ...
}

tcp_connection::~tcp_connection()
{
    // ...
}

void tcp_connection::start()
{
    /**
     * Hold onto the tcp_transport until the post operation completes.
     */
    if (auto transport = m_tcp_transport.lock())
    {
        auto self(shared_from_this());
        
        /**
         * Post the operation onto the boost::asio::io_service.
         */
        io_service_.post(strand_.wrap([this, self, transport]()
        {
            do_start();
        }));
    }
}

void tcp_connection::start(const boost::asio::ip::tcp::endpoint ep)
{
    /**
     * Hold onto the tcp_transport until the post operation completes.
     */
    if (auto transport = m_tcp_transport.lock())
    {
        auto self(shared_from_this());
        
        /**
         * Post the operation onto the boost::asio::io_service.
         */
        io_service_.post(strand_.wrap([this, self, ep, transport]()
        {
            do_start(ep);
        }));
    }
}

void tcp_connection::stop()
{
    auto self(shared_from_this());
    
    /**
     * Post the operation onto the boost::asio::io_service.
     */
    io_service_.post(strand_.wrap([this, self]()
    {
        do_stop();
    }));
}

void tcp_connection::stop_after(const std::uint32_t & interval)
{
    auto self(shared_from_this());
    
    /**
     * Starts the delayed stop timer.
     */
    timer_delayed_stop_.expires_from_now(std::chrono::seconds(interval));
    timer_delayed_stop_.async_wait(strand_.wrap(
        [this, self, interval](boost::system::error_code ec)
    {
        if (ec)
        {
            // ...
        }
        else
        {
            log_debug(
                "TCP connection is stopping after " << interval << " seconds."
            );
            
            /**
             * Stop
             */
            do_stop();
        }
    }));
}

void tcp_connection::send(const char * buf, const std::size_t & len)
{
    if (auto transport = m_tcp_transport.lock())
    {
        transport->write(buf, len);
    }
    else
    {
        stop();
    }
}

void tcp_connection::send_addr_message(const bool & local_address_only)
{
    log_debug("TCP connection is sending addr message.");
    
    if (auto t = m_tcp_transport.lock())
    {
        std::lock_guard<std::recursive_mutex> l1(stack_impl::mutex());
        
        /**
         * Allocate the message.
         */
        message msg("addr");

        if (local_address_only == false)
        {
            auto addr_list = stack_impl_.get_address_manager()->get_addr();
            
            for (auto & i : addr_list)
            {
                if (m_seen_network_addresses.count(i) == 0)
                {
                    msg.protocol_addr().addr_list.push_back(i);
                }
            }
        }
        
        if (globals::instance().is_client_spv() == false)
        {
            /**
             * Get our network port.
             */
            auto port =
                stack_impl_.get_tcp_acceptor()->local_endpoint().port()
            ;
            
            protocol::network_address_t addr =
                protocol::network_address_t::from_endpoint(
                boost::asio::ip::tcp::endpoint(m_address_public, port)
            );
            
            msg.protocol_addr().addr_list.push_back(addr);
        }
        
        /**
         * Encode the message.
         */
        msg.encode();
        
        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

void tcp_connection::send_getblocks_message(
    const sha256 & hash_stop, const block_locator & locator
    )
{
    /**
     * Only send a getblocks message if the remote node is a peer.
     */
    if (
        (m_protocol_version_services & protocol::operation_mode_peer)
        )
    {
        if (globals::instance().is_client_spv() == true)
        {
            /**
             * For better security we perform (SPV) getblocks across all
             * connected peers.
             */
            auto should_send_spv_getblocks =
                globals::instance().spv_use_getblocks() == true
            ;
            
            if (should_send_spv_getblocks == true)
            {
                if (auto t = m_tcp_transport.lock())
                {
                    /**
                     * Set the last time we sent a getblocks.
                     */
                    time_last_getblocks_sent_ = std::time(0);
        
                    /**
                     * Allocate the message.
                     */
                    message msg("getblocks");
                    
                    /**
                     * Set the hashes.
                     */
                    msg.protocol_getblocks().hashes = locator.have();
                    
                    /**
                     * Set the stop hash.
                     */
                    msg.protocol_getblocks().hash_stop = hash_stop;
                    
                    log_none("TCP connection is sending (SPV) getblocks.");
                    
                    /**
                     * Encode the message.
                     */
                    msg.encode();
                    
                    if (utility::is_spv_initial_block_download() == true)
                    {
                        auto self(shared_from_this());
                        
                        /**
                         * Starts the (SPV) getblocks timeout timer.
                         */
                        timer_spv_getblocks_timeout_.expires_from_now(
                            std::chrono::seconds(8)
                        );
                        timer_spv_getblocks_timeout_.async_wait(
                            strand_.wrap(
                            [this, self](boost::system::error_code ec)
                        {
                            if (ec)
                            {
                                // ...
                            }
                            else
                            {
                                log_info(
                                    "TCP connection " << m_identifier <<
                                    " (SPV) getblocks timed out, stopping."
                                );
                                
                                /**
                                 * Stop
                                 */
                                do_stop();
                            }
                        }));
                    }
                    
                    /**
                     * Write the message.
                     */
                    t->write(msg.data(), msg.size());
                }
                else
                {
                    stop();
                }
            }
        }
        else
        {
            log_error(
                "TCP connection tried to send (SPV) getblocks message when "
                "not in SPV client mode."
            );
        }
    }
}

void tcp_connection::send_getblocks_message(
    const block_index * index_begin, const sha256 & hash_end
    )
{
    /**
     * Only send a getblocks message if the remote node is a peer.
     */
    if (
        (m_protocol_version_services & protocol::operation_mode_peer)
        )
    {
        /**
         * Do not send duplicate requests.
         */
        if (
            index_begin == last_getblocks_index_begin_ &&
            hash_end == last_getblocks_hash_end_
            )
        {
            return;
        }

        /**
         * Set the last time we sent a getblocks.
         */
        time_last_getblocks_sent_ = std::time(0);
        
        last_getblocks_index_begin_ =
            const_cast<block_index *> (index_begin)
        ;
        last_getblocks_hash_end_ = hash_end;
        
        if (auto t = m_tcp_transport.lock())
        {
            /**
             * Allocate the message.
             */
            message msg("getblocks");
            
            /**
             * Set the hashes.
             */
            msg.protocol_getblocks().hashes =
                block_locator(index_begin).have()
            ;
            
            /**
             * Set the stop hash.
             */
            msg.protocol_getblocks().hash_stop = hash_end;
            
            log_none("TCP connection is sending getblocks.");
            
            /**
             * Encode the message.
             */
            msg.encode();
            
            /**
             * Write the message.
             */
            t->write(msg.data(), msg.size());
        }
        else
        {
            stop();
        }
    }
}

void tcp_connection::send_inv_message(
    const inventory_vector::type_t type, const sha256 hash_block
    )
{
    auto self(shared_from_this());
    
    /**
     * Post the operation onto the boost::asio::io_service.
     */
    io_service_.post(strand_.wrap([this, self, type, hash_block]()
    {
        do_send_inv_message(type, hash_block);
    }));
}

void tcp_connection::send_inv_message(
    const inventory_vector::type_t type,
    const std::vector<sha256> block_hashes
    )
{
    auto self(shared_from_this());
    
    /**
     * Post the operation onto the boost::asio::io_service.
     */
    io_service_.post(strand_.wrap([this, self, type, block_hashes]()
    {
        do_send_inv_message(type, block_hashes);
    }));
}

void tcp_connection::send_relayed_inv_message(
    const inventory_vector inv, const data_buffer buffer
    )
{
    auto self(shared_from_this());
    
    /**
     * Post the operation onto the boost::asio::io_service.
     */
    io_service_.post(strand_.wrap([this, self, inv, buffer]()
    {
        do_send_relayed_inv_message(inv, buffer);
    }));
}

void tcp_connection::send_getdata_message(
    const std::vector<inventory_vector> & getdata
    )
{
    /**
     * Only send a getdata message if the remote node is a peer.
     */
    if (
        (m_protocol_version_services & protocol::operation_mode_peer)
        )
    {
        /**
         * Append the entries to the end.
         */
   		getdata_.insert(getdata_.end(), getdata.begin(), getdata.end());

        /**
         * Send the getdata message.
         */
        send_getdata_message();
    }
}

void tcp_connection::send_block_message(const block blk)
{
    auto self(shared_from_this());
    
    /**
     * Post the operation onto the boost::asio::io_service.
     */
    io_service_.post(strand_.wrap([this, self, blk]()
    {
        do_send_block_message(blk);
    }));
}

void tcp_connection::send_filterload_message(
    const transaction_bloom_filter & filter
    )
{
    if (globals::instance().is_client_spv() == true)
    {
        if (auto t = m_tcp_transport.lock())
        {
            /**
             * Allocate the message.
             */
            message msg("filterload");

            /**
             * Set the filterload.
             */
            msg.protocol_filterload().filterload =
                std::make_shared<transaction_bloom_filter> (filter)
            ;
            
            log_info("TCP connection is sending filterload.");

            /**
             * Encode the message.
             */
            msg.encode();
            
            /**
             * Write the message.
             */
            t->write(msg.data(), msg.size());
        }
        else
        {
            stop();
        }
    }
}

void tcp_connection::send_filteradd_message(
    const std::vector<std::uint8_t> & data
    )
{
    if (globals::instance().is_client_spv() == true)
    {
        if (auto t = m_tcp_transport.lock())
        {
            /**
             * Allocate the message.
             */
            message msg("filteradd");

            /**
             * Set the data.
             */
            msg.protocol_filteradd().filteradd = data;
            
            log_info("TCP connection is sending filteradd.");

            /**
             * Encode the message.
             */
            msg.encode();
            
            /**
             * Write the message.
             */
            t->write(msg.data(), msg.size());
        }
        else
        {
            stop();
        }
    }
}

void tcp_connection::send_filterclear_message()
{
    if (globals::instance().is_client_spv() == true)
    {
        if (auto t = m_tcp_transport.lock())
        {
            /**
             * Allocate the message.
             */
            message msg("filterclear");

            log_info("TCP connection is sending filterclear.");

            /**
             * Encode the message.
             */
            msg.encode();
            
            /**
             * Write the message.
             */
            t->write(msg.data(), msg.size());
        }
        else
        {
            stop();
        }
    }
}

void tcp_connection::send_tx_message(const transaction tx)
{
    auto self(shared_from_this());
    
    /**
     * Post the operation onto the boost::asio::io_service.
     */
    io_service_.post(strand_.wrap([this, self, tx]()
    {
        do_send_tx_message(tx);
    }));
}

void tcp_connection::send_headers_message(const std::vector<block> & headers)
{
	auto self(shared_from_this());
    
    /**
     * Post the operation onto the boost::asio::io_service.
     */
    io_service_.post(strand_.wrap([this, self, headers]()
    {
        if (auto t = m_tcp_transport.lock())
        {
            /**
             * Allocate the message.
             */
            message msg("headers");

            /**
             * Set the headers.
             */
            msg.protocol_headers().headers = headers;
            
            log_debug(
                "TCP connection is sending headers " <<
                msg.protocol_headers().headers.size() << "."
            );

            /**
             * Encode the message.
             */
            msg.encode();
            
            /**
             * Write the message.
             */
            t->write(msg.data(), msg.size());
        }
        else
        {
            stop();
        }
    }));
}

void tcp_connection::set_hash_checkpoint_known(const sha256 & val)
{
    m_hash_checkpoint_known = val;
}

const sha256 & tcp_connection::hash_checkpoint_known() const
{
    return m_hash_checkpoint_known;
}

void tcp_connection::clear_seen_network_addresses()
{
    auto self(shared_from_this());
    
    /**
     * Post the operation onto the boost::asio::io_service.
     */
    io_service_.post(strand_.wrap([this, self]()
    {
        m_seen_network_addresses.clear();
    }));
}

void tcp_connection::set_dos_score(const std::uint8_t & val)
{
    m_dos_score = val;
    
    /**
     * If the Denial-of-Service score is at least 100 the address is banned
     * and the connection is dropped.
     */
    if (m_dos_score >= 100)
    {
        if (auto transport = m_tcp_transport.lock())
        {
            auto addr =
                transport->socket().remote_endpoint().address().to_string()
            ;
        
            /**
             * Ban the address for 24 hours.
             */
            network::instance().ban_address(addr);
            
            /**
             * Stop.
             */
            stop();
        }
    }
}

const std::uint8_t & tcp_connection::dos_score() const
{
    return m_dos_score;
}

void tcp_connection::set_spv_dos_score(const double & val)
{
    assert(globals::instance().is_client_spv() == true);
    
    m_spv_dos_score = val;
    
    /**
     * If the Denial-of-Service score is at least 100% the address is banned
     * and the connection is dropped.
     */
    if (m_spv_dos_score >= 100.0)
    {
        if (auto transport = m_tcp_transport.lock())
        {
            auto addr =
                transport->socket().remote_endpoint().address().to_string()
            ;
        
            /**
             * Ban the address for one hour.
             */
            network::instance().ban_address(addr, 1 * 60 * 60);
            
            /**
             * Stop.
             */
            stop();
        }
    }
}

const double & tcp_connection::spv_dos_score() const
{
    return m_spv_dos_score;
}

void tcp_connection::set_probe_only(const bool & val)
{
    m_probe_only = val;
}

const sha256 & tcp_connection::hash_best_block_header_sent() const
{
	return m_hash_best_block_header_sent;
}

const bool & tcp_connection::is_sendheaders() const
{
	return m_is_sendheaders;
}

bool tcp_connection::peer_headers_first_block_is_stalled()
{
    if (
        m_peer_headers_first_blocks_requested > 0 &&
        std::time(0) - time_last_block_received_ > 120
        )
	{
        return true;
    }
    
    return false;
}

void tcp_connection::set_peer_headers_first_blocks_requested(
	const std::uint32_t & val
	)
{
	m_peer_headers_first_blocks_requested = val;
}

const std::uint32_t & tcp_connection::peer_headers_first_blocks_requested() const
{
	return m_peer_headers_first_blocks_requested;
}

const std::uint32_t & tcp_connection::identifier() const
{
    return m_identifier;
}

const std::uint32_t tcp_connection::rtt()
{
    auto ret =
    	static_cast<std::uint32_t> ((interval_pong_ - interval_ping_).count())
    ;
    
    if (ret == 0)
    {
        ret = interval_rtt_last_;
    }
    else
    {
        interval_rtt_last_ = ret;
    }
    
    return ret;
}

bool tcp_connection::is_transport_valid()
{
    if (auto transport = m_tcp_transport.lock())
    {
        return true;
    }
    
    return false;
}

void tcp_connection::on_read(const char * buf, const std::size_t & len)
{
    if (globals::instance().state() == globals::state_started)
    {
        auto buffer = std::string(buf, len);

        /**
         * Append to the read queue.
         */
        read_queue_.insert(read_queue_.end(), buf, buf + len);

        while (
            globals::instance().state() == globals::state_started &&
            read_queue_.size() >= message::header_length
            )
        {
            /**
             * Allocate a packet from the entire read queue.
             */
            std::string packet(read_queue_.begin(), read_queue_.end());
            
            /**
             * Allocate the message.
             * @note Packets can be combined, after decoding the message
             * it's buffer will be resized to the actual length.
             */
            message msg(packet.data(), packet.size());
        
            try
            {
                /**
                 * Decode the message.
                 */
                msg.decode();
            }
            catch (std::exception & e)
            {
                log_none(
                    "TCP connection failed to decode message, "
                    "what = " << e.what() << "."
                );

                break;
            }
            
            /**
             * Erase the full/partial packet.
             */
            read_queue_.erase(
                read_queue_.begin(), read_queue_.begin() +
                message::header_length + msg.header().length
            );
            
            try
            {
                /**
                 * Handle the message.
                 */
                handle_message(msg);
            }
            catch (std::exception & e)
            {
                log_debug(
                    "TCP connection failed to handle message, "
                    "what = " << e.what() << "."
                );
                
                /**
                 * If we failed to parse a message with a read queue
                 * twice the size of block::get_maximum_size
                 * then the stream must be corrupted, clear the read queue
                 * and stop the connection.
                 */
                if (
                    read_queue_.size() >
                    block::get_maximum_size() * 2
                    )
                {
                    log_error(
                        "TCP connection read queue too large (" <<
                        read_queue_.size() << "), calling stop."
                    );
                    
                    /**
                     * Clear the read queue.
                     */
                    read_queue_.clear();
                    
                    /**
                     * Call stop
                     */
                    do_stop();
                    
                    return;
                }
            }
        }
    }
}

void tcp_connection::do_start()
{
    m_state = state_starting;
    
    if (m_direction == direction_incoming)
    {
        if (auto transport = m_tcp_transport.lock())
        {
            auto self(shared_from_this());
            
            /**
             * Set the transport on read handler.
             */
            transport->set_on_read(
                [this, self](std::shared_ptr<tcp_transport> t,
                const char * buf, const std::size_t & len)
            {
                on_read(buf, len);
            });

            /**
             * Start the transport accepting the connection.
             */
            transport->start();
            
            /**
             * Start the ping timer.
             */
            timer_ping_.expires_from_now(
                std::chrono::seconds(interval_ping / 8)
            );
            timer_ping_.async_wait(strand_.wrap(
                std::bind(&tcp_connection::do_ping, self,
                std::placeholders::_1))
            );
            
            /**
             * Start the getblocks timer.
             */
            timer_getblocks_.expires_from_now(std::chrono::seconds(1));
            timer_getblocks_.async_wait(strand_.wrap(
                std::bind(&tcp_connection::do_send_getblocks, self,
                std::placeholders::_1))
            );
            
            /**
             * Start the addr rebroadcast timer.
             */
            do_rebroadcast_addr_messages(900);
        }
    }
    else if (m_direction == direction_outgoing)
    {
        assert(0);
    }
    
    m_state = state_started;
}

void tcp_connection::do_start(const boost::asio::ip::tcp::endpoint ep)
{
    m_state = state_starting;

    if (m_direction == direction_incoming)
    {
        assert(0);
    }
    else if (m_direction == direction_outgoing)
    {
        if (auto transport = m_tcp_transport.lock())
        {
            auto self(shared_from_this());
            
            /**
             * Set the transport on read handler.
             */
            transport->set_on_read(
                [this, self](std::shared_ptr<tcp_transport> t,
                const char * buf, const std::size_t & len)
            {
                on_read(buf, len);
            });

            /**
             * Start the transport connecting to the endpoint.
             */
            transport->start(
                ep.address().to_string(), ep.port(), [this, self, ep](
                boost::system::error_code ec,
                std::shared_ptr<tcp_transport> transport)
                {
                    if (ec)
                    {
                        log_none(
                            "TCP connection to " << ep << " failed, "
                            "message = " << ec.message() << "."
                        );
                        
                        stop();
                    }
                    else
                    {
                        log_debug(
                            "TCP connection to " << ep << " success, sending "
                            "version message."
                        );
        
                        /**
                         * Start the version timeout timer.
                         */
                        timer_version_timeout_.expires_from_now(
                            std::chrono::seconds(8)
                        );
                        timer_version_timeout_.async_wait(
                            strand_.wrap(
                                [this, self](boost::system::error_code ec)
                                {
                                    if (ec)
                                    {
                                        // ...
                                    }
                                    else
                                    {
                                        log_error(
                                            "TCP connection (version) timed "
                                            "out, calling stop."
                                        );
                                    
                                        /**
                                         * The connection has timed out, call
                                         * stop.
                                         */
                                        do_stop();
                                    }
                                }
                            )
                        );
                        
                        /**
                         * Send a version message.
                         */
                        send_version_message();
                    }
                }
            );
            
            /**
             * Start the ping timer.
             */
            timer_ping_.expires_from_now(
                std::chrono::seconds(interval_ping / 8)
            );
            timer_ping_.async_wait(strand_.wrap(
                std::bind(&tcp_connection::do_ping, self,
                std::placeholders::_1))
            );
            
            /**
             * Start the getblocks timer.
             */
            timer_getblocks_.expires_from_now(std::chrono::seconds(1));
            timer_getblocks_.async_wait(strand_.wrap(
                std::bind(&tcp_connection::do_send_getblocks, self,
                std::placeholders::_1))
            );
            
            /**
             * Start the addr rebroadcast timer.
             */
            do_rebroadcast_addr_messages(300);
        }
        else
        {
            assert(0);
        }
    }
    
    m_state = state_started;
}

void tcp_connection::do_stop()
{
    m_state = state_stopping;
    
    std::lock_guard<std::recursive_mutex> l1(stack_impl::mutex());
    
    /**
     * If we are an (SPV) node set the active identifier to that of another
     * tcp_connection object.
     */
    if (globals::instance().is_client_spv() == true)
    {
        if (stack_impl_.get_tcp_connection_manager())
        {
            const auto & tcp_connections =
                stack_impl_.get_tcp_connection_manager()->tcp_connections()
            ;
            
            for (auto & i : tcp_connections)
            {
                if (auto connection = i.second.lock())
                {
                    if (
                        connection->is_transport_valid() &&
                        connection->identifier() != m_identifier
                        )
                    {
                        globals::instance(
                            ).set_spv_active_tcp_connection_identifier(
                            connection->identifier()
                        );
                        
                        break;
                    }
                }
            }
        }
    }
    
    /**
     * If we are an (peer) node set the active identifier to that of another
     * tcp_connection object.
     */
    if (globals::instance().peer_use_headers_first_chain_sync() == true)
    {
        if (stack_impl_.get_tcp_connection_manager())
        {
            const auto & tcp_connections =
                stack_impl_.get_tcp_connection_manager()->tcp_connections()
            ;
            
            for (auto & i : tcp_connections)
            {
                if (auto connection = i.second.lock())
                {
                    if (
                        connection->is_transport_valid() &&
                        connection->identifier() != m_identifier
                        )
                    {
                        globals::instance(
                            ).set_peer_headers_first_active_tcp_connection_identifier(
                            connection->identifier()
                        );
                        
                        break;
                    }
                }
            }
        }
    }
    
    /**
     * Stop the transport.
     */
    if (auto t = m_tcp_transport.lock())
    {
        t->stop();
    }
    
    /**
     * Remove references to shared pointers.
     */
    m_on_probe = nullptr;
    
    read_queue_.clear();
    timer_ping_.cancel();
    timer_version_timeout_.cancel();
    timer_ping_timeout_.cancel();
    timer_getblocks_.cancel();
    timer_getheaders_.cancel();
    timer_addr_rebroadcast_.cancel();
    timer_delayed_stop_.cancel();
    timer_spv_getheader_timeout_.cancel();
    timer_spv_getblocks_timeout_.cancel();
    timer_peer_getheader_timeout_.cancel();
    
    m_state = state_stopped;
}

void tcp_connection::send_verack_message()
{
    if (auto t = m_tcp_transport.lock())
    {
        /**
         * Allocate the message.
         */
        message msg("verack");
        
        /**
         * Encode the message.
         */
        msg.encode();
        
        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

void tcp_connection::send_version_message()
{
    if (auto t = m_tcp_transport.lock())
    {
        std::lock_guard<std::recursive_mutex> l1(stack_impl::mutex());
        
        /**
         * Allocate the message.
         */
        message msg("version");

        /**
         * Get our network port.
         */
        auto port =
            globals::instance().is_client_spv() == true ? 0 :
            stack_impl_.get_tcp_acceptor()->local_endpoint().port()
        ;
        
        /**
         * Set the version addr_src address.
         */
        msg.protocol_version().addr_src.port = port;
    
        /**
         * Set the version nonce.
         */
        msg.protocol_version().nonce = globals::instance().version_nonce();
        
        /**
         * Copy the peers' ip address into the addr_dst address.
         */
        if (t->socket().remote_endpoint().address().is_v4())
        {
            std::memcpy(
                &msg.protocol_version().addr_dst.address[0],
                &protocol::v4_mapped_prefix[0],
                protocol::v4_mapped_prefix.size()
            );
            
            auto ip = htonl(
                t->socket().remote_endpoint().address().to_v4().to_ulong()
            );
            
            std::memcpy(
                &msg.protocol_version().addr_dst.address[0] +
                protocol::v4_mapped_prefix.size(), &ip, sizeof(ip)
            );
        }
        else
        {
            std::memcpy(
                &msg.protocol_version().addr_dst.address[0],
                &t->socket().remote_endpoint().address().to_v6().to_bytes()[0],
                msg.protocol_version().addr_dst.address.size()
            );
        }
    
        /**
         * Encode the message.
         */
        msg.encode();

        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

void tcp_connection::send_addr_message(const protocol::network_address_t & addr)
{
    auto self(shared_from_this());
    
    /**
     * Post the operation onto the boost::asio::io_service.
     */
    io_service_.post(strand_.wrap([this, self, addr]()
    {
        do_send_addr_message(addr);
    }));
}

void tcp_connection::do_send_addr_message(
    const protocol::network_address_t & addr
    )
{
    if (m_seen_network_addresses.count(addr) == 0)
    {
        /**
         * Insert the seen address.
         */
        m_seen_network_addresses.insert(addr);
    
        if (auto t = m_tcp_transport.lock())
        {
            /**
             * Allocate the message.
             */
            message msg("addr");
            
            msg.protocol_addr().addr_list.push_back(addr);
            
            /**
             * Encode the message.
             */
            msg.encode();
            
            /**
             * Write the message.
             */
            t->write(msg.data(), msg.size());
        }
        else
        {
            stop();
        }
    }
}

void tcp_connection::do_send_tx_message(const transaction & tx)
{
    if (auto t = m_tcp_transport.lock())
    {
        /**
         * Allocate the message.
         */
        message msg("tx");

        /**
         * Set the tx.
         */
        msg.protocol_tx().tx = std::make_shared<transaction> (tx);
        
        log_debug(
            "TCP connection is sending tx " <<
            msg.protocol_tx().tx->get_hash().to_string().substr(0, 20) <<
            "."
        );

        /**
         * Encode the message.
         */
        msg.encode();
        
        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

void tcp_connection::send_getaddr_message()
{
    if (auto t = m_tcp_transport.lock())
    {
        /**
         * Allocate the message.
         */
        message msg("getaddr");
        
        /**
         * Encode the message.
         */
        msg.encode();
        
        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

void tcp_connection::send_ping_message()
{
    if (auto t = m_tcp_transport.lock())
    {
        /**
         * Allocate the message.
         */
        message msg("ping");
        
        /**
         * Encode the message.
         */
        msg.encode();
        
        log_debug(
            "TCP connection is sending ping, nonce = " <<
            msg.protocol_ping().nonce << "."
        );
        
        /**
         * Set the time that we have sent the ping message.
         */
        interval_ping_ = std::chrono::duration_cast<std::chrono::milliseconds> (
            std::chrono::system_clock::now().time_since_epoch()
        );
        
        /**
         * Clear the last pong interval.
         */
        interval_pong_ = interval_ping_;
        
        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

void tcp_connection::send_pong_message(const std::uint64_t & nonce)
{
    if (auto t = m_tcp_transport.lock())
    {
        /**
         * Allocate the message.
         */
        message msg("pong");
        
        /**
         * Set the nonce.
         */
        msg.protocol_pong().nonce = nonce;
        
        log_debug(
            "TCP connection is sending pong, nonce = " <<
            msg.protocol_pong().nonce << "."
        );
        
        /**
         * Encode the message.
         */
        msg.encode();
        
        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

void tcp_connection::send_getdata_message()
{
    if (auto t = m_tcp_transport.lock())
    {
        /**
         * Only send a getdata message if the remote node is a peer.
         */
        if (
            (m_protocol_version_services & protocol::operation_mode_peer)
            )
        {
            if (getdata_.size() > 0)
            {
                /**
                 * Allocate the message.
                 */
                message msg("getdata");
                
                /**
                 * Set the getdata.
                 */
                msg.protocol_getdata().inventory = getdata_;
                
                /**
                 * Clear the getdata.
                 */
                getdata_.clear();
                
                if (msg.protocol_getdata().inventory.size() == 1)
                {
                    log_info(
                        "TCP connection " << m_identifier << " is sending "
                        "getdata, count = 1, type = " <<
                        msg.protocol_getdata().inventory[0].type()
                    );
                }
                else
                {
                    log_info(
                        "TCP connection " << m_identifier << " is sending "
                        "getdata, count = " <<
                        msg.protocol_getdata().inventory.size() << "."
                    );
                }
                
                /**
                 * Encode the message.
                 */
                msg.encode();
                
                /**
                 * Write the message.
                 */
                t->write(msg.data(), msg.size());
            }
        }
    }
    else
    {
        stop();
    }
}

void tcp_connection::send_getheaders_message(
    const sha256 & hash_stop, const block_locator & locator
    )
{
    if (globals::instance().is_client_spv() == true)
    {
        if (
            m_identifier == globals::instance(
            ).spv_active_tcp_connection_identifier()
            )
        {
            if (auto t = m_tcp_transport.lock())
            {
                /**
                 * Allocate the message.
                 */
                message msg("getheaders");
                
                /**
                 * Set the getheaders.
                 */
                msg.protocol_getheaders().hash_stop = hash_stop;
                msg.protocol_getheaders().locator =
                    std::make_shared<block_locator> (locator)
                ;
                
                log_debug(
                    "TCP connection is sending getheaders, hash_stop = " <<
                    msg.protocol_getheaders().hash_stop.to_string().substr(
                    0, 8) << "."
                );

                /**
                 * Encode the message.
                 */
                msg.encode();
                
                auto self(shared_from_this());
                
                /**
                 * Starts the (SPV) getheaders timeout timer.
                 */
                timer_spv_getheader_timeout_.expires_from_now(
                    std::chrono::seconds(8)
                );
                timer_spv_getheader_timeout_.async_wait(strand_.wrap(
                    [this, self](boost::system::error_code ec)
                {
                    if (ec)
                    {
                        // ...
                    }
                    else
                    {
                        log_debug(
                            "TCP connection " << m_identifier << " (SPV) "
                            "getheaders timed out, stopping."
                        );
                        
                        /**
                         * Stop
                         */
                        do_stop();
                    }
                }));
    
                /**
                 * Write the message.
                 */
                t->write(msg.data(), msg.size());
            }
            else
            {
                stop();
            }
        }
    }
    else
    {
		if (
			m_identifier == globals::instance(
			).peer_headers_first_active_tcp_connection_identifier()
			)
   		{
            if (auto t = m_tcp_transport.lock())
            {
                /**
                 * Allocate the message.
                 */
                message msg("getheaders");
                
                /**
                 * Set the getheaders.
                 */
                msg.protocol_getheaders().hash_stop = hash_stop;
                msg.protocol_getheaders().locator =
                    std::make_shared<block_locator> (locator)
                ;
                
                log_debug(
                    "TCP connection is sending getheaders, hash_stop = " <<
                    msg.protocol_getheaders().hash_stop.to_string().substr(
                    0, 8) << "."
                );

                /**
                 * Encode the message.
                 */
                msg.encode();
                
                auto self(shared_from_this());

                /**
                 * Starts the (peer) getheaders timeout timer.
                 */
                timer_peer_getheader_timeout_.expires_from_now(
                    std::chrono::seconds(8)
                );
                timer_peer_getheader_timeout_.async_wait(strand_.wrap(
                    [this, self](boost::system::error_code ec)
                {
                    if (ec)
                    {
                        // ...
                    }
                    else
                    {
                        log_debug(
                            "TCP connection " << m_identifier << " (peer) "
                            "getheaders timed out, stopping."
                        );
                        
                        /**
                         * Stop
                         */
                        do_stop();
                    }
                }));

                /**
                 * Write the message.
                 */
                t->write(msg.data(), msg.size());
            }
            else
            {
                stop();
            }
        }
    }
}

void tcp_connection::send_sendheaders_message()
{
    if (auto t = m_tcp_transport.lock())
    {
        /**
         * Allocate the message.
         */
        message msg("sendheaders");

        log_debug(
            "TCP connection is sending sendheaders " <<
            msg.protocol_headers().headers.size() << "."
        );

        /**
         * Encode the message.
         */
        msg.encode();
        
        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

void tcp_connection::send_merkleblock_message(const block_merkle & merkleblock)
{
    if (auto t = m_tcp_transport.lock())
    {
        /**
         * Allocate the message.
         */
        message msg("merkleblock");

        /**
         * Set the merkleblock.
         */
        msg.protocol_merkleblock().merkleblock =
            std::make_shared<block_merkle> (merkleblock)
        ;
        
        log_debug(
            "TCP connection is sending merkleblock, tx's = " <<
            msg.protocol_merkleblock(
            ).merkleblock->transactions_matched().size() << "."
        );

        /**
         * Encode the message.
         */
        msg.encode();
        
        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

void tcp_connection::send_mempool_message()
{
    if (auto t = m_tcp_transport.lock())
    {
        /**
         * Allocate the message.
         */
        message msg("mempool");
        
        log_debug("TCP connection is sending mempool " << ".");

        /**
         * Encode the message.
         */
        msg.encode();
        
        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

std::weak_ptr<tcp_transport> & tcp_connection::get_tcp_transport()
{
    return m_tcp_transport;
}

const tcp_connection::direction_t & tcp_connection::direction() const
{
    return m_direction;
}

const std::uint32_t & tcp_connection::protocol_version() const
{
    return m_protocol_version;
}

const std::uint64_t & tcp_connection::protocol_version_services() const
{
    return m_protocol_version_services;
}

const std::uint64_t & tcp_connection::protocol_version_timestamp() const
{
    return m_protocol_version_timestamp;
}

const std::string & tcp_connection::protocol_version_user_agent() const
{
    return m_protocol_version_user_agent;
}

const std::int32_t & tcp_connection::protocol_version_start_height() const
{
    return m_protocol_version_start_height;
}

const protocol::network_address_t &
    tcp_connection::protocol_version_addr_src() const
{
    return m_protocol_version_addr_src;
}

const bool & tcp_connection::protocol_version_relay() const
{
    return m_protocol_version_relay;
}

void tcp_connection::set_on_probe(
    const std::function<void (const std::uint32_t &, const std::string &,
    const std::uint64_t &, const std::int32_t &)> & f
    )
{
    m_on_probe = f;
}

void tcp_connection::relay_inv(
    const inventory_vector & inv, const data_buffer & buffer
    )
{
    std::lock_guard<std::recursive_mutex> l1(stack_impl::mutex());
    
    /**
     * Expire old relay messages.
     */
    while (
        globals::instance().relay_inv_expirations().size() > 0 &&
        globals::instance().relay_inv_expirations().front().first < std::time(0)
        )
    {
        globals::instance().relay_invs().erase(
            globals::instance().relay_inv_expirations().front().second
        );
        
        globals::instance().relay_inv_expirations().pop_front();
    }

    /**
     * Save original serialized message so newer versions are preserved.
     */
    globals::instance().relay_invs().insert(std::make_pair(inv, buffer));
    
    globals::instance().relay_inv_expirations().push_back(
        std::make_pair(std::time(0) + 15 * 60, inv)
    );
    
    log_debug(
        "TCP connection is relaying inv message, command = " <<
        inv.command() << "."
    );
    
    /**
     * Allocate the message.
     */
    message msg(inv.command(), buffer);

    /**
     * Encode the message.
     */
    msg.encode();

    /**
     * Check if this is related to a transaction.
     */
    auto is_tx_related = inv.command() == "tx";
    
    if (m_protocol_version_relay == false && is_tx_related)
    {
        /**
         * Broadcast the message via bip0037 rules.
         */
         stack_impl_.get_tcp_connection_manager()->broadcast_bip0037(
            msg.data(), msg.size()
         );
    }
    else
    {
        /**
         * Broadcast the message to "all" connected peers.
         */
        stack_impl_.get_tcp_connection_manager()->broadcast(
            msg.data(), msg.size()
        );
    }
}

bool tcp_connection::handle_message(message & msg)
{
    if (m_state == state_stopped)
    {
        log_debug(
            "TCP connection got message while stopped, returning."
        );
        
        return false;
    }
    
    std::lock_guard<std::recursive_mutex> l1(stack_impl::mutex());

    if (msg.header().command == "verack")
    {
    	timer_version_timeout_.cancel();
        
    	/**
         * If we are operating in headers first chain sync mode send a
         * sendheaders message to inform the remote peer we prefer blocks
         * advertised as headers instead of inv's.
         */
        if (
        	globals::instance().peer_use_headers_first_chain_sync() == true &&
         	globals::instance().operation_mode() ==
         	protocol::operation_mode_peer
            )
        {
            send_sendheaders_message();
        }
    }
    else if (msg.header().command == "version")
    {
        /**
         * Check that we didn't connection to ourselves.
         */
        if (msg.protocol_version().nonce == globals::instance().version_nonce())
        {
            log_debug(
                "TCP connection got message from ourselves, closing connection."
            );
            
            /**
             * Stop
             */
            do_stop();
            
            return false;
        }
        else
        {
            /**
             * If the protocol version is zero we need to send a verack and a
             * version message.
             */
            if (m_protocol_version == 0)
            {
                /**
                 * Set the protocol version.
                 */
                m_protocol_version = std::min(
                    msg.protocol_version().version,
                    static_cast<std::uint32_t> (protocol::version)
                );
                
                /**
                 * Check for the minimum protocol version.
                 */
                if (m_protocol_version < protocol::minimum_version)
                {
                    log_info(
                        "TCP connection got old protocol version = " <<
                        m_protocol_version << ", calling stop."
                    );
                    
                    /**
                     * Stop
                     */
                    do_stop();
                    
                    return false;
                }

                /**
                 * Set the protocol version services.
                 */
                m_protocol_version_services = msg.protocol_version().services;
                
                /**
                 * If we are an (SPV) node drop connections that do not
                 * support bloom filters.
                 */
                if (globals::instance().is_client_spv() == true)
                {
                    if (
                        !(m_protocol_version_services &
                        protocol::operation_mode_bloom)
                        )
                    {
                        log_info(
                            "TCP connection " << m_identifier << " no bloom "
                            "support in services, calling stop."
                        );
                        
                        /**
                         * Stop
                         */
                        do_stop();
                        
                        return false;
                    }
                }
                
                /**
                 * If we are a (peer) node drop connections that do not
                 * support bloom filters during chain synchronization.
                 * @note This is done because chances are they have better
                 * routines for handling headers first chain synchronization.
                 */
                if (
                	globals::instance(
                    ).peer_use_headers_first_chain_sync() == true &&
                    utility::is_initial_block_download() == true
                    )
                {
                    if (
                        !(m_protocol_version_services &
                        protocol::operation_mode_bloom)
                        )
                    {
                        log_info(
                            "TCP connection " << m_identifier << " no bloom "
                            "support in services, calling stop."
                        );
                        
                        /**
                         * Stop
                         */
                        do_stop();
                        
                        return false;
                    }
                }
                
                /**
                 * Set the protocol version timestamp.
                 */
                m_protocol_version_timestamp =
                    msg.protocol_version().timestamp
                ;
                
                /**
                 * Set the protocol version user agent.
                 */
                m_protocol_version_user_agent =
                    msg.protocol_version().user_agent
                ;
                
                /**
                 * Check for old/banned user agents.
                 */
                if (
                    m_protocol_version_user_agent.find("Cornell") !=
                    std::string::npos
                    )
                {
                    log_info(
                        "TCP connection " << m_identifier << ", user agent " <<
                        "= " << m_protocol_version_user_agent << ","
                        " banning node."
                    );
                    
                    /**
                     * Set the Denial-of-Service score for the connection.
                     */
                    set_dos_score(m_dos_score + 100);
                    
                    return false;
                }
                
                /**
                 * Set the protocol version start height.
                 */
                m_protocol_version_start_height =
                    msg.protocol_version().start_height
                ;
                
                log_debug(
                    "TCP connection " << m_identifier <<
                    " got version = " << m_protocol_version << "."
                );

                /**
                 * Set the protocol version source address.
                 */
                m_protocol_version_addr_src = msg.protocol_version().addr_src;
                
                /**
                 * Set the protocol version relay.
                 */
                m_protocol_version_relay = msg.protocol_version().relay == 1;

                /**
                 * Add the timestamp from the peer.
                 */
                time::instance().add(
                    msg.protocol_version().addr_src,
                    msg.protocol_version().timestamp
                );
                
                /**
                 * Send a verack message.
                 */
                send_verack_message();

                /**
                 * If this is an incoming connection we must send a version
                 * message. If this is an outgoing connection we send both an
                 * getaddr and addr message.
                 */
                if (m_direction == direction_incoming)
                {
                    if (auto transport = m_tcp_transport.lock())
                    {
                        /**
                         * If the remote node is a peer add it to the address
                         * manager.
                         */
                        if (
                            (m_protocol_version_services &
                            protocol::operation_mode_peer)
                            )
                        {
                            /**
                             * If the source address in the version message
                             * matches the address as seen by us inform the
                             * address_manager.
                             */
                            if (
                                protocol::network_address_t::from_endpoint(
                                transport->socket().remote_endpoint()) ==
                                msg.protocol_version().addr_src
                                )
                            {
                                /**
                                 * Add to the address_manager.
                                 */
                                stack_impl_.get_address_manager()->add(
                                    msg.protocol_version().addr_src,
                                    msg.protocol_version().addr_src
                                );

                                /**
                                 * Mark as good.
                                 */
                                stack_impl_.get_address_manager()->mark_good(
                                    msg.protocol_version().addr_src
                                );
                            }
                        }
                        
                        auto self(shared_from_this());
                        
                        /**
                         * Start the version timeout timer.
                         */
                        timer_version_timeout_.expires_from_now(
                            std::chrono::seconds(8)
                        );
                        timer_version_timeout_.async_wait(
                            strand_.wrap(
                                [this, self](boost::system::error_code ec)
                                {
                                    if (ec)
                                    {
                                        // ...
                                    }
                                    else
                                    {
                                        log_error(
                                            "TCP connection (version) timed "
                                            "out, calling stop."
                                        );
                                    
                                        /**
                                         * The connection has timed out, call
                                         * stop.
                                         */
                                        do_stop();
                                    }
                                }
                            )
                        );
                        
                        /**
                         * Send a version message.
                         */
                        send_version_message();
                    }
                }
                else if (m_direction == direction_outgoing)
                {
                    if (auto transport = m_tcp_transport.lock())
                    {
                        /**
                         * Inform the address_manager.
                         */
                        stack_impl_.get_address_manager()->mark_good(
                            protocol::network_address_t::from_endpoint(
                            transport->socket().remote_endpoint())
                        );
                    }
                    
                    if (m_probe_only == true)
                    {
                        /**
                         * Callback
                         */
                        if (m_on_probe)
                        {
                            m_on_probe(
                                m_protocol_version,
                                m_protocol_version_user_agent,
                                m_protocol_version_services,
                                m_protocol_version_start_height
                            );
                        }
                        
                        /**
                         * We have confirmed the peer is valid, stop the
                         * connection.
                         */
                        stop();

                        return true;
                    }
                    else
                    {
                        /**
                         * Set our public ip address for this connection as
                         * reported in the version message.
                         */
                        m_address_public =
                            msg.protocol_version().addr_dst.ipv4_mapped_address()
                        ;
                        
                        /**
                         * Set our public ip address for this connection as
                         * reported in the version message into the global
                         * variables.
                         */
                        globals::instance().set_address_public(
                            m_address_public
                        );

                        log_debug(
                            "TCP connection learned our public ip address (" <<
                            m_address_public.to_string() << ") from "
                            "version message."
                        );
                        
                        if (utility::is_initial_block_download() == false)
                        {
                            /**
                             * If we are a peer advertise our address.
                             */
                            if (
                                globals::instance().operation_mode() ==
                                protocol::operation_mode_peer
                                )
                            {
                                /**
                                 * Send an addr message to advertise our
                                 * address only.
                                 */
                                send_addr_message(true);
                            }
                        }
                        
                        /**
                         * Only send a getaddr message if we have less than
                         * 1000 peers.
                         */
                        if (stack_impl_.get_address_manager()->size() < 1000)
                        {
                            /**
                             * Send a getaddr message to get more addresses.
                             */
                            send_getaddr_message();
                            
                            /**
                             * Set that we just sent a getaddr message.
                             */
                            m_sent_getaddr = true;
                        }
                    }
                }
            }

            /**
             * If we are an (SPV) node set this connection as the active
             * tcp_connection.
             */
            if (globals::instance().is_client_spv() == true)
            {
                globals::instance(
                    ).set_spv_active_tcp_connection_identifier(m_identifier
                );
            }
            
            /**
             * If we are an (SPV) node send a filterfload message before
             * sending a getheaders or getblocks message.
             */
            if (globals::instance().is_client_spv() == true)
            {
                /**
                 * Send the filter load message.
                 */
                send_filterload_message(
                    *globals::instance().spv_transaction_bloom_filter()
                );
            }
            
            /**
             * If we are an (peer) node set this connection as the active
             * tcp_connection.
             */
            if (globals::instance().peer_use_headers_first_chain_sync() == true)
            {
                globals::instance(
                    ).set_peer_headers_first_active_tcp_connection_identifier(
                    m_identifier
                );
            }
            
            /**
             * Send BIP-0035 mempool message.
             */
            if (globals::instance().is_client_spv() == true)
            {
                if (
                    m_direction == direction_outgoing &&
                    utility::is_spv_initial_block_download() == false
                    )
                {
                    send_mempool_message();
                }
            }
            else
            {
                if (
                    m_direction == direction_outgoing &&
                    utility::is_initial_block_download() == false
                    )
                {
                	/**
                     * If we are a (peer) node using headers first first chain
                     * synchronization mode do not send a mempool message until
                     * we have at least as many blocks as the median of all
                     * connected (peer) nodes.
                     */
                	if (
                 	   globals::instance().peer_use_headers_first_chain_sync(
                        ) == true
                        )
                 	{
                  		if (
                      		stack_impl_.local_block_count(
                          	) >= stack_impl_.peer_block_count()
                        	)
                    	{
                     		send_mempool_message();
                     	}
                  	}
                   	else
                    {
                    	send_mempool_message();
                    }
                }
            }
            
            /**
             * If we are an (SPV) client send a getheaders message otherwise
             * if we have never sent a getblocks message or if our best
             * block is the genesis block send getblocks.
             */
            if (globals::instance().is_client_spv() == true)
            {
                if (globals::instance().spv_use_getblocks() == false)
                {
                    /**
                     * Get the block_locator hashes.
                     */
                    const auto & block_locator_hashes =
                        globals::instance().spv_block_locator_hashes()
                    ;
                    
                    /**
                     * Allocate the block_locator with the last and
                     * first hash.
                     */
                    block_locator locator(block_locator_hashes);
                    
                    /**
                     * Send the getheaders message.
                     */
                    send_getheaders_message(sha256(), locator);
                    
                    auto self(shared_from_this());
                    
                    /**
                     * Start the getheaders timer.
                     */
                    timer_getheaders_.expires_from_now(
                        std::chrono::seconds(8)
                    );
                    timer_getheaders_.async_wait(
                        strand_.wrap(
                        std::bind(&tcp_connection::do_send_getheaders, self,
                        std::placeholders::_1))
                    );
                }
                else
                {
                    /**
                     * Get the block_locator hashes.
                     */
                    const auto & block_locator_hashes =
                        globals::instance().spv_block_locator_hashes()
                    ;
                    
                    /**
                     * Allocate the block_locator with the last and
                     * first hash.
                     */
                    block_locator locator(block_locator_hashes);
                    
                    /**
                     * Send the getblocks message.
                     */
                    send_getblocks_message(sha256(), locator);
                }
            }
            else if (
            	globals::instance().peer_use_headers_first_chain_sync() == true
                )
            {
            	/**
                 * Send a bip-0130 sendheaders message.
                 */
            	send_sendheaders_message();
            
                /**
                 * Get the block_locator hashes.
                 */
                const auto & block_locator_hashes =
                    globals::instance(
                    ).peer_headers_first_block_locator_hashes()
                ;
            
                /**
                 * Allocate the block_locator with the last and
                 * first hash.
                 */
                block_locator locator(block_locator_hashes);
            
                /**
                 * Send the getheaders message.
                 */
                send_getheaders_message(sha256(), locator);
                
                auto self(shared_from_this());
            
                /**
                 * Start the getheaders timer.
                 */
                timer_getheaders_.expires_from_now(
                    std::chrono::seconds(8)
                );
                timer_getheaders_.async_wait(
                    strand_.wrap(
                    std::bind(&tcp_connection::do_send_getheaders, self,
                    std::placeholders::_1))
                );
            }
            else if (
                did_send_getblocks_ == false ||
                (constants::test_net == true &&
                stack_impl::get_block_index_best()->get_block_hash() ==
                block::get_hash_genesis_test_net()) ||
                (constants::test_net == false &&
                stack_impl::get_block_index_best()->get_block_hash() ==
                block::get_hash_genesis())
                )
            {
                /**
                 * When using headers first chain synchronization we
                 * do not need to ever send a getblocks message.
                 */
                if (
                    globals::instance(
                    ).peer_use_headers_first_chain_sync() == true
                    )
                {
                    // ...
                }
                else
                {
                    did_send_getblocks_ = true;
                    
                    log_debug(
                        "Connection is sending getblocks, best block = " <<
                        stack_impl::get_block_index_best()->get_block_hash(
                        ).to_string().substr(0, 20) << "."
                    );
                    
                    send_getblocks_message(
                        stack_impl::get_block_index_best(), sha256()
                    );
                }
            }
        
            log_debug(
                "Connection received version message, version = " <<
                msg.protocol_version().version << ", start height = " <<
                msg.protocol_version().start_height << ", dest = " <<
                msg.protocol_version().addr_dst.ipv4_mapped_address(
                ).to_string() << ", src = " << msg.protocol_version(
                ).addr_src.ipv4_mapped_address().to_string() << "."
            );
            
            /**
             * Update the peer block counts.
             */
            globals::instance().peer_block_counts().input(
                m_protocol_version_start_height
            );
        }
    }
    else if (msg.header().command == "buversion")
    {
        // ...
    }
    else if (msg.header().command == "addr")
    {
        if (msg.protocol_addr().count > 1000)
        {
            /**
             * Set the Denial-of-Service score for the connection.
             */
            set_dos_score(m_dos_score + 20);
        }
        else
        {
            log_debug(
                "TCP transport got " << msg.protocol_addr().count <<
                " addresses."
            );

            /**
             * Use the peer adjusted time.
             */
            auto now = time::instance().get_adjusted();
            
            auto since = now - 10 * 60;
        
            auto addr_list = msg.protocol_addr().addr_list;
            
            for (auto & i : addr_list)
            {
                if (i.timestamp <= 100000000 || i.timestamp > now + 10 * 60)
                {
                    i.timestamp = static_cast<std::uint32_t> (
                        now - 5 * 24 * 60 * 60
                    );
                }
                
                /**
                 * Insert the seen address.
                 */
                m_seen_network_addresses.insert(i);

                log_debug(
                    "TCP connection got addr.address = " <<
                    i.ipv4_mapped_address().to_string() <<
                    ", addr.port = " << i.port <<
                    ", is_local = " << i.is_local() <<
                    ", timestamp = " <<
                    ((std::time(0) - i.timestamp) / 60) << " mins."
                );
                
                if (i.is_local() == false)
                {
                    if (
                        i.timestamp > since && m_sent_getaddr == false &&
                        addr_list.size() <= 10
                        )
                    {
                        static sha256 hash_salt;
                        
                        if (hash_salt == 0)
                        {
                            hash_salt = hash::sha256_random();
                        }
                        
                        std::uint64_t hash_addr = i.get_hash();
                        
                        sha256 hash_random =
                            hash_salt ^ (hash_addr << 32) ^
                            ((std::time(0) + hash_addr) / (24 * 60 * 60))
                        ;
                        
                        hash_random = sha256::from_digest(&hash::sha256d(
                            hash_random.digest(), sha256::digest_length)[0]
                        );
                        
                        std::multimap<
                            sha256, std::shared_ptr<tcp_connection>
                        > mixes;
                        
                        auto tcp_connections =
                            stack_impl_.get_tcp_connection_manager(
                            )->tcp_connections()
                        ;
                        
                        for (auto & i2 : tcp_connections)
                        {
                            if (auto t = i2.second.lock())
                            {
                                std::uint32_t ptr_uint32;
                                
                                auto ptr_transport = t.get();
                                
                                std::memcpy(
                                    &ptr_uint32, &ptr_transport,
                                    sizeof(ptr_uint32)
                                );
                                
                                sha256 hash_key = hash_random ^ ptr_uint32;
                                
                                hash_key = sha256::from_digest(&hash::sha256d(
                                    hash_key.digest(), sha256::digest_length)[0]
                                );
                            
                                mixes.insert(std::make_pair(hash_key, t));
                            }
                        }
                        
                        int relay_nodes = 8;
                        
                        for (
                            auto it = mixes.begin();
                            it != mixes.end() && relay_nodes-- > 0; ++it
                            )
                        {
                            if (it->second)
                            {
                                it->second->send_addr_message(i);
                            }
                        }
                    }
                    
                    /**
                     * Set to false to disable learning of new peers.
                     */
                    if (true)
                    {
                        /**
                         * Add the address to the address_manager.
                         */
                        stack_impl_.get_address_manager()->add(
                            i, msg.protocol_version().addr_src, 60
                        );
                    }
                }
            }
            
            if (stack_impl_.get_address_manager()->get_addr().size() < 1000)
            {
                /**
                 * Set that we have not sent a getaddr message.
                 */
                m_sent_getaddr = false;
            }
        }
    }
    else if (msg.header().command == "getaddr")
    {
        /**
         * Send an addr message.
         */
        send_addr_message();
    }
    else if (msg.header().command == "reject")
    {
        log_info("TCP connection " << m_identifier << " got reject message.");
        
        /**
         * Callback
         */
        stack_impl_.on_reject_message(msg);
    }
    else if (msg.header().command == "ping")
    {
        log_debug(
            "TCP connection got ping, nonce = " <<
            msg.protocol_ping().nonce << ", sending pong."
        );
        
        /**
         * Send a pong message with the nonce.
         */
        send_pong_message(msg.protocol_ping().nonce);
    }
    else if (msg.header().command == "pong")
    {
        log_debug(
            "TCP connection got pong, nonce = " <<
            msg.protocol_pong().nonce << "."
        );
        
        /**
         * Cancel the ping timeout timer.
         */
        timer_ping_timeout_.cancel();
        
        /**
         * Set the time that we have received the pong message.
         */
        interval_pong_ = std::chrono::duration_cast<std::chrono::milliseconds> (
            std::chrono::system_clock::now().time_since_epoch()
        );
    }
    else if (msg.header().command == "inv")
    {
        /**
         * If true we must send an SPV getblocks message AFTER sending
         * a getdata message on the current block.
         */
        auto should_send_spv_getblocks = false;
        
        /**
         * The (SPV) transaction hashes.
         */
        std::vector<sha256> spv_hashes_tx;
        
        if (msg.protocol_inv().inventory.size() > protocol::max_inv_size)
        {
            /**
             * Set the Denial-of-Service score for the connection.
             */
            set_dos_score(m_dos_score + 20);
        }
        else
        {
            if (globals::instance().is_client_spv() == false)
            {
                /**
                 * Find the last block in the inventory vector.
                 */
                auto last_block = static_cast<std::uint32_t> (-1);
                
                for (auto i = 0; i < msg.protocol_inv().inventory.size(); i++)
                {
                    if (
                        msg.protocol_inv().inventory[
                        msg.protocol_inv().inventory.size() - 1 - i].type() ==
                        inventory_vector::type_msg_block
                        )
                    {
                        last_block = static_cast<std::uint32_t> (
                            msg.protocol_inv().inventory.size() - 1 - i
                        );
                        
                        break;
                    }
                }
                
                /**
                 * Open the transaction database for reading.
                 */
                db_tx tx_db("r");
                
                auto index = 0;
                
                auto inventory = msg.protocol_inv().inventory;

                for (auto & i : inventory)
                {
                    insert_inventory_vector_seen(i);
                
                    auto already_have = inventory_vector::already_have(
                        tx_db, i
                    );
                    
                    if (globals::instance().debug() && false)
                    {
                        log_debug(
                            "Connection got inv = " << i.to_string() <<
                            (already_have ? " have" : " new") << "."
                        );
                    }
                    
                    if (already_have == false)
                    {
#define BCASH_STRESS_TEST 1
#if (defined BCASH_STRESS_TEST && BCASH_STRESS_TEST)
						if (
							globals::instance(
                            ).peer_headers_first_heights_and_hashes(
                            ).size() < stack_impl_.peer_block_count()
                        	)
                        {
                            if (i.type() == inventory_vector::type_msg_tx)
                            {
                                continue;
                            }
						}
#else
                    	/**
                         * If we are synchronizing the block chain headers
                         * first ignore all inventory_vector::type_msg_tx until
                         * we have downloaded almost all of the block chain.
                         */
                    	if (
							globals::instance().operation_mode() ==
                            protocol::operation_mode_peer &&
                     	   	globals::instance(
                            ).peer_use_headers_first_chain_sync() == true &&
                        	(utility::is_initial_block_download() == true ||
                            stack_impl_.local_block_count() <
                            m_protocol_version_start_height)
                            )
                     	{
                            if (i.type() == inventory_vector::type_msg_tx)
                            {
                                continue;
                            }
                        }
#endif // BCASH_STRESS_TEST
                        /**
                         * Ask for the data.
                         */
                        getdata_.push_back(i);
                    }
                    else if (
                        i.type() == inventory_vector::type_msg_block &&
                        globals::instance().orphan_blocks().count(i.hash())
                        )
                    {
                        /**
                         * When using headers first chain synchronization we
                         * do not need to ever send a getblocks message.
                         */
                        if (
                            globals::instance(
                            ).peer_use_headers_first_chain_sync() == true
                            )
                        {
                            // ...
                        }
                        else
                        {
                            send_getblocks_message(
                                stack_impl::get_block_index_best(),
                                utility::get_orphan_root(
                                globals::instance().orphan_blocks()[i.hash()])
                            );
                        }
                    }
                    else if (index == last_block)
                    {
                        /**
                         * When using headers first chain synchronization we
                         * do not need to ever send a getblocks message.
                         */
                        if (
                        	globals::instance(
                            ).peer_use_headers_first_chain_sync() == true
                            )
                        {
                        	// ...
                        }
                        else
                        {
                            /**
                             * In case we are on a very long side-chain, it is
                             * possible that we already have the last block in
                             * an inv bundle sent in response to getblocks. Try
                             * to detect this situation and push another
                             * getblocks to continue.
                             */
                            send_getblocks_message(
                                globals::instance().block_indexes()[i.hash()],
                                sha256()
                            );
                            
                            if (globals::instance().debug() && false)
                            {
                                log_debug(
                                    "Connection is forcing getblocks "
                                    "request " << i.to_string() << "."
                                );
                            }
                        }
                    }
                    
                    /**
                     * Inform the wallet manager.
                     */
                    wallet_manager::instance().on_inventory(i.hash());
                    
                    index++;
                }
            }
            else
            {
                /**
                 * Find the last block in the inventory vector.
                 */
                auto last_block = static_cast<std::uint32_t> (-1);

                /**
                 * If the type is of inventory_vector::type_msg_block
                 * set it to
                 * inventory_vector::type_msg_filtered_block_nonstandard
                 * so the remote node does not send blocks in response
                 * to our getdata requests but instead merkleblocks.
                 */
                for (auto & i : msg.protocol_inv().inventory)
                {
                    if (i.type() == inventory_vector::type_msg_block)
                    {
                        i.set_type(
                            inventory_vector::type_msg_filtered_block
                        );
                    }
                }
                
                for (auto i = 0; i < msg.protocol_inv().inventory.size(); i++)
                {
                    if (
                        msg.protocol_inv().inventory[
                        msg.protocol_inv().inventory.size() - 1 - i].type() ==
                        inventory_vector::type_msg_filtered_block
                        )
                    {
                        last_block = static_cast<std::uint32_t> (
                            msg.protocol_inv().inventory.size() - 1 - i
                        );
                        
                        break;
                    }
                }
                
                auto index = 0;
                
                auto inventory = msg.protocol_inv().inventory;
                
                for (auto & i : inventory)
                {
                    insert_inventory_vector_seen(i);
   
                    auto already_have = inventory_vector::spv_already_have(i);
                    
                    log_debug(
                        "SPV inv already_have = " << already_have
                    );

                    if (already_have == false)
                    {
                        /**
                         * Filter out INV's that (SPV) clients do not need to
                         * know about.
                         */
                        if (globals::instance().spv_use_getblocks() == true)
                        {
                            if (
                                i.type() ==
                                inventory_vector::type_msg_filtered_block
                                )
                            {
                                /**
                                 * Ask for the data.
                                 */
                                getdata_.push_back(i);
                            }
                            else if (i.type() == inventory_vector::type_msg_tx)
                            {
                                /**
                                 * Ask for the data.
                                 */
                                getdata_.push_back(i);
                                
                                /**
                                 * Inform the wallet manager.
                                 */
                                wallet_manager::instance().on_inventory(
                                    i.hash()
                                );
                            }
                         }
                    }
                    else if (index == last_block)
                    {
                        // ...
                    }
                    
                    index++;
                }
            }
        }

        /**
         * Set the first and last hash.
         */
        std::vector<sha256> hashes;
        
        if (globals::instance().is_client_spv() == true)
        {
            /**
             * If we got 500 block hashes request the next 500 block hashes.
             */
            if (getdata_.size() >= 500)
            {
                /**
                 * Check if we already have the first or last hash.
                 */
                auto already_have = inventory_vector::spv_already_have(
                    getdata_.front()
                );
                
                already_have |= inventory_vector::spv_already_have(
                    getdata_.back()
                );
                
                if (already_have == false)
                {
                    should_send_spv_getblocks = true;
                    
                    /**
                     * Get the first block header.
                     */
                    auto hash_first = getdata_.front().hash();
                    
                    /**
                     * Get the last block header.
                     */
                    auto hash_last = getdata_.back().hash();
                    
                    hashes.push_back(hash_last);
                    hashes.push_back(hash_first);
                }
            }
        }
        
        /**
         * If we have some getdata send it now.
         */
        send_getdata_message();
        
        /**
         * If we should send SPV getblocks do so now.
         */
        if (
            globals::instance().is_client_spv() == true &&
            should_send_spv_getblocks == true
            )
        {
            /**
             * Allocate the block_locator with the last and
             * first hash.
             */
            block_locator locator(hashes);

            /**
             * Send the getblocks message.
             */
            send_getblocks_message(sha256(), locator);
        }
    }
    else if (msg.header().command == "getdata")
    {
        /**
         * If we are a peer handle the getdata message.
         */
        if (
            globals::instance().operation_mode() ==
            protocol::operation_mode_peer
            )
        {
            if (msg.protocol_getdata().count > protocol::max_inv_size)
            {
                log_debug(
                    "TCP connection received getdata, size = " <<
                    msg.protocol_getdata().count << "."
                );
                
                /**
                 * Set the Denial-of-Service score for the connection.
                 */
                set_dos_score(m_dos_score + 20);
            }
            else
            {
                if (msg.protocol_getdata().count != 1)
                {
                    log_debug(
                        "TCP connection received getdata, size = " <<
                        msg.protocol_getdata().count << "."
                    );
                }
                
                auto inventory = msg.protocol_getdata().inventory;
                
                for (auto & i : inventory)
                {
                    if (msg.protocol_getdata().count == 1)
                    {
                        log_debug(
                            "TCP connection received getdata for " <<
                            i.to_string() << "."
                        );
                    }
                    
                    if (
                        i.type() == inventory_vector::type_msg_block ||
                        i.type() ==
                        inventory_vector::type_msg_filtered_block
                        )
                    {
                        /**
                         * Find the block.
                         */
                        auto it = globals::instance().block_indexes().find(
                            i.hash()
                        );
                        
                        if (it != globals::instance().block_indexes().end())
                        {
                            /**
                             * Allocate the block.
                             */
                            block blk;
                            
                            /**
                             * Read the block from disk.
                             */
                            blk.read_from_disk(it->second);
                            
                            if (i.type() == inventory_vector::type_msg_block)
                            {
                                /**
                                 * Send the block message.
                                 */
                                do_send_block_message(blk);
                            }
                            else
                            {
                                /**
                                 * Check if we have a BIP-0037 bloom filter.
                                 */
                                if (transaction_bloom_filter_)
                                {
                                    /**
                                     * Create the block_merkle.
                                     */
                                    block_merkle merkle_block(
                                        blk, *transaction_bloom_filter_
                                    );
                                    
                                    /**
                                     * Send the merkleblock message.
                                     */
                                    send_merkleblock_message(merkle_block);
                                    
                                    for (
                                        auto & i :
                                        merkle_block.transactions_matched()
                                        )
                                    {
                                        for (auto & j : blk.transactions())
                                        {
                                            if (i.second == j.get_hash())
                                            {
                                                /**
                                                 * Send the tx message.
                                                 */
                                                send_tx_message(j);
                                            }
                                        }
                                    }
                                }
                            }

                            /**
                             * Trigger them to send a getblocks request for the
                             * next batch of inventory.
                             */
                            if (i.hash() == m_hash_continue)
                            {
                                /**
                                 * Send latest proof-of-work block to allow the
                                 * download node to accept as orphan.
                                 */
                                std::vector<sha256> block_hashes;
                                
                                /**
                                 * Insert the (previous) best block index's
                                 * hash.
                                 */
                                block_hashes.push_back(
                                    utility::get_last_block_index(
                                    stack_impl::get_block_index_best()
                                    )->get_block_hash()
                                );
               
                                /**
                                 * Send an inv message.
                                 */
                                do_send_inv_message(
                                    inventory_vector::type_msg_block,
                                    block_hashes
                                );
                                
                                /**
                                 * Set the hash continue to null.
                                 */
                                m_hash_continue = 0;
                            }
                        }
                    }
                    else if (i.is_know_type())
                    {
                        /**
                         * Send stream from relay memory.
                         */
                        auto did_send = false;
                        
                        auto it = globals::instance().relay_invs().find(i);
                        
                        if (it != globals::instance().relay_invs().end())
                        {
                            /**
                             * Send the relayed inv message.
                             */
                            do_send_relayed_inv_message(
                                i, data_buffer(it->second.data(),
                                it->second.size())
                            );
                            
                            did_send = true;
                        }
                        
                        if (did_send == false)
                        {
                            if (i.type() == inventory_vector::type_msg_tx)
                            {
                                if (
                                    transaction_pool::instance().exists(
                                    i.hash())
                                    )
                                {
                                    auto tx = transaction_pool::instance(
                                        ).lookup(i.hash()
                                    );

                                    /**
                                     * Send the tx message.
                                     */
                                    send_tx_message(tx);
                                }
                            }
                        }
                    }
                    
                    /**
                     * Inform the wallet manager.
                     */
                    wallet_manager::instance().on_inventory(i.hash());
                }
            }
        }
        else
        {
            log_info(
                "TCP connection (operation mode client) is dropping "
                "getdata message."
            );
        }
    }
    else if (msg.header().command == "getblocks")
    {
        /**
         * If we are a peer with an up-to-date blockchain handle the
         * getblocks message.
         */
        if (
            utility::is_initial_block_download() == false &&
            globals::instance().operation_mode() ==
            protocol::operation_mode_peer
            )
        {
            /**
             * Find the last block the sender has in the main chain.
             */
            auto index = block_locator(
                msg.protocol_getblocks().hashes
            ).get_block_index();
            
            /**
             * Send the rest of the chain.
             */
            if (index)
            {
                index = index->block_index_next();
            }
            
            /**
             * We send 500 block hashes.
             */
            enum { default_blocks = 500 };
            
            /**
             * The limit on the number of blocks to send.
             */
            std::int16_t limit = default_blocks;

            log_debug(
                "TCP connection getblocks " <<
                (index ? index->height() : -1) << " to " <<
                msg.protocol_getblocks().hash_stop.to_string(
                ).substr(0, 20) << " limit " << limit << "."
            );
            
            /**
             * The block hashes to send.
             */
            std::vector<sha256> block_hashes;
            
            for (; index; index = index->block_index_next())
            {
                if (
                    index->get_block_hash() ==
                    msg.protocol_getblocks().hash_stop
                    )
                {
                    log_debug(
                        "TCP connection getblocks stopping at " <<
                        index->height() << " " <<
                        index->get_block_hash().to_string().substr(0, 20)
                        << "."
                    );
                    
                    /**
                     * Tell the downloading node about the latest block.
                     */
                    if (
                        msg.protocol_getblocks().hash_stop !=
                        globals::instance().hash_best_chain()
                        )
                    {
                        /**
                         * Insert the block hash.
                         */
                        block_hashes.push_back(
                            globals::instance().hash_best_chain()
                        );
                    }
                    
                    break;
                }
                
                /**
                 * Insert the block hash.
                 */
                block_hashes.push_back(index->get_block_hash());
                
                if (--limit <= 0)
                {
                    /**
                     * When this block is requested, we'll send an inv
                     * that'll make them getblocks the next batch of
                     * inventory.
                     */
                    log_debug(
                        "TCP connection getblocks stopping at limit " <<
                        index->height() << " " <<
                        index->get_block_hash().to_string().substr(
                        0, 20) << "."
                    );

                    /**
                     * Set the hash continue.
                     */
                    m_hash_continue = index->get_block_hash();
                    
                    break;
                }
            }

            if (block_hashes.size() > 0)
            {
                /**
                 * Send an inv message with the block hashes.
                 */
                do_send_inv_message(
                    inventory_vector::type_msg_block, block_hashes
                );
            }
        }
        else
        {
            log_debug(
                "TCP connection (operation mode client or initial download)"
                " is dropping getblocks message."
            );
        }
    }
    else if (msg.header().command == "getheaders")
    {
        log_debug("Got getheaders");
        
        /**
         * Do not send headers when blockchain synchronization is in progress.
         */
        if (utility::is_initial_block_download() == false)
        {
            const auto & locator = msg.protocol_getheaders().locator;
            
            block_index * index = 0;
            
            if (locator && locator->is_null())
            {
                auto it = globals::instance().block_indexes().find(
                    msg.protocol_getheaders().hash_stop
                );
                
                if (it == globals::instance().block_indexes().end())
                {
                    return true;
                }
                
                index = it->second;
            }
            else
            {
                index = locator->get_block_index();
                
                if (index)
                {
                    index = index->block_index_next();
                }
            }

            std::vector<block> headers;
            
            std::int16_t limit = 2000;
            
            log_debug(
                "TCP connection getheaders " << (index ? index->height() : -1) <<
                " to " <<
                msg.protocol_getheaders().hash_stop.to_string().substr(0, 8) << "."
            );

            for (; index; index = index->block_index_next())
            {
                headers.push_back(index->get_block_header());
                
                if (
                    --limit <= 0 ||
                    index->get_block_hash() == msg.protocol_getheaders().hash_stop
                    )
                {
                    break;
                }
            }
            
            /**
             * Send headers message.
             */
            send_headers_message(headers);
            
            /**
             * Set the hash of the best header we sent.
             */
            m_hash_best_block_header_sent =
                index ? index->get_block_hash() :
                stack_impl::get_block_index_best()->get_block_hash()
            ;
        }
    }
    else if (msg.header().command == "headers")
    {
        log_debug("Got headers = " << msg.protocol_headers().headers.size());

        /**
         * Cancel the (SPV) getheaders timeout timer.
         */
        timer_spv_getheader_timeout_.cancel();
        
        /**
         * Cancel the (peer) getheaders timeout timer.
         */
        timer_peer_getheader_timeout_.cancel();
        
        /**
         * Set the last time we got a headers.
         */
        time_last_headers_received_ = std::time(0);
        
        if (
            globals::instance().operation_mode() ==
            protocol::operation_mode_client &&
            globals::instance().is_client_spv() == true
            )
        {
            /**
             * Make sure we have some headers.
             */
            if (msg.protocol_headers().headers.size() > 0)
            {
                /**
                 * Get the time of the last block header.
                 */
                auto time_last_header = static_cast<std::time_t> (
                    msg.protocol_headers().headers.back().header().timestamp)
                ;
                
                log_none(
                    "TCP connection got " <<
                    msg.protocol_headers().headers.size() <<
                    " headers, last time ago = " <<
                    std::time(0) - time_last_header
                );
                
                if (
                    msg.protocol_headers().headers.size() >= 2000 ||
                    time_last_header >=
                    globals::instance().spv_time_wallet_created()
                    )
                {
                    /**
                     * Get the first block header.
                     */
                    auto hash_first =
                        msg.protocol_headers().headers.front().get_hash()
                    ;
                    
                    /**
                     * Get the last block header.
                     */
                    auto hash_last =
                        msg.protocol_headers().headers.back().get_hash()
                    ;

                    /**
                     * After N time since wallet creation switch from
                     * downloading headers to BIP-0037 merkleblock's for
                     * the rest of the chain.
                     */
                    if (
                        time_last_header >=
                        globals::instance().spv_time_wallet_created() &&
                        globals::instance().spv_use_getblocks() == false
                        )
                    {
                        globals::instance().set_spv_use_getblocks(true);
                        
                        log_info(
                            "TCP connection is switching to (SPV) getblocks."
                        );
                        
                        log_info(
                            time_last_header << ":" <<
                            globals::instance().spv_time_wallet_created()
                        );
                    }

                    if (globals::instance().spv_use_getblocks() == true)
                    {
                        /**
                         * Set the first and last hash.
                         */
                        std::vector<sha256> hashes;
                        
                        hashes.push_back(hash_last);
                        hashes.push_back(hash_first);
                        
                        /**
                         * Allocate the block_locator with the last and
                         * first hash.
                         */
                        block_locator locator(hashes);
                        
                        /**
                         * Send the next getblocks message.
                         */
                        send_getblocks_message(sha256(), locator);
                    }
                    else
                    {
                        /**
                         * Set the first and last hash.
                         */
                        std::vector<sha256> hashes;
                        
                        hashes.push_back(hash_last);
                        hashes.push_back(hash_first);
                        
                        /**
                         * Allocate the block_locator with the last and
                         * first hash.
                         */
                        block_locator locator(hashes);
                        
                        /**
                         * Send the next getheaders message.
                         */
                        send_getheaders_message(sha256(), locator);
                    }
                }
                else
                {
                    /**
                     * We expect at least 2000 headers, any less and we ignore
                     * the message.
                     */
                }
            }
            else
            {
                /**
                 * We expect at least 1 header, any less and we switch to
                 * getblocks.
                 */
                globals::instance().set_spv_use_getblocks(true);
                
                log_info(
                    "TCP connection is switching to (SPV) getblocks because we "
                    "got 0 headers."
                );
            
                /**
                 * Send a getblocks message.
                 */
                if (globals::instance().spv_use_getblocks() == true)
                {
                    /**
                     * Get the block_locator hashes.
                     */
                    const auto & block_locator_hashes =
                        globals::instance().spv_block_locator_hashes()
                    ;
                    
                    /**
                     * Allocate the block_locator with the last and
                     * first hash.
                     */
                    block_locator locator(block_locator_hashes);
                    
                    /**
                     * Send the getblocks message.
                     */
                    send_getblocks_message(sha256(), locator);
                }
            }
            
            auto self(shared_from_this());
            
            for (auto & i : msg.protocol_headers().headers)
            {
                auto merkle_block = std::make_shared<block_merkle> (i);
                
                if (merkle_block->is_valid_spv() == true)
                {
                    log_none(
                        "TCP connection " << this << " got valid merkle_block, "
                        "matches = " <<
                        merkle_block->transactions_matched().size() << "."
                    );
                    
                    /**
                     * Only block_merkle's required matching received
                     * transactions.
                     */
                    std::vector<transaction> transactions_received;

                    auto self(shared_from_this());
                    
                    /**
                     * Post the operation onto the boost::asio::io_service.
                     */
                    globals::instance().strand().dispatch(
                        [this, self, merkle_block, transactions_received]()
                    {
                        /**
                         * Callback
                         */
                        stack_impl_.on_spv_merkle_block(
                            self, *merkle_block, transactions_received
                        );
                    });
                }
                else
                {
                    log_error(
                        "TCP connection " << this << " got bad merkle "
                        "block, dropping."
                    );
                }
            }
        }
        else
        {
            /**
             * Make sure we have some headers.
             */
            if (msg.protocol_headers().headers.size() > 0)
            {
                /**
                 * If we have at least 2000 headers this is a response to a
                 * getheaders message.
                 */
                if (msg.protocol_headers().headers.size() >= 2000)
                {
                    if (
                    	m_identifier != globals::instance(
                        ).peer_headers_first_active_tcp_connection_identifier()
                        )
                    {
                    	return false;
                    }
                
                    auto self(shared_from_this());
                    
                    for (auto & i : msg.protocol_headers().headers)
                    {
                        auto block_header = std::make_shared<block> (i);
     
                        if (block_header->is_header_valid() == true)
                        {
                            if (
                            	stack_impl_.on_peer_block_header(
                                self, *block_header) == false
                                )
                            {
                                /**
                                 * @note Verify this break is not a performance
                                 * or redundancy problem.
                                 */
                                break;
                            }
                        }
                        else
                        {
                            log_error(
                                "TCP connection " << this << " got bad block "
                                "header, dropping."
                            );
                        }
                    }
                    
                    /**
                     * Get the first block header.
                     */
                    auto hash_first =
                        msg.protocol_headers().headers.front().get_hash()
                    ;
                
                    /**
                     * Get the last block header.
                     */
                    auto hash_last =
                        msg.protocol_headers().headers.back().get_hash()
                    ;
                    
                    /**
                     * Set the first and last hash.
                     */
                    std::vector<sha256> hashes;
                
                    hashes.push_back(hash_last);
                    hashes.push_back(hash_first);
                    
                    /**
                     * Allocate the block_locator with the last and
                     * first hash.
                     */
                    block_locator locator(hashes);
                
                    /**
                     * Send the next getheaders message.
                     */
                    send_getheaders_message(sha256(), locator);
                }
                else
                {
                    /**
                     * We expect at least 1 header, any less and we ignore the
                     * message.
                     */
                    auto self(shared_from_this());
                    
                    for (auto & i : msg.protocol_headers().headers)
                    {
                        auto block_header = std::make_shared<block> (i);
     
                        if (block_header->is_header_valid() == true)
                        {
                            /**
                             * Callback
                             */
                            if (
                            	stack_impl_.on_peer_block_header(
                                self, *block_header) == false
                                )
                            {
                            	/**
                                 * @note Verify this break is not a performance
                                 * or redundancy problem.
                                 */
                                break;
                            }
                        }
                        else
                        {
                            log_error(
                                "TCP connection " << this << " got bad block "
                                "header, dropping."
                            );
                        }
                    }
                }
            }
            else
            {
				// ...
            }
        }
    }
    else if (msg.header().command == "tx")
    {
        const auto & tx = msg.protocol_tx().tx;
        
        if (tx != nullptr)
        {
        	log_info("Got tx " << tx->get_hash().to_string());
            
            /**
             * If we are an (SPV) client we handle transactions differently.
             */
            if (globals::instance().is_client_spv() == true)
            {
                if (spv_block_merkle_current_ != nullptr)
                {
                    if (
                        spv_block_merkle_current_tx_hashes_.count(
                        tx->get_hash()) > 0
                        )
                    {
                        /**
                         * Set the Tx time.
                         */
                        tx->set_time(
                            spv_block_merkle_current_->block_header(
                            ).timestamp
                        );
                        
                        /**
                         * Inform the wallet_manager.
                         */
                        wallet_manager::instance().sync_with_wallets(
                            *tx, nullptr, true
                        );
                    
                        spv_block_merkle_current_tx_received_.push_back(*tx);
                        spv_block_merkle_current_tx_hashes_.erase(
                            tx->get_hash()
                        );
                    }
                    
                    if (spv_block_merkle_current_tx_hashes_.size() == 0)
                    {
                        /**
                         * Get a shared reference to the block_merkle.
                         */
                        auto merkle_block = spv_block_merkle_current_;
                        
                        auto self(shared_from_this());
                        
                        auto transactions_received =
                            spv_block_merkle_current_tx_received_
                        ;

                        /**
                         * Dispatch the operation onto the boost::asio::strand.
                         */
                        globals::instance().strand().dispatch(
                            [this, self, tx, merkle_block,
                            transactions_received]()
                        {
                            /**
                             * Callback
                             */
                            stack_impl_.on_spv_merkle_block(
                                self, *merkle_block, transactions_received
                            );
                        });
                
                        spv_block_merkle_current_ = nullptr;
                        spv_block_merkle_current_tx_received_.clear();
                    }
                    
                    /**
                     * Allocate the inventory_vector.
                     */
                    inventory_vector inv(
                        inventory_vector::type_msg_tx, tx->get_hash()
                    );

                    insert_inventory_vector_seen(inv);
                }
                else if (utility::is_spv_initial_block_download() == false)
                {
                    /**
                     * During sync do not inform the wallet of transactions
                     * that we do not already have the block header for.
                     */
                    tx->set_time(
                        static_cast<std::uint32_t> (std::time(0))
                    );
                    
                    wallet_manager::instance().sync_with_wallets(
                        *tx, 0, true
                    );
                    
                    /**
                     * Allocate the inventory_vector.
                     */
                    inventory_vector inv(
                        inventory_vector::type_msg_tx, tx->get_hash()
                    );

                    insert_inventory_vector_seen(inv);
                }
            }
            else
            {
                /**
                 * Allocate the inventory_vector.
                 */
                inventory_vector inv(
                    inventory_vector::type_msg_tx, tx->get_hash()
                );

                /**
                 * Allocate the data_buffer.
                 */
                data_buffer buffer;
                
                /**
                 * Encode the transaction.
                 */
                tx->encode(buffer);
                
                std::vector<sha256> queue_work;
                std::vector<sha256> queue_erase;
            
                auto missing_inputs = false;
                
                auto ret = tx->accept_to_transaction_pool_2(&missing_inputs);
                
                log_info("ret = " << ret.second);
                
                if (ret.first == true)
                {
                    /**
                     * Inform the wallet_manager.
                     */
                    wallet_manager::instance().sync_with_wallets(
                        *tx, nullptr, true
                    );
            
                    if (m_protocol_version_relay == false)
                    {
                        log_info(
                            "TCP connection is not relaying transaction."
                        );
                    }
                    else
                    {
                        /**
                         * Relay the inv.
                         */
                        relay_inv(inv, buffer);
                    }
                    
                    queue_work.push_back(inv.hash());
                    queue_erase.push_back(inv.hash());

                    /**
                     * Recursively process any orphan transactions that
                     * depended on this one.
                     */
                    for (auto i = 0; i < queue_work.size(); i++)
                    {
                        auto hash_previous = queue_work[i];

                        auto it = globals::instance(
                            ).orphan_transactions_by_previous()[
                            hash_previous].begin()
                        ;
                        
                        for (
                            ;
                            it != globals::instance(
                            ).orphan_transactions_by_previous()[
                            hash_previous].end();
                            ++it
                            )
                        {
                            data_buffer buffer2(
                                it->second->data(), it->second->size()
                            );
                            
                            transaction tx2;
                            
                            tx2.decode(buffer2);
                            
                            inventory_vector inv2(
                                inventory_vector::type_msg_tx,
                                tx2.get_hash()
                            );
                            
                            auto missing_inputs2 = false;

                            if (
                                tx2.accept_to_transaction_pool_2(
                                &missing_inputs2).first
                                )
                            {
                                log_debug(
                                    "TCP connection accepted orphan "
                                    "transaction " << inv2.hash().to_string(
                                    ).substr(0, 10) << "."
                                )
                                /**
                                 * Inform the wallet_manager.
                                 */
                                wallet_manager::instance().sync_with_wallets(
                                    tx2, nullptr, true
                                );

                                if (m_protocol_version_relay == false)
                                {
                                    log_info(
                                        "TCP connection is not relaying "
                                        "transaction to BIP-0037 node."
                                    );
                                }
                                else
                                {
                                    relay_inv(inv2, buffer2);
                                }
                                
                                queue_work.push_back(inv2.hash());
                                queue_erase.push_back(inv2.hash());
                            }
                            else if (missing_inputs2 == false)
                            {
                                /**
                                 * Invalid orphan.
                                 */
                                queue_erase.push_back(inv2.hash());
                                
                                log_debug(
                                    "TCP connection removed invalid orphan "
                                    "transaction " << inv2.hash().to_string(
                                    ).substr(0, 16) << "."
                                );
                            }
                        }
                    }

                    for (auto & i : queue_erase)
                    {
                        utility::erase_orphan_tx(i);
                    }
                }
                else if (missing_inputs == true)
                {
                    utility::add_orphan_tx(buffer);
#define BCASH_STRESS_TEST 1
#if (defined BCASH_STRESS_TEST && BCASH_STRESS_TEST)
                    if (m_protocol_version_relay == false)
                    {
                        log_info(
                            "TCP connection is not relaying transaction."
                        );
                    }
                    else
                    {
                        /**
                         * Relay the inv.
                         */
                        relay_inv(inv, buffer);
                    }
#endif // BCASH_STRESS_TEST
                    /**
                     * Limit the size of the orphan transactions.
                     */
                    auto evicted = utility::limit_orphan_tx_size(
                        static_cast<std::uint32_t> (
                        block::get_maximum_size() / 100)
                    );
                    
                    if (evicted > 0)
                    {
                        log_debug(
                            "TCP connection orphans overflow, evicted = " <<
                            evicted << "."
                        );
                    }
                }
            }
        }
    }
    else if (msg.header().command == "block")
    {
        if (msg.protocol_block().blk)
        {
#define BCASH_STRESS_TEST 1
#if (defined BCASH_STRESS_TEST && BCASH_STRESS_TEST)
        if (globals::instance().block_indexes().size() >= 2016 * 8)
		{
            log_info(
                "Dropping block (bcst) " <<
                msg.protocol_block().blk->get_hash().to_string() << "."
            );
            
            return true;
        }
#endif // BCASH_STRESS_TEST
            log_debug(
                "Connection received block " <<
                msg.protocol_block().blk->get_hash().to_string(
                ) << "."
            );
#if 0
            msg.protocol_block().blk->print();
#endif
            /**
             * Set the time we received a block.
             */
            time_last_block_received_ = std::time(0);
            
            /**
             * If we are in (peer) headers first block chain synchronization
             * mode decrement the number of requested blocks now that one has
             * arrived.
             */
            if (
            	globals::instance().peer_use_headers_first_chain_sync() == true
                )
            {
            	/**
             	 * Prevent faulty node from wrapping our count by sending
                 * more blocks than requested.
                 */
            	if (m_peer_headers_first_blocks_requested > 0)
             	{
					m_peer_headers_first_blocks_requested--;
    			}
            }
            
            if (globals::instance().is_client_spv() == false)
            {
                /**
                 * Allocate an inventory_vector.
                 */
                inventory_vector inv(
                    inventory_vector::type_msg_block,
                    msg.protocol_block().blk->get_hash()
                );
                
                insert_inventory_vector_seen(inv);
                
                auto self(shared_from_this());

				auto ptr_block = msg.protocol_block().blk;

				/**
    			 * @note post() will not block; dispatch will block, use post()
                 * as long as concurrency is ok.
                 */
#if 1
                /**
                 * Post the operation onto the boost::asio::io_service.
                 */
                globals::instance().io_service().post(
                    [this, self, ptr_block]()
                {
                    /**
                     * Process the block.
                     */
                    if (
                        stack_impl_.process_block(self, ptr_block)
                        )
                    {
                        // ...
                    }
                });
#else
                /**
                 * Dispatch the operation onto the boost::asio::strand.
                 */
                globals::instance().strand().dispatch(
                    [this, self, ptr_block]()
                {
                    /**
                     * Process the block.
                     */
                    if (
                        stack_impl_.process_block(self, ptr_block)
                        )
                    {
                        // ...
                    }
                });
#endif
            }
            else
            {
                block_merkle merkle_block(*msg.protocol_block().blk);
                
                std::vector<transaction> transactions_received;
                
                auto self(shared_from_this());
                
                /**
                 * Post the operation onto the boost::asio::io_service.
                 */
                globals::instance().strand().dispatch(
                    [this, self, merkle_block, transactions_received]()
                {
                    /**
                     * Callback
                     */
                    stack_impl_.on_spv_merkle_block(
                        self, *const_cast<block_merkle *> (&merkle_block),
                        transactions_received
                    );
                });
            }
        }
    }
    else if (msg.header().command == "merkleblock")
    {
        assert(msg.protocol_merkleblock().merkleblock);
        
        if (msg.protocol_merkleblock().merkleblock)
        {
            log_none(
                "Connection received merkleblock " <<
                msg.protocol_merkleblock().merkleblock->get_hash().to_string(
                ).substr(0, 20)
                << "."
            );
            
            /**
             * Allocate an inventory_vector.
             */
            inventory_vector inv(
                inventory_vector::type_msg_filtered_block,
                msg.protocol_merkleblock().merkleblock->get_hash()
            );
            
            insert_inventory_vector_seen(inv);
            
            /**
             * Cancel the (SPV) getblocks timeout timer.
             */
            timer_spv_getblocks_timeout_.cancel();
            
            /**
             * Set the time we received a block.
             */
            time_last_block_received_ = std::time(0);
            
            /**
             * If we have matched transaction hashes hold this block_merkle
             * and wait for all of the trnsactions to arrive otherwise callback
             * the block_merkle as-as.
             */
            if (
                msg.protocol_merkleblock().merkleblock->transactions_matched(
                ).size() > 0
                )
            {
                if (spv_block_merkle_current_)
                {
                    log_error(
                        "TCP connection got partial merkle block, dropping."
                    );
                    
                    return true;
                }
                
                spv_block_merkle_current_ =
                    msg.protocol_merkleblock().merkleblock
                ;
                spv_block_merkle_current_tx_hashes_.clear();

                for (
                    auto & i : spv_block_merkle_current_->transactions_matched()
                    )
                {
                    spv_block_merkle_current_tx_hashes_.insert(i.second);
                }
            }
            else
            {
                /**
                 * Get a shared reference to the block_merkle.
                 */
                auto merkle_block = msg.protocol_merkleblock().merkleblock;
                
                /**
                 * This block_merkle has no matching received transactions.
                 */
                std::vector<transaction> transactions_received;
                
                auto self(shared_from_this());
                
                /**
                 * Post the operation onto the boost::asio::io_service.
                 */
                globals::instance().strand().dispatch(
                    [this, self, merkle_block, transactions_received]()
                {
                    /**
                     * Callback
                     */
                    stack_impl_.on_spv_merkle_block(
                        self, *merkle_block, transactions_received
                    );
                });
            }
        }
    }
    else if (msg.header().command == "filterload")
    {
        assert(msg.protocol_filterload().filterload);
        
        /**
         * First check the size constrainsts of the filter.
         */
        if (
            msg.protocol_filterload(
            ).filterload->is_within_size_constraints() == false
            )
        {
            /**
             * Set the Denial-of-Service score for the connection.
             */
            set_dos_score(m_dos_score + 100);
        }
        else
        {
            transaction_bloom_filter_.reset(
                new transaction_bloom_filter(
                *msg.protocol_filterload().filterload)
            );
            
            transaction_bloom_filter_->update_empty_full();
        }
        
        m_protocol_version_relay = true;
    }
    else if (msg.header().command == "filteradd")
    {
        /**
         * First check the size.
         */
        if (
            msg.protocol_filteradd().filteradd.size() >
            script::max_element_size
            )
        {
            /**
             * Set the Denial-of-Service score for the connection.
             */
            set_dos_score(m_dos_score + 100);
        }
        else
        {
            if (transaction_bloom_filter_ == 0)
            {
                /**
                 * Set the Denial-of-Service score for the connection.
                 */
                set_dos_score(m_dos_score + 100);
            }
            else
            {
                transaction_bloom_filter_->insert(
                    msg.protocol_filteradd().filteradd
                );
            }
        }
    }
    else if (msg.header().command == "filterclear")
    {
        transaction_bloom_filter_.reset(
            new transaction_bloom_filter()
        );
        
        m_protocol_version_relay = true;
    }
    else if (msg.header().command == "feefilter")
    {
        /**
         * We don't handle the feefilter message yet and may never.
         */
    }
    else if (msg.header().command == "mempool")
    {
        log_debug("Got mempool");
        
        std::vector<sha256> block_hashes;
        
        transaction_pool::instance().query_hashes(block_hashes);
        
        if (transaction_bloom_filter_)
        {
            std::vector<sha256> block_hashes_filtered;
            
            for (auto & i : block_hashes)
            {
                if (transaction_pool::instance().exists(i) == true)
                {
                    auto tx = transaction_pool::instance().lookup(i);
                    
                    if (
                        transaction_bloom_filter_->is_relevant_and_update(
                        tx) == true
                        )
                    {
                        block_hashes_filtered.push_back(i);
                    }
                }
            }
            
            if (block_hashes_filtered.size() > protocol::max_inv_size)
            {
                block_hashes_filtered.resize(protocol::max_inv_size);
            }
        
            if (block_hashes_filtered.size() > 0)
            {
                do_send_inv_message(
                    inventory_vector::type_msg_tx, block_hashes_filtered
                );
            }
        }
        else
        {
            if (block_hashes.size() > protocol::max_inv_size)
            {
                block_hashes.resize(protocol::max_inv_size);
            }
        
            if (block_hashes.size() > 0)
            {
                do_send_inv_message(
                    inventory_vector::type_msg_tx, block_hashes
                );
            }
        }
    }
    else if (msg.header().command == "sendheaders")
    {
        log_info(
            "TCP connection " << m_identifier << " got sendheaders, "
            "will announce new blocks by headers (instead of inv)."
        );
        
        /**
         * Set that we will now announce blocks to this peer with headers
         * instead of inv's.
         */
        m_is_sendheaders = true;
    }
    else if (msg.header().command == "sendcmpct")
    {
        log_info(
            "TCP connection " << m_identifier << " got sendcmpct, "
            "feature not supported, dropping."
        );
    }
    else if (msg.header().command == "alert")
    {
        /**
         * Deprecated
         */
    }
    else
    {
        log_error(
            "Connection got unknown command " << msg.header().command << "."
        );
    }
    
    if (
        msg.header().command == "version" || msg.header().command == "addr" ||
        msg.header().command == "inv" || msg.header().command == "getdata" ||
        msg.header().command == "ping"
        )
    {
        /**
         * Inform the address_manager.
         */
        stack_impl_.get_address_manager()->on_connected(
            msg.protocol_version().addr_src
        );
    }
    
    return true;
}

void tcp_connection::do_ping(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        auto self(shared_from_this());
        
        /**
         * Start the ping timeout timer.
         */
        timer_ping_timeout_.expires_from_now(
            std::chrono::seconds(60)
        );
        timer_ping_timeout_.async_wait(
            strand_.wrap(
                [this, self](boost::system::error_code ec)
                {
                    if (ec)
                    {
                        // ...
                    }
                    else
                    {
                        log_error(
                            "TCP connection (ping) timed out, calling stop."
                        );
                    
                        /**
                         * The connection has timed out, call stop.
                         */
                        do_stop();
                    }
                }
            )
        );
        
        if (m_state == state_started)
        {
            /**
             * Send a ping message every interval_ping seconds.
             */
            send_ping_message();
            
            timer_ping_.expires_from_now(std::chrono::seconds(interval_ping));
            timer_ping_.async_wait(strand_.wrap(
                std::bind(&tcp_connection::do_ping, self,
                std::placeholders::_1))
            );
        }
    }
}

void tcp_connection::do_send_getblocks(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        /**
         * When using headers first chain synchronization we do not
         * need to ever send a getblocks message.
         */
        if (
			globals::instance().operation_mode() ==
            protocol::operation_mode_peer &&
            globals::instance().peer_use_headers_first_chain_sync() == true
            )
        {
            /**
             * If this connection has not received a block in a while stop it.
             */
            if (
                std::time(0) - time_last_block_received_ >
                (utility::is_initial_block_download() == true ?
                constants::work_target_spacing :
                constants::work_target_spacing * 12)
                )
            {
                if (auto transport = m_tcp_transport.lock())
                {
                    auto ep = transport->socket().remote_endpoint();
                    
                    log_info(
                        "TCP connection has not received a block since too "
                        "long, dropping connection to " << ep << "."
                    );
                }
                
                /**
                 * Call stop.
                 */
                do_stop();
                
                return;
            }
            else
            {
                if (m_state == state_started)
                {
                    auto self(shared_from_this());
                    
                    /**
                     * Start the getblocks timer.
                     */
					timer_getblocks_.expires_from_now(std::chrono::seconds(60));
                    timer_getblocks_.async_wait(strand_.wrap(
                        std::bind(&tcp_connection::do_send_getblocks, self,
                        std::placeholders::_1))
                    );
                }
            }
		}
  		else
    	{
            /**
             * The block spacing must be more than 63 seconds.
             */
            assert(constants::work_target_spacing > 63);
            
            /**
             * If we have not received a block in a long time drop the
             * connection but do not ban it.
             * @note Does not pertain to SPV nodes.
             */
            if (
                m_direction == direction_outgoing &&
                std::time(0) - time_last_block_received_ >
                constants::work_target_spacing * 12 &&
                globals::instance().is_client_spv() == false
                )
            {
                if (auto transport = m_tcp_transport.lock())
                {
                    auto ep = transport->socket().remote_endpoint();
                    
                    log_info(
                        "TCP connection has not received a block since too "
                        "long, dropping connection to " << ep << "."
                    );
                }
                
                /**
                 * Call stop.
                 */
                do_stop();
                
                return;
            }
            else
            {
                if (globals::instance().is_client_spv() == true)
                {
                    auto should_send_spv_getblocks =
                        globals::instance().spv_use_getblocks() == true
                    ;
                    
                    if (should_send_spv_getblocks == true)
                    {
                        if (
                            globals::instance().spv_best_block_height() <
                            stack_impl_.peer_block_count() &&
                            std::time(0) - time_last_block_received_ >= 60
                            )
                        {
                            log_info(
                                "TCP connection " << m_identifier <<
                                " (SPV) getblocks stalled, calling stop."
                            );
                            
                            /**
                             * We've stalled.
                             */
                            do_stop();
                            
                            return;
                        }
                    }
                }
                else
                {
                    if (
                        utility::is_initial_block_download() == true &&
                        (std::time(0) - time_last_block_received_ >=
                        constants::work_target_spacing * 3)
                        )
                    {
                        log_info(
                            "TCP connection " << m_identifier <<
                            " chain sync stalled, calling stop."
                        );
                        
                        /**
                         * We've stalled.
                         */
                        do_stop();
                        
                        return;
                    }
                    else if (
                        (std::time(0) - time_last_block_received_ >=
                        (constants::work_target_spacing * 3)) ||
                        (utility::is_initial_block_download() == true &&
                        std::time(0) - time_last_block_received_ >=
                        constants::work_target_spacing * 3)
                        )
                    {
                        if (
                            std::time(0) - time_last_getblocks_sent_ >=
                            constants::work_target_spacing * 3
                            )
                        {
                            log_info(
                                "TCP connection " << m_identifier <<
                                " is sending getblocks."
                            );

                            /**
                             * Send a getblocks message with our best index.
                             */
                            send_getblocks_message(
                                stack_impl::get_block_index_best(), sha256()
                            );
                        }
                    }
                }
                
                if (m_state == state_started)
                {
                    auto self(shared_from_this());
                    
                    /**
                     * Start the getblocks timer.
                     */
                    if (globals::instance().is_client_spv() == true)
                    {
                        timer_getblocks_.expires_from_now(
                        	std::chrono::seconds(8)
                        );
                    }
                    else
                    {
                        timer_getblocks_.expires_from_now(
                        	std::chrono::seconds(8)
                        );
                    }
                    
                    timer_getblocks_.async_wait(strand_.wrap(
                        std::bind(&tcp_connection::do_send_getblocks, self,
                        std::placeholders::_1))
                    );
                }
            }
        }
    }
}

void tcp_connection::do_send_inv_message(
    const inventory_vector::type_t & type, const sha256 & hash_block
    )
{
    if (auto t = m_tcp_transport.lock())
    {
        inventory_vector inv(type, hash_block);
        
        /**
         * Prevent sending duplicate INV's.
         */
        if (inventory_vectors_seen_set_.count(inv) > 0)
        {
            log_info(
                "Already sent INV " << hash_block.to_string().substr(0, 16)
            );
            
            return;
        }
        
        /**
         * Allocate the message.
         */
        message msg("inv");
        
        /**
         * Set the inventory_vector.
         */
        msg.protocol_inv().inventory.push_back(inv);
        
        /**
         * Set the count.
         */
        msg.protocol_inv().count = msg.protocol_inv().inventory.size();
        
        log_none("TCP connection is sending inv.");
        
        /**
         * Encode the message.
         */
        msg.encode();
        
        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

void tcp_connection::do_send_inv_message(
    const inventory_vector::type_t & type,
    const std::vector<sha256> & block_hashes
    )
{
    if (auto t = m_tcp_transport.lock())
    {
        /**
         * Allocate the message.
         */
        message msg("inv");
        
        for (auto & i : block_hashes)
        {
            inventory_vector inv(type, i);

            if (inventory_vectors_seen_set_.count(inv) > 0)
            {
                log_info(
                    "Already sent INV " << i.to_string().substr(0, 16) <<
                    ", continuing."
                );
                
                continue;
            }
            /**
             * Append the inventory_vector.
             */
            msg.protocol_inv().inventory.push_back(inv);
        }
        
        /**
         * Set the count.
         */
        msg.protocol_inv().count = msg.protocol_inv().inventory.size();
        
        log_none(
            "TCP connection is sending inv, count = " <<
            msg.protocol_inv().count << "."
        );
        
        /**
         * Encode the message.
         */
        msg.encode();
        
        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

void tcp_connection::do_send_relayed_inv_message(
    const inventory_vector & inv, const data_buffer & buffer
    )
{
    std::lock_guard<std::recursive_mutex> l1(stack_impl::mutex());
    
    /**
     * Expire old relay messages.
     */
    while (
        globals::instance().relay_inv_expirations().size() > 0 &&
        globals::instance().relay_inv_expirations().front().first < std::time(0)
        )
    {
        globals::instance().relay_invs().erase(
            globals::instance().relay_inv_expirations().front().second
        );
        
        globals::instance().relay_inv_expirations().pop_front();
    }

    /**
     * Save original serialized message so newer versions are preserved.
     */
    globals::instance().relay_invs().insert(std::make_pair(inv, buffer));
    
    globals::instance().relay_inv_expirations().push_back(
        std::make_pair(std::time(0) + 15 * 60, inv)
    );
    
    if (auto t = m_tcp_transport.lock())
    {
        /**
         * Allocate the message.
         */
        message msg(inv.command(), buffer);

        /**
         * Encode the message.
         */
        msg.encode();

        log_debug(
            "TCP connection is sending (relayed) inv message, command = " <<
            inv.command() << ", buffer size = " << buffer.size() << "."
        );
    
        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

void tcp_connection::do_send_block_message(const block & blk)
{
    if (auto t = m_tcp_transport.lock())
    {
        /**
         * Allocate the message.
         */
        message msg("block");
        
        /**
         * Set the block.
         */
        msg.protocol_block().blk = std::make_shared<block> (blk);
        
        log_none(
            "TCP connection is sending block " <<
            msg.protocol_block().blk->get_hash().to_string().substr(0, 20) <<
            "."
        );
        
        /**
         * Encode the message.
         */
        msg.encode();
        
        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

void tcp_connection::do_send_getheaders(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        /**
         * The block spacing must be more than 63 seconds.
         */
        assert(constants::work_target_spacing > 63);

        std::lock_guard<std::recursive_mutex> l1(stack_impl::mutex());
        
        if (
            globals::instance().is_client_spv() == true &&
            globals::instance().spv_use_getblocks() == false
            )
        {
            if (
                m_identifier == globals::instance(
                ).spv_active_tcp_connection_identifier()
                )
            {
                if (
                    std::time(0) - time_last_headers_received_ >=
                    (constants::work_target_spacing * 2) ||
                    (utility::is_spv_initial_block_download() &&
                    std::time(0) - time_last_headers_received_ > 3)
                    )
                {
                    /**
                     * Get the block_locator hashes.
                     */
                    const auto & block_locator_hashes =
                        globals::instance().spv_block_locator_hashes()
                    ;
                    
                    /**
                     * Allocate the block_locator with the last and
                     * first hash.
                     */
                    block_locator locator(block_locator_hashes);
                    
                    /**
                     * Send the getheaders message.
                     */
                    send_getheaders_message(sha256(), locator);
                }
            }
        }
        else if (
            globals::instance().peer_use_headers_first_chain_sync() == true
            )
        {
            if (
                m_identifier == globals::instance(
                ).peer_headers_first_active_tcp_connection_identifier()
                )
            {
                if (
                    std::time(0) - time_last_headers_received_ >=
                    (constants::work_target_spacing * 2) ||
                    (utility::is_initial_block_download() &&
                    std::time(0) - time_last_headers_received_ > 3)
                    )
                {
                    /**
                     * Get the block_locator hashes.
                     */
                    const auto & block_locator_hashes =
                        globals::instance(
                        ).peer_headers_first_block_locator_hashes()
                    ;
                    
                    /**
                     * Allocate the block_locator with the last and
                     * first hash.
                     */
                    block_locator locator(block_locator_hashes);
                    
                    /**
                     * Send the getheaders message.
                     */
                    send_getheaders_message(sha256(), locator);
                }
            }
        }
            
        /**
         * After initial download of the headers SPV nodes use getblocks
         * to continue synchronisation. Peer nodes always user headers
         * first or getblocks and not a combination.
         */
        if (
            (globals::instance().is_client_spv() == true &&
            utility::is_spv_initial_block_download() == true) ||
            (globals::instance().peer_use_headers_first_chain_sync(
            ) == true && globals::instance().peer_headers_first_blocks(
            ).size() < m_protocol_version_start_height - 6)
            )
        {
            if (m_state == state_started)
            {
                auto self(shared_from_this());
                
                /**
                 * Start the getheaders timer.
                 */
                timer_getheaders_.expires_from_now(std::chrono::seconds(8));
                timer_getheaders_.async_wait(strand_.wrap(
                    std::bind(&tcp_connection::do_send_getheaders, self,
                    std::placeholders::_1))
                );
            }
        }
    }
}

void tcp_connection::do_rebroadcast_addr_messages(
    const std::uint32_t & interval
    )
{
    auto self(shared_from_this());
    
    /**
     * Start the addr rebroadcast timer.
     */
    timer_addr_rebroadcast_.expires_from_now(std::chrono::seconds(interval));
    timer_addr_rebroadcast_.async_wait(strand_.wrap(
        [this, self] (const boost::system::error_code & ec)
        {
            if (ec)
            {
                // ...
            }
            else
            {
                static std::int64_t g_last_addr_rebroadcast;
                
                if (
                    utility::is_initial_block_download() == false &&
                    (std::time(0) - g_last_addr_rebroadcast > 8 * 60 * 60)
                    )
                {
                    std::lock_guard<std::recursive_mutex> l1(
                        stack_impl::mutex()
                    );
                    
                    auto tcp_connections =
                        stack_impl_.get_tcp_connection_manager(
                        )->tcp_connections()
                    ;
                    
                    for (auto & i : tcp_connections)
                    {
                        if (g_last_addr_rebroadcast > 0)
                        {
                            if (auto t = i.second.lock())
                            {
                                /**
                                 * Periodically clear the seen network
                                 * addresses to allow for new rebroadcasts.
                                 */
                                t->clear_seen_network_addresses();

                                /**
                                 * Get our network port.
                                 */
                                auto port =
                                    globals::instance().is_client_spv(
                                    ) == true ? 0 :stack_impl_.get_tcp_acceptor(
                                    )->local_endpoint().port()
                                ;

                                protocol::network_address_t addr =
                                    protocol::network_address_t::from_endpoint(
                                    boost::asio::ip::tcp::endpoint(
                                    m_address_public, port)
                                );
    
                                t->send_addr_message(addr);
                            }
                        }
                    }
                    
                    g_last_addr_rebroadcast = std::time(0);
                    
                    do_rebroadcast_addr_messages(8 * 60 * 60);
                }
                else
                {
                    do_rebroadcast_addr_messages(60 * 60);
                }
            }
        })
    );
}

bool tcp_connection::insert_inventory_vector_seen(const inventory_vector & inv)
{
    auto ret = inventory_vectors_seen_set_.insert(inv);
    
    enum { inv_queue_max_len = 1024 };
    
    if (ret.second == true)
    {
        if (
            inv_queue_max_len &&
            inventory_vectors_seen_queue_.size() == inv_queue_max_len
            )
        {
            inventory_vectors_seen_set_.erase(
                inventory_vectors_seen_queue_.front()
            );
            
            inventory_vectors_seen_queue_.pop_front();
        }
        
        inventory_vectors_seen_queue_.push_back(inv);
    }
    
    return ret.second;
}
