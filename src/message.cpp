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

#include <ctime>
#include <random>
#include <vector>

#include <coin/block.hpp>
#include <coin/block_merkle.hpp>
#include <coin/block_locator.hpp>
#include <coin/constants.hpp>
#include <coin/endian.hpp>
#include <coin/globals.hpp>
#include <coin/hash.hpp>
#include <coin/logger.hpp>
#include <coin/message.hpp>
#include <coin/time.hpp>
#include <coin/transaction_bloom_filter.hpp>

using namespace coin;

message::message(const char * buf, const std::size_t & len)
    : data_buffer(buf, len)
{
    // ...
}

message::message(const std::string & command)
{
    m_header.magic = header_magic();
    m_header.command = command;
}

message::message(
    const std::string & command, const data_buffer & payload
    )
    : m_payload(payload)
{
    m_header.magic = header_magic();
    m_header.command = command;
}

void message::encode()
{
    if (m_payload.size() == 0)
    {
        if (m_header.command == "verack")
        {
            // ...
        }
        else if (m_header.command == "version")
        {
            /**
             * Create the version.
             */
            m_payload = create_version();
        }
        else if (m_header.command == "addr")
        {
            /**
             * Create the addr.
             */
            m_payload = create_addr();
        }
        else if (m_header.command == "getaddr")
        {
            // ...
        }
        else if (m_header.command == "reject")
        {
            /**
             * Create the reject.
             */
            m_payload = create_reject();
        }
        else if (m_header.command == "ping")
        {
            /**
             * Create the ping.
             */
            m_payload = create_ping();
        }
        else if (m_header.command == "pong")
        {
            /**
             * Create the pong.
             */
            m_payload = create_pong();
        }
        else if (m_header.command == "inv")
        {
            /**
             * Create the inv.
             */
            m_payload = create_inv();
        }
        else if (m_header.command == "getdata")
        {
            /**
             * Create the getdata.
             */
            m_payload = create_getdata();
        }
        else if (m_header.command == "getblocks")
        {
            /**
             * Create the getblocks.
             */
            m_payload = create_getblocks();
        }
        else if (m_header.command == "getheaders")
        {
            /**
             * Create the getheaders.
             */
            m_payload = create_getheaders();
        }
        else if (m_header.command == "headers")
        {
            /**
             * Create the headers.
             */
            m_payload = create_headers();
        }
        else if (m_header.command == "sendheaders")
        {
            /**
             * Create the sendheaders.
             */
            m_payload = create_sendheaders();
        }
        else if (m_header.command == "block")
        {
            /**
             * Create the block.
             */
            m_payload = create_block();
        }
        else if (m_header.command == "tx")
        {
            /**
             * Create the tx.
             */
            m_payload = create_tx();
        }
        else if (m_header.command == "filterload")
        {
            /**
             * Create the filterload.
             */
            m_payload = create_filterload();
        }
        else if (m_header.command == "filteradd")
        {
            /**
             * Create the filteradd.
             */
            m_payload = create_filteradd();
        }
        else if (m_header.command == "filterclear")
        {
            /**
             * Create the filterclear.
             */
            m_payload = create_filterclear();
        }
        else if (m_header.command == "merkleblock")
        {
            /**
             * Create the merkleblock.
             */
            m_payload = create_merkleblock();
        }
    }
    
    /**
     * Encode the header magic to little endian.
     */
    auto header_magic = endian::to_little<std::uint32_t> (m_header.magic);
    
    /**
     * Write the header length.
     */
    write_bytes(reinterpret_cast<char *> (
        &header_magic[0]), header_magic.size()
    );

    /**
     * Make sure the header command is 12 or less bytes in length.
     * @note We add one byte to the size for null-termination.
     */
    assert(m_header.command.size() + 1 <= 12);
    
    /**
     * Check the command size is within bounds.
     */
    if (m_header.command.size() + 1 > 12)
    {
        log_error(
            "Message encoding failed, header command (" << m_header.command <<
            ") is too long, bytes = " << m_header.command.size() << "."
        );
        
        return;
    }
    
    /**
     * Write the header command.
     * @note We add one byte to the size for null-termination.
     */
    write_bytes(m_header.command.c_str(), m_header.command.size() + 1);
    
    /**
     * Pad the rest of the 12 byte command with zeros.
     */
    for (auto i = 0; i < 12 - (m_header.command.size() + 1); i++)
    {
       write_byte(0);
    }
    
    /**
     * Set the header length.
     */
    m_header.length = static_cast<std::uint32_t> (m_payload.size());
    
    /**
     * Encode the header length to little endian.
     */
    auto header_length = endian::to_little<std::uint32_t>(m_header.length);
    
    /**
     * Write the header length.
     */
    write_bytes(reinterpret_cast<char *> (
        &header_length[0]), header_length.size()
    );
    
    /**
     * Calculate the header checksum.
     */
    m_header.checksum = hash::sha256d_checksum(
        reinterpret_cast<const std::uint8_t *>(m_payload.data()),
        m_payload.size()
    );
    
    /**
     * Encode the header checksum to little endian.
     */
    auto header_checksum = endian::to_little<std::uint32_t>(m_header.checksum);
            
    /**
     * Write the header checksum.
     */
    write_bytes(reinterpret_cast<char *> (
        &header_checksum[0]), header_checksum.size()
    );
    
    /**
     * Write the payload.
     */
    write_bytes(m_payload.data(), m_payload.size());
}

void message::decode()
{
    /**
     * Decode the header magic from little endian.
     */
    m_header.magic = read_uint32();
    
    log_none(
        "Message got header magic = " << m_header.magic << ", verified = " <<
        verify_header_magic() << "."
    );
    
    if (verify_header_magic() == false)
    {
        throw std::runtime_error("invalid header magic");
    }
    
    /**
     * Allocate memory for the header command.
     */
    char header_command[12];
    
    std::memset(header_command, 0, sizeof(header_command));
    
    /**
     * Read the header command.
     */
    read_bytes(header_command, sizeof(header_command));
    
    /**
     * Set the header command.
     */
    if (header_command[12 - 1] == 0)
    {
        m_header.command = std::string(
            header_command, header_command + strlen(header_command)
        );
    }
    else
    {
        m_header.command = std::string(header_command, header_command + 12);
    }
    
    for (auto i = 0; i < 12; i++)
    {
        if (header_command[i] == 0)
        {
            /**
             * There must be all zeros after the first zero.
             */
            for (auto j = i; j < 12; j++)
            {
                if (header_command[j] != 0)
                {
                    throw std::runtime_error(
                        "invalid header command (missing null)"
                    );
                }
            }
        }
        else if (header_command[i] < ' ' || header_command[i] > 0x7E)
        {
            throw std::runtime_error(
                "invalid header command (characters out of range)"
            );
        }
    }
    
    log_none("Message got header command = " << m_header.command << ".");
    
    /**
     * Decode the header length from little endian.
     */
    m_header.length = read_uint32();
    
    log_none("Message got header length = " << m_header.length << ".");
    
    /**
     * Read the header checksum.
     */
    m_header.checksum = read_uint32();
    
    log_none("Message got header checksum = " << m_header.checksum << ".");

    if (remaining() < m_header.length)
    {
        throw std::runtime_error(
            "(" + m_header.command + ") underrun, header len = " +
            std::to_string(m_header.length) +
            ", remaining = " + std::to_string(remaining())
        );
    }
    
    if (m_header.length > 0)
    {
        /**
         * Calculate the header checksum.
         */
        auto checksum = hash::sha256d_checksum(
            reinterpret_cast<const std::uint8_t *>(read_ptr()), m_header.length
        );

        if (m_header.checksum != checksum)
        {
            throw std::runtime_error("invalid header checksum");
        }
        
        if (m_header.command == "verack")
        {
            // ...
        }
        else if (m_header.command == "version")
        {
            m_protocol_version.version = read_uint32();
            m_protocol_version.services = read_uint64();
            m_protocol_version.timestamp = read_uint64();
            m_protocol_version.addr_src = read_network_address(false, false);
            m_protocol_version.addr_dst = read_network_address(false, false);
            m_protocol_version.nonce = read_uint64();
            
            auto user_agent_length = read_var_int();
            
            enum { maximum_user_agent_length = 256 };
            
            if (user_agent_length > maximum_user_agent_length)
            {
                throw std::runtime_error("invalid user agent string");
            }
            
            m_protocol_version.user_agent.resize(user_agent_length);
            
            read_bytes(
                const_cast<char *> (m_protocol_version.user_agent.data()),
                m_protocol_version.user_agent.size()
            );
            m_protocol_version.start_height = read_uint32();
            
            /**
             * bip-0037
             */
            if (remaining() > 0)
            {
                /**
                 * Only read the version.relay if the remote node is not a peer.
                 */
                if (
                    (m_protocol_version.services &
                    protocol::operation_mode_peer)
                    )
                {
                    /**
                     * Set relay to true.
                     */
                    m_protocol_version.relay = true;
                }
                else
                {
                    /**
                     * Set relay to version.relay.
                     */
                    m_protocol_version.relay = read_uint8();
                }
            }
            else
            {
                /**
                 * Set relay to true.
                 */
                m_protocol_version.relay = true;
            }

            log_none("version = " << m_protocol_version.version);
            log_none("services = " << m_protocol_version.services);
            log_none("timestamp = " << m_protocol_version.timestamp);
            log_none("addr_src.port = " << m_protocol_version.addr_src.port);
            log_none("nonce = " << m_protocol_version.nonce);
            log_none("user_agent = " << m_protocol_version.user_agent);
            log_none("start_height = " << m_protocol_version.start_height);
            log_none(
                "relay = " << static_cast<bool> (m_protocol_version.relay)
            );
        }
        else if (m_header.command == "addr")
        {
            /**
             * Read the variable length integer.
             */
            m_protocol_addr.count = read_var_int();
            
            if (m_protocol_addr.count > 1000)
            {
                throw std::runtime_error("invalid addr count");
            }

            for (auto i = 0; i < m_protocol_addr.count; i++)
            {
                /**
                 * Read the network address, including the prefixed timestamp.
                 */
                protocol::network_address_t addr = read_network_address(
                    false, true
                );
                
                /**
                 * Retain the protocol::network_address_t.
                 */
                m_protocol_addr.addr_list.push_back(addr);
            }
        }
        else if (m_header.command == "getaddr")
        {
            // ...
        }
        else if (m_header.command == "reject")
        {
            /**
             * Read the reject.
             */
            m_protocol_reject.message_length = read_var_int();
            
            if (m_protocol_reject.message_length > sizeof(header_command))
            {
                throw std::runtime_error("invalid reject message length");
            }
            
            m_protocol_reject.message.resize(m_protocol_reject.message_length);
            
            read_bytes(
                const_cast<char *> (&m_protocol_reject.message[0]),
                m_protocol_reject.message_length
            );
            
            m_protocol_reject.ccode = read_uint8();
            m_protocol_reject.reason_length = read_var_int();
            
            if (m_protocol_reject.reason_length > 111)
            {
                throw std::runtime_error("invalid reject reason length");
            }
            
            m_protocol_reject.reason.resize(m_protocol_reject.reason_length);
            
            read_bytes(
                const_cast<char *> (m_protocol_reject.reason.data()),
                m_protocol_reject.reason_length
            );
            
            log_info(
                "Reject message = " << m_protocol_reject.message <<
                ", ccode = " << (int)m_protocol_reject.ccode << ", reason = " <<
                m_protocol_reject.reason << "."
            );
            
            /**
             * The bitcon protocol forces us to guess if there is a data
             * field and what size it might be. Therefore we only attempt to
             * decode 32-byte data fields.
             */
            if (remaining() >= sha256::digest_length)
            {
                m_protocol_reject.data.resize(sha256::digest_length);
                
                read_bytes(reinterpret_cast<char *> (
                    &m_protocol_reject.data[0]), sha256::digest_length
                );
                
                log_info(
                    "Reject hash = " <<
                    sha256::from_digest(&m_protocol_reject.data[0]).to_string()
                );
            }
        }
        else if (m_header.command == "ping")
        {
            /**
             * Read the nonce.
             */
            m_protocol_ping.nonce = read_uint64();
        }
        else if (m_header.command == "pong")
        {
            /**
             * Read the nonce.
             */
            m_protocol_pong.nonce = read_uint64();
        }
        else if (m_header.command == "inv")
        {
            /**
             * Read the variable length integer.
             */
            m_protocol_inv.count = read_var_int();
            
            for (auto i = 0; i < m_protocol_inv.count; i++)
            {
                inventory_vector inv = read_inventory_vector();

                if (inv.type() > inventory_vector::type_error)
                {
                    /**
                     * Retain the inventory_vector.
                     */
                    m_protocol_inv.inventory.push_back(inv);
                }
            }
        }
        else if (m_header.command == "getdata")
        {
            /**
             * Read the variable length integer.
             */
            m_protocol_getdata.count = read_var_int();
            
            for (auto i = 0; i < m_protocol_getdata.count; i++)
            {
                inventory_vector inv = read_inventory_vector();
                
                log_none("getdata inv.type = " << inv.type());
                
                if (inv.type() > inventory_vector::type_error)
                {
                    /**
                     * Retain the inventory_vector.
                     */
                    m_protocol_getdata.inventory.push_back(inv);
                }
            }
        }
        else if (m_header.command == "getblocks")
        {
            /**
             * Read the version.
             */
            m_protocol_getblocks.version = read_uint32();
            
            /**
             * Read the count.
             */
            m_protocol_getblocks.count = read_var_int();
            
            /**
             * Read the hashes.
             */
            for (auto i = 0; i < m_protocol_getblocks.count; i++)
            {
                m_protocol_getblocks.hashes.push_back(read_sha256());
            }
            
            /**
             * Read the hash stop.
             */
            m_protocol_getblocks.hash_stop = read_sha256();
        }
        else if (m_header.command == "block")
        {
            /**
             * Allocate the block.
             */
            m_protocol_block.blk = std::make_shared<block> ();
            
            /**
             * Decode the block.
             */
            if (m_protocol_block.blk->decode(*this))
            {
                // ...
            }
            else
            {
                log_error("Message failed to decode block.");
                
                /**
                 * Deallocate the block.
                 */
                m_protocol_block.blk.reset();
            }
        }
        else if (m_header.command == "getheaders")
        {
            /**
             * Allocate the block_locator.
             */
            m_protocol_getheaders.locator = std::make_shared<block_locator> ();
            
            /**
             * Decode the block_locator.
             */
            m_protocol_getheaders.locator->decode(*this);

            /**
             * Read the hash stop.
             */
            m_protocol_getheaders.hash_stop = read_sha256();
        }
        else if (m_header.command == "headers")
        {
            auto count = read_var_int();
            
            if (count > 0)
            {
                for (auto i = 0; i < count; i++)
                {
                    block block_header;
                    
                    if (block_header.decode(*this, true) == true)
                    {
                        m_protocol_headers.headers.push_back(block_header);
                    }
                }
            }
        }
        else if (m_header.command == "tx")
        {
            /**
             * Allocate the tx.
             */
            m_protocol_tx.tx = std::make_shared<transaction> ();
            
            /**
             * Decode the tx.
             */
            if (m_protocol_tx.tx->decode(*this))
            {
                // ...
            }
            else
            {
                log_error("Message failed to decode tx.");
                
                /**
                 * Deallocate the tx.
                 */
                m_protocol_tx.tx.reset();
            }
        }
        else if (m_header.command == "filterload")
        {
            /**
             * Allocate the filterload.
             */
            m_protocol_filterload.filterload =
                std::make_shared<transaction_bloom_filter> ()
            ;
            
            /**
             * Decode the filterload.
             */
            if (m_protocol_filterload.filterload->decode(*this))
            {
                // ...
            }
            else
            {
                log_error("Message failed to decode filterload.");
                
                /**
                 * Deallocate the filterload.
                 */
                m_protocol_filterload.filterload.reset();
            }
        }
        else if (m_header.command == "filteradd")
        {
            auto len = read_var_int();
            
            if (len > 0)
            {
                m_protocol_filteradd.filteradd.resize(len);
                
                read_bytes(
                    reinterpret_cast<char *> (
                    &m_protocol_filteradd.filteradd[0]),
                    m_protocol_filteradd.filteradd.size()
                );
            }
        }
        else if (m_header.command == "filterclear")
        {
            // ...
        }
        else if (m_header.command == "merkleblock")
        {
            /**
             * Allocate the merkleblock.
             */
            m_protocol_merkleblock.merkleblock =
                std::make_shared<block_merkle> ()
            ;
            
            /**
             * Decode the merkleblock.
             */
            if (m_protocol_merkleblock.merkleblock->decode(*this))
            {
                // ...
            }
            else
            {
                log_error("Message failed to decode merkleblock.");
                
                /**
                 * Deallocate the merkleblock.
                 */
                m_protocol_merkleblock.merkleblock.reset();
            }
        }
        else if (m_header.command == "sendheaders")
        {
            // ...
        }
        else if (m_header.command == "sendcmpct")
        {
            // ...
        }
        else if (m_header.command == "feefilter")
        {
            m_protocol_feefilter.feerate = read_int64();
            
            log_info(
                "Message got feefilter, feerate = " <<
                m_protocol_feefilter.feerate / constants::coin << "."
            );
        }
        else if (m_header.command == "buversion")
        {
            auto port = read_uint16();
            
            log_info("Message got buversion, port = " << port << ".");
        }
        else if (m_header.command == "alert")
        {
            /**
             * Deprecated
             */
        }
        else
        {
            log_error(
                "Message got invalid command = " << m_header.command << "."
            );
        }
    }
}

bool message::verify_header_magic()
{
    return m_header.magic == header_magic();
}

std::vector<std::uint8_t> message::header_magic_bytes()
{
#define BCASH_STRESS_TEST 1
#if (defined BCASH_STRESS_TEST && BCASH_STRESS_TEST)
    /**
     * BCash
     */
    std::vector<std::uint8_t> ret = { 0xe3, 0xe1, 0xf3, 0xe8 };
#else
	/**
	 * Bitcoin
  	 */
	std::vector<std::uint8_t> ret = { 0xf9, 0xbe, 0xb4, 0xd9 };
#endif // BCASH_STRESS_TEST
    
    if (constants::test_net == true)
    {
#if (defined BCASH_STRESS_TEST && BCASH_STRESS_TEST)
        /**
         * BCash
         */
        ret = { 0xf4, 0xe5, 0xf3, 0xf4 };
#else
    	/**
     	 * Bitcoin
         */
    	ret = { 0x0b, 0x11, 0x09, 0x07 };
#endif // BCASH_STRESS_TEST
    }

    return ret;
}

const std::uint32_t message::header_magic()
{
    static std::uint32_t ret = 0;
    
    if (ret == 0)
    {
        /**
         * Copy into a 32-bit unsigned integer.
         */
        std::memcpy(&ret, &header_magic_bytes()[0], sizeof(ret));
    }

    return ret;
}

message::header_t & message::header()
{
    return m_header;
}

protocol::version_t & message::protocol_version()
{
    return m_protocol_version;
}

protocol::addr_t & message::protocol_addr()
{
    return m_protocol_addr;
}

protocol::ping_t & message::protocol_ping()
{
    return m_protocol_ping;
}

protocol::pong_t & message::protocol_pong()
{
    return m_protocol_pong;
}

protocol::inv_t & message::protocol_inv()
{
    return m_protocol_inv;
}

protocol::getdata_t & message::protocol_getdata()
{
    return m_protocol_getdata;
}

protocol::getblocks_t & message::protocol_getblocks()
{
    return m_protocol_getblocks;
}

protocol::reject_t & message::protocol_reject()
{
    return m_protocol_reject;
}

protocol::block_t & message::protocol_block()
{
    return m_protocol_block;
}

protocol::getheaders_t & message::protocol_getheaders()
{
    return m_protocol_getheaders;
}

protocol::headers_t & message::protocol_headers()
{
    return m_protocol_headers;
}

protocol::tx_t & message::protocol_tx()
{
    return m_protocol_tx;
}

protocol::filterload_t & message::protocol_filterload()
{
    return m_protocol_filterload;
}

protocol::filteradd_t & message::protocol_filteradd()
{
    return m_protocol_filteradd;
}

protocol::merkleblock_t & message::protocol_merkleblock()
{
    return m_protocol_merkleblock;
}

data_buffer message::create_version()
{
    data_buffer ret;
    
    /**
     * Set the payload version.
     */
    m_protocol_version.version = protocol::version;
    
    /**
     * Set the services based on the operation mode.
     */
    if (
        globals::instance().operation_mode() ==
        protocol::operation_mode_peer
        )
    {
        /**
         * Set the payload services.
         */
        m_protocol_version.services =
            protocol::operation_mode_peer | protocol::operation_mode_bloom
        ;
    }
    else
    {
        /**
         * Set the payload services.
         */
        m_protocol_version.services = protocol::operation_mode_client;
    }

    /**
     * Set the payload timestamp (non-adjusted).
     */
    m_protocol_version.timestamp = std::time(0);
    
    /**
     * Set the services based on the operation mode.
     */
    if (
        globals::instance().operation_mode() ==
        protocol::operation_mode_peer
        )
    {
        /**
         * Set the payload addr_src services.
         */
        m_protocol_version.addr_src.services = protocol::operation_mode_peer;
    }
    else
    {
        /**
         * Set the payload addr_src services.
         */
        m_protocol_version.addr_src.services = protocol::operation_mode_client;
    }

    /**
     * Set the payload addr_src address.
     */
    m_protocol_version.addr_src.address =
    {
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff, 0x0a, 0x00, 0x00, 0x01}
    };

    /**
     * Set the payload addr_dst services.
     */
    m_protocol_version.addr_dst.services = protocol::operation_mode_peer;
    
    /**
     * Set the payload addr_dst port.
     */
    m_protocol_version.addr_dst.port = protocol::default_tcp_port;
    
    /**
     * Allocate the user agent comments.
     */
    std::vector<std::string> comments;

    if (
        globals::instance().operation_mode() ==
        protocol::operation_mode_client &&
        globals::instance().is_client_spv() == true
        )
    {
        comments.push_back("SPV Client");
    }
    else if (
        globals::instance().operation_mode() == protocol::operation_mode_peer
        )
    {
        comments.push_back("Peer");
    }
    else if (
        globals::instance().operation_mode() == protocol::operation_mode_client
        )
    {
        comments.push_back("Client");
    }
    else
    {
        comments.push_back("Unknown");
    }
    
#if (defined _MSC_VER)
    comments.push_back("Windows");
#elif (defined __ANDROID__)
    comments.push_back("Android");
#elif (defined __IPHONE_OS_VERSION_MAX_ALLOWED)
    comments.push_back("iOS");
#elif (defined __APPLE__)
    comments.push_back("macOS");
#elif (defined __linux__)
    comments.push_back("Linux");
#endif
    
    /**
     * Create the user agent string.
     */
    auto user_agent = utility::format_sub_version(
        constants::client_name, constants::version_client, comments
    );
    
    /**
     * Set the payload user_agent.
     */
    m_protocol_version.user_agent = user_agent;

    /**
     * Set the payload start height.
     */
    if (globals::instance().is_client_spv() == true)
    {
        m_protocol_version.start_height =
            globals::instance().spv_best_block_height() < 0 ? 0 :
            globals::instance().spv_best_block_height()
        ;
    }
    else
    {
        m_protocol_version.start_height =
            globals::instance().best_block_height() < 0 ? 0 :
            globals::instance().best_block_height()
        ;
    }
    
    /**
     * Set the nonce.
     */
    if (m_protocol_version.nonce == 0)
    {
        m_protocol_version.nonce = std::rand();
    }
    
    /**
     * Encode the payload version to little endian.
     */
    auto payload_version = endian::to_little<std::uint32_t>(
        m_protocol_version.version
    );
    
    assert(payload_version.size() == 4);
    
    /**
     * Write the payload version.
     */
    ret.write_bytes(reinterpret_cast<char *> (
        &payload_version[0]), payload_version.size()
    );
    
    /**
     * Encode the payload services to little endian.
     */
    auto payload_services = endian::to_little<std::uint64_t>(
        m_protocol_version.services
    );
    
    assert(payload_services.size() == 8);
    
    /**
     * Write the payload services.
     */
    ret.write_bytes(reinterpret_cast<char *> (
        &payload_services[0]), payload_services.size()
    );

    /**
     * Encode the payload timestamp to little endian.
     */
    auto payload_timestamp = endian::to_little<std::uint64_t>(
        m_protocol_version.timestamp
    );
    
    assert(payload_timestamp.size() == 8);
    
    /**
     * Write the payload timestamp.
     */
    ret.write_bytes(reinterpret_cast<char *> (
        &payload_timestamp[0]), payload_timestamp.size()
    );
    
    /**
     * Write the payload addr_src ommiting the timestamp.
     */
    ret.write_network_address(m_protocol_version.addr_src, false, false);
 
    /**
     * Write the payload addr_dst ommiting the timestamp.
     */
    ret.write_network_address(m_protocol_version.addr_dst, false, false);
    
    /**
     * Encode the payload nonce to little endian.
     */
    auto payload_nonce = endian::to_little<std::uint64_t>(
        m_protocol_version.nonce
    );
    
    assert(payload_nonce.size() == 8);
    
    /**
     * Write the payload nonce.
     */
    ret.write_bytes(reinterpret_cast<char *> (
        &payload_nonce[0]), payload_nonce.size()
    );

    /**
     * Write the payload user_agent's length.
     */
    ret.write_var_int(m_protocol_version.user_agent.size());
    
    /**
     * Write the payload user_agent.
     */
    ret.write_bytes(
        m_protocol_version.user_agent.data(),
        m_protocol_version.user_agent.size()
    );

    /**
     * Encode the payload start_height to little endian.
     */
    auto payload_start_height = endian::to_little<std::uint32_t>
        (m_protocol_version.start_height
    );
    
    /**
     * Write the payload start height.
     */
    ret.write_bytes(reinterpret_cast<char *> (
        &payload_start_height[0]), payload_start_height.size()
    );
    
    /**
     * BIP-0037
     */
        
    /**
     * Set the payload relay.
     */
    m_protocol_version.relay = true;

    /**
     * Write the payload relay.
     */
    ret.write_uint8(m_protocol_version.relay);
    
    return ret;
}

data_buffer message::create_addr()
{
    data_buffer ret;
    
    m_protocol_addr.count = m_protocol_addr.addr_list.size();
    
    ret.write_var_int(m_protocol_addr.count);
    
    auto addr_list = m_protocol_addr.addr_list;
    
    
    for (auto & i : addr_list)
    {
        ret.write_network_address(i, false);
    }
    
    return ret;
}

data_buffer message::create_ping()
{
    data_buffer ret;
    
    /**
     * Set the ping nonce.
     */
    m_protocol_ping.nonce = std::rand();
    
    /**
     * Encode the payload nonce to little endian.
     */
    auto payload_nonce = endian::to_little<std::uint64_t>(
        m_protocol_ping.nonce
    );
    
    assert(payload_nonce.size() == 8);
    
    /**
     * Write the payload nonce.
     */
    ret.write_bytes(reinterpret_cast<char *> (
        &payload_nonce[0]), payload_nonce.size()
    );
    
    return ret;
}

data_buffer message::create_pong()
{
    data_buffer ret;
    
    /**
     * Set the pong nonce.
     */
    m_protocol_pong.nonce = std::rand();
    
    /**
     * Encode the payload nonce to little endian.
     */
    auto payload_nonce = endian::to_little<std::uint64_t>(
        m_protocol_pong.nonce
    );
    
    assert(payload_nonce.size() == 8);
    
    /**
     * Write the payload nonce.
     */
    ret.write_bytes(reinterpret_cast<char *> (
        &payload_nonce[0]), payload_nonce.size()
    );
    
    return ret;
}

data_buffer message::create_inv()
{
    data_buffer ret;
    
    m_protocol_inv.count = m_protocol_inv.inventory.size();
    
    ret.write_var_int(m_protocol_inv.count);
    
    auto inventory = m_protocol_inv.inventory;
    
    for (auto & i : inventory)
    {
        i.encode(ret);
    }
    
    return ret;
}

data_buffer message::create_getdata()
{
    data_buffer ret;
    
    m_protocol_getdata.count = m_protocol_getdata.inventory.size();
    
    ret.write_var_int(m_protocol_getdata.count);
    
    auto inventory = m_protocol_getdata.inventory;
    
    for (auto & i : inventory)
    {
        i.encode(ret);
    }
    
    return ret;
}

data_buffer message::create_getblocks()
{
    data_buffer ret;
    
    m_protocol_getblocks.version = constants::version_client;
    
    ret.write_uint32(m_protocol_getblocks.version);
    
    m_protocol_getblocks.count = m_protocol_getblocks.hashes.size();
    
    ret.write_var_int(m_protocol_getblocks.count);
    
    auto hashes = m_protocol_getblocks.hashes;
    
    for (auto & i : hashes)
    {
        ret.write_sha256(i);
    }
    
    ret.write_sha256(m_protocol_getblocks.hash_stop);
    
    return ret;
}

data_buffer message::create_reject()
{
    data_buffer ret;
    
    m_protocol_reject.message_length = m_protocol_reject.message.size();
    
    ret.write_var_int(m_protocol_reject.message_length);
    ret.write_bytes(
        m_protocol_reject.message.data(), m_protocol_reject.message.size()
    );
    ret.write_uint8(m_protocol_reject.ccode);
    
    m_protocol_reject.reason_length = m_protocol_reject.reason.size();
    
    ret.write_var_int(m_protocol_reject.reason_length);
    ret.write_bytes(
        m_protocol_reject.reason.data(), m_protocol_reject.reason.size()
    );
    
    if (m_protocol_reject.data.size() > 0)
    {
        ret.write_bytes(
            reinterpret_cast<const char *>(&m_protocol_reject.data[0]),
            m_protocol_reject.data.size()
        );
    }
    
    return ret;
}

data_buffer message::create_getheaders()
{
    data_buffer ret;
    
    assert(m_protocol_getheaders.locator);
    
    /**
     * Encode the locator.
     */
    m_protocol_getheaders.locator->encode(ret);
    
    /**
     * Encode the hash stop.
     */
    ret.write_sha256(m_protocol_getheaders.hash_stop);
    
    return ret;
}

data_buffer message::create_headers()
{
    data_buffer ret;
    
    /**
     * Encode the number of block headers.
     */
    ret.write_var_int(m_protocol_headers.headers.size());
    
    for (auto & i : m_protocol_headers.headers)
    {
        /**
         * Encode only the block header.
         */
        i.encode(ret, true);
    }
    
    return ret;
}

data_buffer message::create_sendheaders()
{
    data_buffer ret;
    
    // ...
    
    return ret;
}

data_buffer message::create_block()
{
    data_buffer ret;
    
    if (m_protocol_block.blk)
    {
        m_protocol_block.blk->encode(ret);
    }
    
    return ret;
}

data_buffer message::create_filterload()
{
    data_buffer ret;
    
    if (m_protocol_filterload.filterload)
    {
        m_protocol_filterload.filterload->encode(ret);
    }
    
    return ret;
}

data_buffer message::create_filteradd()
{
    data_buffer ret;
    
    ret.write_var_int(m_protocol_filteradd.filteradd.size());
    
    if (m_protocol_filteradd.filteradd.size() > 0)
    {
        ret.write_bytes(
            reinterpret_cast<const char *> (&m_protocol_filteradd.filteradd[0]),
            m_protocol_filteradd.filteradd.size()
        );
    }

    return ret;
}

data_buffer message::create_filterclear()
{
    data_buffer ret;
    
    // ...
    
    return ret;
}

data_buffer message::create_merkleblock()
{
    data_buffer ret;
    
    if (m_protocol_merkleblock.merkleblock)
    {
        m_protocol_merkleblock.merkleblock->encode(ret);
    }
    
    return ret;
}

data_buffer message::create_tx()
{
    data_buffer ret;
    
    if (m_protocol_tx.tx)
    {
        m_protocol_tx.tx->encode(ret);
    }
    
    return ret;
}
