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

#ifndef COIN_MESSAGE_HPP
#define COIN_MESSAGE_HPP

#include <cstdint>
#include <string>

#include <coin/data_buffer.hpp>
#include <coin/protocol.hpp>

namespace coin {

    /**
     * Implements a message.
     */
    class message : public data_buffer
    {
        public:
        
            /**
             * The header magic length.
             */
            enum { header_magic_length = 4 };
        
            /**
             * Constructor
             * @param buf The buffer.
             * @param len The length.
             */
            message(const char * buf, const std::size_t & len);
        
            /**
             * Constructor
             * @param command The command.
             */
            message(const std::string & command);
        
            /**
             * Constructor
             * @param command The command.
             * @param payload The payload.
             */
            message(
                const std::string & command, const data_buffer & payload
            );
        
            /**
             * Encodes the message.
             */
            void encode();
        
            /**
             * Decodes the message.
             */
            void decode();
        
            /**
             * Verifies the header magic.
             */
            bool verify_header_magic();

            /**
             * The header magic.
             */
            static std::vector<std::uint8_t> header_magic_bytes();
        
            /**
             * The header magic number.
             */
            static const std::uint32_t header_magic();
        
            /**
             * The header length.
             */
            enum { header_length = 24 };
        
            /**
             * The header.
             * @param magic A value indicating message origin network, and to
             * seek to next message when the tcp stream state is unknown.
             * @param command A null-terminated ASCII string identifying the
             * packet. This field MUST be 12 bytes in length.
             * @param length The lenth of the payload.
             * @param checksum The checksum of the payload calculated by
             * sha256(sha256(payload)).
             */
            typedef struct
            {
                std::uint32_t magic;
                std::string command;
                std::uint32_t length;
                std::uint32_t checksum;
            } header_t;

            /**
             * The header.
             */
            header_t & header();
        
            /**
             * The protocol version.
             */
            protocol::version_t & protocol_version();
        
            /**
             * The protocol addr structure.
             */
            protocol::addr_t & protocol_addr();
        
            /**
             * The protocol ping structure.
             */
            protocol::ping_t & protocol_ping();
        
            /**
             * The protocol pong structure.
             */
            protocol::pong_t & protocol_pong();
        
            /**
             * The protocol inv structure.
             */
            protocol::inv_t & protocol_inv();
        
            /**
             * The protocol getdata structure.
             */
            protocol::getdata_t & protocol_getdata();
        
            /**
             * The protocol getblocks structure.
             */
            protocol::getblocks_t & protocol_getblocks();
        
            /**
             * The protocol reject structure.
             */
            protocol::reject_t & protocol_reject();
        
            /**
             * The protocol block structure.
             */
            protocol::block_t & protocol_block();
        
            /**
             * The protocol getheaders structure.
             */
            protocol::getheaders_t & protocol_getheaders();
        
            /**
             * The protocol headers structure.
             */
            protocol::headers_t & protocol_headers();
        
            /**
             * The protocol tx structure.
             */
            protocol::tx_t & protocol_tx();
        
            /**
             * The protocol filterload.
             */
            protocol::filterload_t & protocol_filterload();
        
            /**
             * The protocol filteradd.
             */
            protocol::filteradd_t & protocol_filteradd();
        
            /**
             * The protocol merkleblock.
             */
            protocol::merkleblock_t & protocol_merkleblock();
        
        private:
        
            /**
             * The header.
             */
            header_t m_header;
        
            /**
             * The payload.
             */
            data_buffer m_payload;
    
            /**
             * The protocol version structure.
             */
            protocol::version_t m_protocol_version;
        
            /**
             * The protocol addr structure.
             */
            protocol::addr_t m_protocol_addr;
        
            /**
             * The protocol ping structure.
             */
            protocol::ping_t m_protocol_ping;
        
            /**
             * The protocol pong structure.
             */
            protocol::pong_t m_protocol_pong;
        
            /**
             * The protocol inv structure.
             */
            protocol::inv_t m_protocol_inv;
        
            /**
             * The protocol getdata structure.
             */
            protocol::getdata_t m_protocol_getdata;
        
            /**
             * The protocol getblocks structure.
             */
            protocol::getblocks_t m_protocol_getblocks;
        
            /**
             * The protocol reject structure.
             */
            protocol::reject_t m_protocol_reject;
        
            /**
             * The protocol block structure.
             */
            protocol::block_t m_protocol_block;
        
            /**
             * The protocol getheaders structure.
             */
            protocol::getheaders_t m_protocol_getheaders;
        
            /**
             * The protocol headers structure.
             */
            protocol::headers_t m_protocol_headers;
        
            /**
             * The protocol tx structure.
             */
            protocol::tx_t m_protocol_tx;
        
            /**
             * The protocol filterload.
             */
            protocol::filterload_t m_protocol_filterload;
        
            /**
             * The protocol filteradd.
             */
            protocol::filteradd_t m_protocol_filteradd;
        
            /**
             * The protocol merkleblock.
             */
            protocol::merkleblock_t m_protocol_merkleblock;
        
            /**
             * The protocol feefilter.
             */
            protocol::feefilter_t m_protocol_feefilter;
        
        protected:
        
            /**
             * Creates a version.
             */
            data_buffer create_version();
        
            /**
             * Creates an addr.
             */
            data_buffer create_addr();
        
            /**
             * Creates a ping.
             */
            data_buffer create_ping();
        
            /**
             * Creates a pong.
             */
            data_buffer create_pong();
        
            /**
             * Creates an inv.
             */
            data_buffer create_inv();
        
            /**
             * Creates a getdata.
             */
            data_buffer create_getdata();
        
            /**
             * Creates a getblocks.
             */
            data_buffer create_getblocks();
        
            /**
             * Creates a reject.
             */
            data_buffer create_reject();
        
            /**
             * Creates getheaders.
             */
            data_buffer create_getheaders();
        
            /**
             * Creates headers.
             */
            data_buffer create_headers();
        
            /**
             * Creates a sendheaders.
             */
         	data_buffer create_sendheaders();
        
            /**
             * Creates a block.
             */
            data_buffer create_block();
 
            /**
             * Creates a filterload.
             */
            data_buffer create_filterload();
        
            /**
             * Creates a filteradd.
             */
            data_buffer create_filteradd();
        
            /**
             * Creates a filterclear.
             */
            data_buffer create_filterclear();
  
            /**
             * Creates a merkleblock.
             */
            data_buffer create_merkleblock();
        
            /**
             * Creates a tx.
             */
            data_buffer create_tx();
    };
    
} // namespace coin

#endif // COIN_MESSAGE_HPP
