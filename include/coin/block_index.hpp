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

#ifndef COIN_BLOCK_INDEX_HPP
#define COIN_BLOCK_INDEX_HPP

#include <cstdint>

#include <coin/big_number.hpp>
#include <coin/point_out.hpp>
#include <coin/sha256.hpp>

namespace coin {

    class block;
    
    /**
     * Implements a block index.
     */
    class block_index
    {
        public:
        
            /**
             * Constructor
             */
            block_index();
        
            /**
             * Constructor
             * @param file The file.
             * @param block_position The block position.
             * @param blk The block.
             */
            block_index(
                const std::uint32_t & file,
                const std::uint32_t & block_position, block & blk
            );
        
            /**
             * The block flags.
             */
            typedef enum
            {
                block_flag_1 = 1 << 0,
            } block_flag_t;
        
            /**
             * Sets the block hash.
             * @param value The value.
             */
            void set_hash_block(const sha256 & val);
        
            /**
             * Gets the block hash.
             */
            sha256 get_block_hash() const;
        
            /**
             * Gets a copy of the block header.
             */
            block get_block_header() const;
        
            /**
             * Sets the previous block index.
             * @param val The value.
             */
            void set_block_index_previous(block_index * val);
        
            /**
             * Sets the next block index.
             * @param val The value.
             */
            void set_block_index_next(block_index * val);
        
            /**
             * The previous block index.
             */
            block_index * block_index_previous();
        
            /**
             * The previous block index.
             */
            const block_index * block_index_previous() const;
        
            /**
             * The next block index.
             */
            block_index * block_index_next();
        
            /**
             * The next block index.
             */
            const block_index * block_index_next() const;
        
            /**
             * The file.
             */
            const std::uint32_t & file() const;
        
            /**
             * The block position.
             */
            const std::uint32_t & block_position() const;
        
            /**
             * Sets the trust score of the chain (ppcoin).
             * @param val The value.
             */
            void set_chain_trust(const big_number & val);
        
            /**
             * The trust score of the chain (ppcoin).
             */
            const big_number & chain_trust() const;
        
            /**
             * Sets the height.
             * @param val The value.
             */
            void set_height(const std::int32_t & val);
        
            /**
             * The height.
             */
            const std::int32_t & height() const;
        
            /**
             * Sets the mint.
             * @param value The value.
             */
            void set_mint(const std::int64_t & value);
        
            /**
             * The mint.
             */
            const std::int64_t & mint() const;
        
            /**
             * Sets the money supply.
             * @param value The value.
             */
            void set_money_supply(const std::int64_t & value);
            
            /**
             * The money supply.
             */
            const std::int64_t & money_supply() const;
        
            /**
             * The block index flags.
             */
            const std::uint32_t & flags() const;
        
            /**
             * The version.
             */
            const std::int32_t & version() const;
        
            /**
             * The merkle root hash.
             */
            const sha256 & hash_merkle_root() const;
        
            /**
             * The time.
             */
            const std::int64_t & time() const;
        
            /**
             * The bits.
             */
            const std::uint32_t & bits() const;
        
            /**
             * The nonce.
             */
            const std::uint32_t & nonce() const;

            /**
             * Gets the block trust.
             */
            big_number get_block_trust();
        
            /**
             * The median timespan.
             */
            enum { median_time_span = 11 };

            /**
             * Gets the medium time past.
             */
            std::int64_t get_median_time_past();

            /**
             * Gets the medium time.
             */
            std::int64_t get_median_time();
    
            /**
             * If true it is proof of work.
             */
            bool is_proof_of_work() const;
    
            /**
             * If true it is in the main chain.
             */
            bool is_in_main_chain() const;

            /**
             * Gets the ancestor (parent) block at the given height.
             */
            const block_index * get_ancestor(
                const std::int32_t & height) const
            ;
            
        private:
        
            friend class block_index_disk;
            friend class db_tx;
        
            /**
             * The block hash.
             */
            sha256 m_hash_block;
        
            /**
             * The previous block index.
             */
            block_index * m_block_index_previous;
        
            /**
             * The next block index.
             */
            block_index * m_block_index_next;
        
            /**
             * The file.
             */
            std::uint32_t m_file;
        
            /**
             * The block position.
             */
            std::uint32_t m_block_position;
        
            /**
             * The trust score of the chain (ppcoin).
             */
            big_number m_chain_trust;
        
            /**
             * The height.
             */
            std::int32_t m_height;

            /**
             * The mint.
             */
            std::int64_t m_mint;
        
            /**
             * The money supply.
             */
            std::int64_t m_money_supply;

            /**
             * The block index flags.
             */
            std::uint32_t m_flags;

            // block header
        
            /**
             * The version.
             */
            std::int32_t m_version;
        
            /**
             * The merkle root hash.
             */
            sha256 m_hash_merkle_root;
        
            /**
             * The time.
             */
            std::int64_t m_time;
        
            /**
             * The bits.
             */
            std::uint32_t m_bits;
        
            /**
             * The nonce.
             */
            std::uint32_t m_nonce;

        protected:
        
            // ...
    };
    
} // namespace coin

#endif // COIN_BLOCK_INDEX_HPP
