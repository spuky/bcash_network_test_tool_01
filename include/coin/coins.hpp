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

#ifndef COIN_COINS_HPP
#define COIN_COINS_HPP

#include <cassert>
#include <cstdint>
#include <vector>

#include <coin/data_buffer.hpp>
#include <coin/point_out.hpp>
#include <coin/transaction.hpp>
#include <coin/transaction_out.hpp>

namespace coin {

	/**
	 * Implements a set of unspent transaction outputs (UTXO's).
  	 */
	class coins
	{
    	public:
     
            /**
             * Implements a structure used to unspend outputs in case of a
             * block reorganization.
             */
            typedef struct reorganize_data_s
            {
                /**
                 * Encodes
                 * @param buffer The data_buffer.
                 */
                void encode(data_buffer & buffer) const
                {
                	buffer.write_uint8(is_coin_base);
                    
                	tx_out.encode(buffer);
                 	
					buffer.write_uint32(height);
                    
                    buffer.write_uint32(version);
                }
                
                /**
                 * Decodes
                 * @param buffer The data_buffer.
                 */
                void decode(data_buffer & buffer)
                {
                	is_coin_base = buffer.read_uint8();
                    
                	tx_out.decode(buffer);
                 
                 	height = buffer.read_uint32();
                  
                  	version = buffer.read_uint32();
                }
                
                /**
                 * If true the owning transaction is coin base.
                 */
                bool is_coin_base = false;
                
                /**
                 * The unspent transaction_out object.
                 */
                transaction_out tx_out;

                /**
                 * The block height at which the owning transaction was included.
                 */
                std::uint32_t height = 0;

                /**
                 * The version of the owning transaction.
                 */
                std::uint32_t version = 0;

            } reorganize_data_t;

			/**
             * Implements statistics for use with the coins_database.
             */
            typedef struct statistics_s
            {
                std::uint32_t height = 0;
                std::uint64_t transactions = 0;
                std::uint64_t transaction_outputs = 0;
                std::uint64_t encoded_size = 0;
            } statistics_t;

     		/**
       		 * Constructor
       		 */
			coins()
   				: m_is_coin_base(false)
       			, m_height(0)
          		, m_version(0)
   			{
      			// ...
            }
       
       		/**
             * Constructor
             * @param tx The transaction.
             * @param height The block height the given transaction was
             * included.
             */
       		coins(const transaction & tx, const std::uint32_t & height)
         		: m_is_coin_base(tx.is_coin_base())
           		, m_transaction_outs(tx.transactions_out())
             	, m_height(height)
             	, m_version(tx.version())
         	{
          		// ...
          	}
        
            /**
             * Encodes
             * @param buffer The data_buffer.
             */
            void encode(data_buffer & buffer) const
            {
             	std::uint32_t mask_size = 0;
                std::uint32_t mask_code = 0;
                
                calculate_mask_size(mask_size, mask_code);
                
        		auto first =
					m_transaction_outs.size() > 0 &&
                    m_transaction_outs[0].is_null() == false
                ;
        		auto second =
                	m_transaction_outs.size() > 1 &&
                    m_transaction_outs[1].is_null() == false
                ;
        
        		assert(mask_code || first || second);
          
          		std::uint32_t code =
					(mask_code - (first || second ? 0 : 1)) * 8 +
                    (m_is_coin_base ? 1 : 0) + (first ? 2 : 0) +
                    (second ? 4 : 0)
              	;
               
               	/**
           		 * Write the version.
              	 */
               	buffer.write_var_int(m_version);
                
				/**
				 * Write the code.
				 */
                buffer.write_var_int(code);
                
                /**
                 * The (spending) bitmask
                 */
				for (auto i = 0; i < mask_size; i++)
                {
                	std::uint8_t available = 0;
                 
            		for (
                    	auto j = 0; j < 8 && 2 + i * 8 + j <
                        m_transaction_outs.size(); j++
                        )
              		{
                		if (
                        	m_transaction_outs[2 + i * 8 + j].is_null() == false
                            )
                   		{
							available |= (1 << j);
                		}
                	}
                 
                 	/**
                     * Write the available.
                     */
                 	buffer.write_byte(available);
                }
                
				/**
                 * The transaction_out objects.
                 */
             	for (auto & i : m_transaction_outs)
              	{
               		if (i.is_null() == false)
                 	{
                  		i.encode(buffer);
                  	}
               	}
                
				/**
				 * Write the height.
				 */
				buffer.write_var_int(m_height);
            }
        
            /**
             * Decodes
             * @param buffer The data_buffer.
             */
            void decode(data_buffer & buffer)
            {
                /**
                 * Read the version.
                 */
                m_version = static_cast<std::uint32_t> (buffer.read_var_int());
                
                /**
                 * Read the code.
                 */
				auto code = static_cast<std::uint32_t> (buffer.read_var_int());
                
                /**
                 * If (code & 1) we are a from a coinbase transaction.
                 */
                m_is_coin_base = code & 1;
                
                /**
                 * Build the array of available transaction_out objects.
                 */
                std::vector<bool> available(2, false);
                
                available[0] = code & 2;
                available[1] = code & 4;
                
                std::uint32_t mask_code =
                	(code / 8) + ((code & 6) != 0 ? 0 : 1)
                ;
                
                while (mask_code > 0)
                {
                    auto avail = buffer.read_uint8();
                    
                    for (auto i = 0; i < 8; i++)
                    {
                        auto flag = (avail & (1 << i)) != 0;
                        
                        available.push_back(flag);
                    }
                    
                    if (avail != 0)
                    {
                        mask_code--;
                    }
                }
                
                /**
                 * Reserve memory for the transaction_out objects.
                 */
                m_transaction_outs.assign(available.size(), transaction_out());
                
                /**
                 * Read each available transaction_out object.
                 */
                for (auto i = 0; i < available.size(); i++)
                {
                    if (available[i] == true)
                    {
                    	m_transaction_outs[i].decode(buffer);
                    }
                }
                
				/**
				 * Read the height.
				 */
				m_height = static_cast<std::uint32_t> (buffer.read_var_int());
               
               	/**
                 * Cleanup the transaction_out objects.
                 */
				cleanup();
            }
        
            /**
             * If true the owning transaction is coin base.
             */
            const bool & is_coin_base() const
            {
            	return m_is_coin_base;
            }

            /**
             * The unspent transaction_out objects.
             */
			std::vector<transaction_out> & transaction_outs()
            {
                return m_transaction_outs;
            }
        
            /**
             * The unspent transaction_out objects.
             */
            const std::vector<transaction_out> & transaction_outs() const
            {
            	return m_transaction_outs;
            }

            /**
             * The block height at which the owning transaction was included.
             */
            const std::uint32_t & height() const
            {
            	return m_height;
            }

            /**
             * The version of the owning transaction.
             */
            const std::uint32_t & version() const
            {
            	return m_version;
            }
        
        	/**
         	 * Removes all of the spent transaction_out objects from the back
           	 * of the array.
             */
            void cleanup()
            {
            	while (
               		m_transaction_outs.size() > 0 &&
                	m_transaction_outs.back().is_null() == true
                    )
             	{
              		m_transaction_outs.pop_back();
              	}
            }
        
        	/**
         	 * Calculates the amount of bytes and the amount of non-zero bytes
             * for the bitmask.
             * @param bytes The bytes.
             * @param bytes_non_zero The non-zero bytes.
           	 */
            void calculate_mask_size(
             	std::uint32_t & bytes, std::uint32_t & bytes_non_zero
             	) const
            {
                std::uint32_t byte_last_used = 0;
                
                for (auto i = 0; 2 + i * 8 < m_transaction_outs.size(); i++)
                {
                    auto is_zero = true;
                
                    for (
                    	auto j = 0; j < 8 &&
                        2 + i * 8 + j < m_transaction_outs.size(); j++
                        )
                    {
                        if (
                        	m_transaction_outs[2 + i * 8 + j].is_null() == false
                            )
                        {
                            is_zero = false;
                            
                            continue;
                        }
                    }
                
                    if (is_zero == false)
                    {
                        byte_last_used = i + 1;
                        
                        bytes_non_zero++;
                    }
                }
                
                bytes += byte_last_used;
            }
        
            /**
             * Marks the given point_out as spent.
             * @param out The point_out.
             * @param reorg_data_out The reorganize_data_t (out).
             */
            bool spend(
            	const point_out & out, reorganize_data_t & reorg_data_out
                )
            {
                if (out.n() >= m_transaction_outs.size())
                {
                    return false;
                }
                
                if (m_transaction_outs[out.n()].is_null() == true)
                {
                    return false;
                }
                
                reorg_data_out.tx_out = m_transaction_outs[out.n()];
            
                m_transaction_outs[out.n()].set_null();
                
                /**
                 * Cleanup any spent transaction_out objects.
                 */
                cleanup();
                
                if (m_transaction_outs.size() == 0)
                {
                	reorg_data_out.is_coin_base = m_is_coin_base;
                    reorg_data_out.height = m_height;
                    reorg_data_out.version = m_version;
                }

                return true;
            }

            /**
			 * Marks a point_out spent at the given position.
    		 * @param position The position of the desired point_out object.
			 */
            bool spend(const std::uint32_t & position)
            {
            	reorganize_data_t reorg_data_unused;
                
                point_out out(0, position);
                
                return spend(out, reorg_data_unused);
            }

            /**
			 * If true the transaction_out is available at the given position.
    		 * @param position The position.
			 */
            bool is_available(const std::uint32_t & position) const
            {
                return
                    position < m_transaction_outs.size() &&
                    m_transaction_outs[position].is_null() == false
                ;
            }
        
            /**
             * If true we have spent all availble transaction_out objects.
             */
            bool is_pruned() const
            {
                for (auto & i : m_transaction_outs)
                {
                    if (i.is_null() == false)
                    {
                        return false;
                    }
                }
                
                return true;
            }
        
        	/**
             * Swaps this with coins_out.
             * @param coins_out The coins.
             */
            void swap(coins & coins_out)
            {
            	std::swap(coins_out.m_is_coin_base, m_is_coin_base);
                
            	coins_out.m_transaction_outs.swap(m_transaction_outs);
                
            	std::swap(coins_out.m_height, m_height);
                
            	std::swap(coins_out.m_version, m_version);
            }
        
            /**
             * operator ==
             */
            friend bool operator == (const coins & lhs, const coins & rhs)
            {
            	if (lhs.is_pruned() == true && rhs.is_pruned() == true)
             	{
              		return true;
              	}
                
				return
    	            lhs.m_is_coin_base == rhs.m_is_coin_base &&
                    lhs.m_height == rhs.m_height &&
                    lhs.m_version == rhs.m_version &&
                    lhs.m_transaction_outs == rhs.m_transaction_outs
                ;
            }
        
            /**
             * operator !=
             */
            friend bool operator != (const coins & lhs, const coins & rhs)
            {
                return !(lhs == rhs);
            }

     	private:
        
            /**
             * If true the owning transaction is coin base.
             */
            bool m_is_coin_base;
        
      		/**
     		 * The unspent transaction_out objects.
             */
			std::vector<transaction_out> m_transaction_outs;
        
            /**
             * The block height at which the owning transaction was included.
             */
        	std::uint32_t m_height;
        
        	/**
             * The version of the owning transaction.
             */
         	std::uint32_t m_version;
        
      	protected:
       
			// ...
	};
	
} // namespace coin

#endif // COIN_COINS_HPP
