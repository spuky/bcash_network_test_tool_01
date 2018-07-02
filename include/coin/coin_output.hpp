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

#ifndef COIN_COIN_OUTPUT_HPP
#define COIN_COIN_OUTPUT_HPP

#include <cassert>
#include <cstdint>

#include <coin/data_buffer.hpp>
#include <coin/transaction_out.hpp>

namespace coin {

    /**
     * Implements an unspent transaction output (UTXO).
	 */
    class coin_output
    {
        public:
        
            /**
             * Encodes
             * @param buffer The data_buffer.
             */
            void encode(data_buffer & buffer) const
            {
            	// ...
            }
        
            /**
             * Decodes
             * @param buffer The data_buffer.
             */
            void decode(data_buffer & buffer)
            {
				// ...
            }
        
        private:
        
            /**
             * If true the owning transaction is coin base.
             */
            bool m_is_coin_base = false;
        
            /**
             * The transaction_out.
             */
            transaction_out m_transaction_output;
        
            /**
             * The block height at which the owning transaction was included.
             */
            std::uint32_t m_height = 0;
        
        protected:
        
        	// ...
    };

} // namespace coin

#endif // COIN_COIN_OUTPUT_HPP

