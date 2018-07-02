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

#ifndef COIN_BIP_152_HPP
#define COIN_BIP_152_HPP

#include <cstdint>

#include <coin/data_buffer.hpp>
#include <coin/transaction.hpp>

namespace coin {
    
    /**
     * Implements BIP-152 classes.
     */
    namespace bip_152 {
    
        /**
         * Implements a BIP-152 PrefilledTransaction.
         */
        class prefilled_transaction : public data_buffer
        {
            public:
            
                /**
                 * Constructor
                 */
                explicit prefilled_transaction(
                    const std::uint64_t & index, const transaction & tx
                    )
                    : m_index(index)
                    , m_transaction(tx)
                {
                    // ...
                }
            
            private:
            
                /**
                 * The index.
                 */
                std::uint64_t m_index;
            
                /**
                 * The transaction.
                 */
                transaction m_transaction;
            
            protected:
            
                // ...
        };
    
    } // namespace bip_152
    
} // namespace coin

#endif // COIN_BIP_152_HPP
